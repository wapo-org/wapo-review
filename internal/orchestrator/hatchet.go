package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hatchet-dev/hatchet/pkg/client/rest"
	"github.com/hatchet-dev/hatchet/sdks/go"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

type ShardsOutput struct {
	Shards []StageResult `json:"shards"`
}

type HatchetRunner struct {
	Client   *hatchet.Client
	Workflow *hatchet.Workflow
	stages   ReviewStages
}

var _ WorkflowRunner = (*HatchetRunner)(nil)

func RegisterHatchet(client *hatchet.Client, stages ReviewStages, tenantLimit int) (*HatchetRunner, error) {
	if client == nil || stages == nil {
		return nil, errors.New("Hatchet client and review stages are required")
	}
	if tenantLimit < 1 {
		tenantLimit = 4
	}
	prLimit := int32(1)
	tenantLimit32 := int32(tenantLimit)
	cancel := hatchet.CancelInProgress
	fair := hatchet.GroupRoundRobin

	w := client.NewWorkflow(
		"pr_review",
		hatchet.WithWorkflowConcurrency(
			hatchet.Concurrency{
				Expression:    `input.repo + ":" + string(input.prNumber)`,
				MaxRuns:       &prLimit,
				LimitStrategy: &cancel,
			},
			hatchet.Concurrency{
				Expression:    `input.tenantId`,
				MaxRuns:       &tenantLimit32,
				LimitStrategy: &fair,
			},
		),
	)

	prepare := w.NewTask("prepare_pr", func(ctx hatchet.Context, in ReviewInput) (StageResult, error) {
		return stages.PreparePR(ctx, in)
	}, hatchet.WithRetries(2), hatchet.WithExecutionTimeout(10*time.Minute))

	gates := w.NewTask("sandbox_gates", func(ctx hatchet.Context, in ReviewInput) (StageResult, error) {
		var prep StageResult
		if err := ctx.ParentOutput(prepare, &prep); err != nil {
			return StageResult{}, fmt.Errorf("read prepare output: %w", err)
		}
		return stages.SandboxGates(ctx, in, prep)
	}, hatchet.WithParents(prepare), hatchet.WithRetries(2), hatchet.WithExecutionTimeout(30*time.Minute))

	graphTask := w.NewTask("graph_and_static", func(ctx hatchet.Context, in ReviewInput) (StageResult, error) {
		var prep StageResult
		if err := ctx.ParentOutput(prepare, &prep); err != nil {
			return StageResult{}, fmt.Errorf("read prepare output: %w", err)
		}
		return stages.GraphAndStatic(ctx, in, prep)
	}, hatchet.WithParents(prepare), hatchet.WithRetries(2), hatchet.WithExecutionTimeout(30*time.Minute))

	shards := w.NewTask("review_shards", func(ctx hatchet.Context, in ReviewInput) (ShardsOutput, error) {
		var prep StageResult
		if err := ctx.ParentOutput(prepare, &prep); err != nil {
			return ShardsOutput{}, fmt.Errorf("read prepare output: %w", err)
		}
		res, err := stages.ReviewShards(ctx, in, prep)
		return ShardsOutput{Shards: res}, err
	}, hatchet.WithParents(prepare, graphTask), hatchet.WithRetries(2), hatchet.WithExecutionTimeout(30*time.Minute))

	consolidate := w.NewTask("consolidate", func(ctx hatchet.Context, in ReviewInput) (StageResult, error) {
		var gRes, grRes StageResult
		var sRes ShardsOutput
		if err := ctx.ParentOutput(gates, &gRes); err != nil {
			return StageResult{}, fmt.Errorf("read sandbox gates output: %w", err)
		}
		if err := ctx.ParentOutput(graphTask, &grRes); err != nil {
			return StageResult{}, fmt.Errorf("read graph output: %w", err)
		}
		if err := ctx.ParentOutput(shards, &sRes); err != nil {
			return StageResult{}, fmt.Errorf("read shard output: %w", err)
		}
		return stages.Consolidate(ctx, in, gRes, grRes, sRes.Shards)
	}, hatchet.WithParents(gates, graphTask, shards), hatchet.WithRetries(2), hatchet.WithExecutionTimeout(15*time.Minute))

	browser := w.NewTask("browser_qa", func(ctx hatchet.Context, in ReviewInput) (StageResult, error) {
		if !in.UIChecks {
			return StageResult{Status: "skipped"}, nil
		}
		var cRes StageResult
		if err := ctx.ParentOutput(consolidate, &cRes); err != nil {
			return StageResult{}, fmt.Errorf("read consolidate output: %w", err)
		}
		return stages.BrowserAndVisualQA(ctx, in, cRes)
	}, hatchet.WithParents(consolidate), hatchet.WithRetries(1), hatchet.WithExecutionTimeout(30*time.Minute))

	w.NewTask("publish_review", func(ctx hatchet.Context, in ReviewInput) (StageResult, error) {
		var cRes, bRes StageResult
		if err := ctx.ParentOutput(consolidate, &cRes); err != nil {
			return StageResult{}, fmt.Errorf("read consolidate output: %w", err)
		}
		if err := ctx.ParentOutput(browser, &bRes); err != nil {
			return StageResult{}, fmt.Errorf("read browser output: %w", err)
		}
		return stages.PublishReview(ctx, in, cRes, bRes)
	}, hatchet.WithParents(consolidate, browser), hatchet.WithRetries(3), hatchet.WithExecutionTimeout(10*time.Minute))

	return &HatchetRunner{Client: client, Workflow: w, stages: stages}, nil
}

// StartWorker registers the pr_review workflow on a live Hatchet worker and
// starts pulling tasks over outbound gRPC TLS. Call the returned cleanup func
// during graceful shutdown.
func (h *HatchetRunner) StartWorker(workerName string, slots int) (func() error, error) {
	if h == nil || h.Client == nil || h.Workflow == nil {
		return nil, errors.New("hatchet runner is not initialized")
	}
	if workerName == "" {
		workerName = "wapo-review-worker"
	}
	if slots < 1 {
		slots = 16
	}
	worker, err := h.Client.NewWorker(
		workerName,
		hatchet.WithWorkflows(h.Workflow),
		hatchet.WithSlots(slots),
	)
	if err != nil {
		return nil, fmt.Errorf("create hatchet worker: %w", err)
	}
	return worker.Start()
}

func (h *HatchetRunner) TriggerReview(ctx context.Context, in ReviewInput) (*hatchet.WorkflowRunRef, error) {
	if h == nil || h.Client == nil {
		return nil, errors.New("hatchet runner is not initialized")
	}
	return h.Client.RunNoWait(ctx, "pr_review", in)
}

func (h *HatchetRunner) Start(ctx context.Context, in ReviewInput) (RunRef, error) {
	ref, err := h.TriggerReview(ctx, in)
	if err != nil {
		return RunRef{}, err
	}
	return RunRef{ID: ref.RunId}, nil
}

func (h *HatchetRunner) Wait(ctx context.Context, ref RunRef) (ReviewResult, error) {
	if h == nil || h.Client == nil {
		return ReviewResult{}, errors.New("hatchet runner is not initialized")
	}
	if ref.ID == "" {
		return ReviewResult{}, errors.New("run ref ID is required")
	}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		details, err := h.Client.Runs().Get(ctx, ref.ID)
		if err != nil {
			return ReviewResult{}, err
		}
		switch details.Run.Status {
		case rest.V1TaskStatusCOMPLETED:
			return ReviewResult{Ref: ref}, nil
		case rest.V1TaskStatusFAILED, rest.V1TaskStatusCANCELLED:
			return ReviewResult{Ref: ref}, fmt.Errorf("hatchet run %s ended with status %s", ref.ID, details.Run.Status)
		}
		select {
		case <-ctx.Done():
			return ReviewResult{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (h *HatchetRunner) Replay(ctx context.Context, ref RunRef, _ ...string) error {
	if h == nil || h.Client == nil {
		return errors.New("hatchet runner is not initialized")
	}
	uid, err := uuid.Parse(ref.ID)
	if err != nil {
		return fmt.Errorf("invalid hatchet run UUID %q: %w", ref.ID, err)
	}
	ids := []openapi_types.UUID{uid}
	_, err = h.Client.Runs().Replay(ctx, rest.V1ReplayTaskRequest{ExternalIds: &ids})
	return err
}

func (h *HatchetRunner) Cancel(ctx context.Context, ref RunRef) error {
	if h == nil || h.Client == nil {
		return errors.New("hatchet runner is not initialized")
	}
	uid, err := uuid.Parse(ref.ID)
	if err != nil {
		return fmt.Errorf("invalid hatchet run UUID %q: %w", ref.ID, err)
	}
	ids := []openapi_types.UUID{uid}
	_, err = h.Client.Runs().Cancel(ctx, rest.V1CancelTaskRequest{ExternalIds: &ids})
	return err
}
