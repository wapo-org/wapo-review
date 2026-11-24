package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"github.com/eino-contrib/jsonschema"
	"github.com/wapo-org/wapo-review/internal/agent"
	"github.com/wapo-org/wapo-review/internal/redact"
	"github.com/wapo-org/wapo-review/internal/workspace"
	"golang.org/x/sync/errgroup"
)

type SkepticDecision struct {
	FindingID string `json:"finding_id"`
	File      string `json:"file,omitempty"`
	Title     string `json:"title,omitempty"`
	Verdict   string `json:"verdict"`
	Reason    string `json:"reason"`
}

type SkepticReport struct {
	Kept      []workspace.VerifiedFinding
	Dropped   []SkepticDecision
	Batches   int
	Turns     int
	TokensIn  int
	TokensOut int
}

type verdictArgs struct {
	FindingID string `json:"finding_id"`
	Verdict   string `json:"verdict" jsonschema:"enum=keep,drop"`
	Reason    string `json:"reason"`
}

type verdictTool struct{ record func(verdictArgs) }

func (t verdictTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: "record_verdict", Desc: "Record a keep or drop verdict for one candidate finding", ParamsOneOf: schema.NewParamsOneOfByJSONSchema(jsonschema.Reflect(verdictArgs{}))}, nil
}

func (t verdictTool) InvokableRun(_ context.Context, raw string, _ ...tool.Option) (string, error) {
	var args verdictArgs
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		return "", err
	}
	if args.Verdict != "keep" && args.Verdict != "drop" {
		return "", fmt.Errorf("verdict must be keep or drop")
	}
	t.record(args)
	return `{"recorded":true}`, nil
}

func RunAdversarialGate(ctx context.Context, modelFactory func(context.Context) (model.ToolCallingChatModel, error), repoRoot string, extraTools []tool.InvokableTool, findings []workspace.VerifiedFinding, maxConcurrency int, redactor *redact.Redactor) SkepticReport {
	report := SkepticReport{Kept: append([]workspace.VerifiedFinding(nil), findings...)}
	if len(findings) == 0 || modelFactory == nil {
		return report
	}
	if maxConcurrency <= 0 {
		maxConcurrency = 6
	}
	batches := make([][]workspace.VerifiedFinding, 0, (len(findings)+7)/8)
	for start := 0; start < len(findings); start += 8 {
		end := min(len(findings), start+8)
		batches = append(batches, findings[start:end])
	}
	report.Batches = len(batches)
	type batchResult struct {
		decisions      map[string]verdictArgs
		turns, in, out int
	}
	results := make([]batchResult, len(batches))
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(maxConcurrency)
	for i, batch := range batches {
		i, batch := i, batch
		group.Go(func() error {
			m, err := modelFactory(groupCtx)
			if err != nil || m == nil {
				return nil
			}
			decisions := map[string]verdictArgs{}
			ids := make([]string, 0, len(batch))
			for _, f := range batch {
				ids = append(ids, f.ID)
			}
			tools := []tool.InvokableTool{verdictTool{record: func(a verdictArgs) { decisions[a.FindingID] = a }}}
			tools = append(tools, extraTools...)
			loop := &agent.ReviewLoop{Model: m, SystemPrompt: "You are an adversarial code-review verifier. For each candidate finding, check the surrounding code (and use read_file/grep on callers/guards if needed) and try to disprove the claimed failure scenario. Call record_verdict for EVERY finding_id in the batch. Verdict MUST be `keep` for every concrete, verifiable bug (including subtle concurrency races, migration/compatibility breaks, UTF-16/size-limit bugs, and logic bugs). Verdict MUST be `drop` ONLY when the finding is factually contradicted by the code or caller guards, garbled/uncertain/nonsensical, purely speculative without a real trigger, or an exact duplicate of another finding in the batch. Batch multiple record_verdict calls per turn.", Tools: tools, Guards: []agent.CompletionGuard{agent.RequireAllItemsCompleted(ids)}, MaxTurns: 8, MaxNudges: 1, Redactor: redactor, OnToolResult: func(rec agent.ToolRecord, ev *agent.ReviewEvidence) {
				if rec.Name == "record_verdict" && rec.Error == "" {
					var a verdictArgs
					if json.Unmarshal([]byte(rec.Arguments), &a) == nil {
						ev.CompletedItems[a.FindingID] = true
					}
				}
			}}
			res, err := loop.Run(groupCtx, skepticPrompt(repoRoot, batch))
			br := batchResult{decisions: decisions, turns: len(res.Turns), in: int(res.Usage.InputTokens), out: int(res.Usage.OutputTokens)}
			if err == nil {
				results[i] = br
			}
			return nil
		})
	}
	_ = group.Wait()
	decisions := map[string]verdictArgs{}
	for _, result := range results {
		report.Turns += result.turns
		report.TokensIn += result.in
		report.TokensOut += result.out
		for id, d := range result.decisions {
			decisions[id] = d
		}
	}
	report.Kept = make([]workspace.VerifiedFinding, 0, len(findings))
	for _, f := range findings {
		d, ok := decisions[f.ID]
		if ok && d.Verdict == "drop" && strings.TrimSpace(d.Reason) != "" {
			report.Dropped = append(report.Dropped, SkepticDecision{FindingID: f.ID, File: f.File, Title: f.Title, Verdict: d.Verdict, Reason: d.Reason})
			continue
		}
		report.Kept = append(report.Kept, f)
	}
	return report
}

func skepticPrompt(root string, findings []workspace.VerifiedFinding) string {
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "\nFinding %s\nFile: %s\nLines: %d..%d\nSeverity: %s\nCategory: %s\nTitle: %s\nBody: %s\nEvidenceQuote: %s\nSource context:\n", f.ID, f.File, f.StartLine, f.EndLine, f.Severity, f.Category, f.Title, f.Body, f.EvidenceQuote)
		path := filepath.Join(root, filepath.FromSlash(f.File))
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		lo, hi := max(1, f.StartLine-15), min(len(lines), f.EndLine+15)
		for n := lo; n <= hi; n++ {
			fmt.Fprintf(&b, "%d | %s\n", n, lines[n-1])
		}
	}
	return b.String()
}
