package orchestrator

import "context"

type ReviewInput struct {
	Version        int    `json:"version"`
	RunID          string `json:"runId"`
	TenantID       string `json:"tenantId"`
	Repo           string `json:"repo"`
	PRNumber       int    `json:"prNumber"`
	Trigger        string `json:"trigger"`
	BeforeSHA      string `json:"beforeSha,omitempty"`
	InstallationID int64  `json:"installationId,omitempty"`
	UIChecks       bool   `json:"uiChecks"`
}
type StageResult struct {
	Version int            `json:"version"`
	Status  string         `json:"status"`
	Data    map[string]any `json:"data,omitempty"`
}
type ReviewStages interface {
	PreparePR(context.Context, ReviewInput) (StageResult, error)
	SandboxGates(context.Context, ReviewInput, StageResult) (StageResult, error)
	GraphAndStatic(context.Context, ReviewInput, StageResult) (StageResult, error)
	ReviewShards(context.Context, ReviewInput, StageResult) ([]StageResult, error)
	Consolidate(context.Context, ReviewInput, StageResult, StageResult, []StageResult) (StageResult, error)
	BrowserAndVisualQA(context.Context, ReviewInput, StageResult) (StageResult, error)
	PublishReview(context.Context, ReviewInput, StageResult, StageResult) (StageResult, error)
}
type ReviewOutput struct {
	Prepare, Gates, Graph, Consolidated, Browser, Published StageResult
	Shards                                                  []StageResult
}
type RunRef struct{ ID string }
type ReviewResult struct {
	Ref    RunRef
	Output ReviewOutput
}
type WorkflowRunner interface {
	Start(context.Context, ReviewInput) (RunRef, error)
	Wait(context.Context, RunRef) (ReviewResult, error)
	Replay(context.Context, RunRef, ...string) error
	Cancel(context.Context, RunRef) error
}
