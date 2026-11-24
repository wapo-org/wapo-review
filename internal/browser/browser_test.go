package browser

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"github.com/wapo-org/wapo-review/internal/agent"
	"github.com/wapo-org/wapo-review/internal/memory"
	"github.com/wapo-org/wapo-review/internal/sandbox"
)

type stubVisionOrChatModel struct {
	responses []*schema.Message
	idx       int
}

func (m *stubVisionOrChatModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}
func (m *stubVisionOrChatModel) Generate(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	if m.idx >= len(m.responses) {
		return nil, errors.New("out of responses")
	}
	r := m.responses[m.idx]
	m.idx++
	return r, nil
}
func (m *stubVisionOrChatModel) Stream(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return nil, errors.New("not implemented")
}

type stubExecutor struct {
	seen []CheckPlan
}

func (s *stubExecutor) Run(_ context.Context, _ *sandbox.Container, plan CheckPlan) (CheckReport, error) {
	s.seen = append(s.seen, plan)
	return CheckReport{
		Passed:       true,
		URL:          plan.URL,
		Screenshots:  []string{"/tmp/shot1.png"},
		StorageState: json.RawMessage(`{"cookies":[{"name":"auth","value":"v1"}]}`),
	}, nil
}

func TestResolvePreviewURLAndSSRFRejection(t *testing.T) {
	for _, bad := range []string{
		"http://preview.example.com",
		"https://localhost:3000",
		"https://127.0.0.1/app",
		"https://169.254.169.254/latest/meta-data",
		"https://172.20.10.1/internal",
		"https://10.0.0.5/internal",
		"https://user:pass@preview.example.com",
	} {
		if got, err := ResolvePreviewURL([]string{bad}, nil, nil, ""); err == nil {
			t.Fatalf("expected unsafe URL %q rejected, got %q", bad, got)
		}
	}
	got, err := ResolvePreviewURL([]string{"http://bad.test"}, []string{"https://pr-42.example.vercel.app"}, nil, "")
	if err != nil || got != "https://pr-42.example.vercel.app" {
		t.Fatalf("unexpected resolved URL: %q err=%v", got, err)
	}
}

func TestSuppressFalseBlockers(t *testing.T) {
	blockers := []Blocker{
		{Kind: "browser_runtime", Summary: "playwright unavailable"},
		{Kind: "development_preview", Summary: "preview offline"},
		{Kind: "test_account", Summary: "no account"},
		{Kind: "product_bug", Summary: "checkout button throws 500"},
	}

	// Without telemetry, all blockers are kept.
	kept0, supp0 := SuppressFalseBlockers(blockers, RunTelemetry{})
	if len(kept0) != 4 || len(supp0) != 0 {
		t.Fatalf("without telemetry expected 4 kept / 0 suppressed, got %d / %d", len(kept0), len(supp0))
	}

	// With validated browser check telemetry, false blockers are suppressed while product_bug stays.
	kept, supp := SuppressFalseBlockers(blockers, RunTelemetry{BrowserCheckExecutions: 1})
	if len(kept) != 1 || kept[0].Kind != "product_bug" || len(supp) != 3 {
		t.Fatalf("with telemetry expected 1 kept (product_bug) and 3 suppressed, got kept=%+v supp=%+v", kept, supp)
	}
}

func TestHandsOnRunnerEnforcesBrowserCheckAndPairedRollback(t *testing.T) {
	ws := t.TempDir()
	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = ws
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@e.com", "GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@e.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
	}
	runGit("init", "-q")
	if err := os.WriteFile(filepath.Join(ws, "state.txt"), []byte("clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "state.txt")
	runGit("commit", "-q", "-m", "init")

	var c sandbox.Container = &sandbox.LocalContainer{Root: ws}
	cm := sandbox.NewCheckpointManager(c)
	execStub := &stubExecutor{}

	// We capture the checkpoint ID dynamically via a thin wrapper tool test OR pre-save & also test tool save/rollback.
	cpPre, err := cm.Save(context.Background(), "pre-test", sandbox.BrowserState{
		URL:          "https://preview.example.com/step1",
		StorageState: json.RawMessage(`{"cookies":[{"name":"sid","value":"saved"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Mutate workspace before rollback.
	if err := os.WriteFile(filepath.Join(ws, "state.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sm := &stubVisionOrChatModel{
		responses: []*schema.Message{
			// Turn 1: tries to finish without running browser check -> MUST be nudged by RequireToolCalled("run_browser_check")
			{Role: schema.Assistant, Content: "looks fine without running browser"},
			// Turn 2: runs browser check
			{Role: schema.Assistant, ToolCalls: []schema.ToolCall{{
				ID:       "call-1",
				Function: schema.FunctionCall{Name: "run_browser_check", Arguments: `{"scenario_id":"s1","url":"https://preview.example.com","steps":[{"action":"screenshot","label":"home"}]}`},
			}}},
			// Turn 3: rolls back to pre-test checkpoint (restores dirty file + browser storageState)
			{Role: schema.Assistant, ToolCalls: []schema.ToolCall{{
				ID:       "call-2",
				Function: schema.FunctionCall{Name: "rollback_checkpoint", Arguments: `{"id":"` + cpPre.ID + `"}`},
			}}},
			// Turn 4: runs second check verifying restored storageState was automatically carried forward!
			{Role: schema.Assistant, ToolCalls: []schema.ToolCall{{
				ID:       "call-3",
				Function: schema.FunctionCall{Name: "run_browser_check", Arguments: `{"scenario_id":"s2","url":"https://preview.example.com/step1","steps":[]}`},
			}}},
			// Turn 5: finishes cleanly
			{Role: schema.Assistant, Content: "hands_on completed"},
		},
	}

	runner := &HandsOnRunner{
		Loop:       &agent.ReviewLoop{Model: sm, MaxTurns: 8, MaxNudges: 2},
		Executor:   execStub,
		Container:  &c,
		Checkpoint: cm,
		Memory:     []memory.Note{{Text: "Use approved test model for streaming flows.", Scope: "hands_on"}},
	}
	res, err := runner.Run(context.Background(), "Verify preview UI")
	if err != nil {
		t.Fatalf("HandsOnRunner.Run failed: %v", err)
	}
	if res.Nudges != 1 || runner.Telemetry.BrowserCheckExecutions != 2 || runner.Telemetry.Rollbacks != 1 {
		t.Fatalf("unexpected telemetry: nudges=%d telemetry=%+v", res.Nudges, runner.Telemetry)
	}
	// Verify workspace rolled back cleanly.
	b, err := os.ReadFile(filepath.Join(ws, "state.txt"))
	if err != nil || string(b) != "clean\n" {
		t.Fatalf("expected workspace rolled back to clean, got %q err=%v", string(b), err)
	}
	// Verify restored browser storage state flowed into subsequent run_browser_check!
	if len(execStub.seen) != 2 || !strings.Contains(string(execStub.seen[1].StorageState), `"saved"`) {
		t.Fatalf("expected restored storageState forwarded to s2 check, got %+v", execStub.seen)
	}
}

func TestSandboxPlaywrightExecutorCustomRunner(t *testing.T) {
	var c sandbox.Container = &sandbox.LocalContainer{Root: t.TempDir()}
	ex := &SandboxPlaywrightExecutor{
		RunnerCommand: []string{"sh", "-c", `cat >/dev/null; printf '{"passed":true,"url":"https://preview.example.com","screenshots":["/tmp/a.png"]}'`},
	}
	rep, err := ex.Run(context.Background(), &c, CheckPlan{ScenarioID: "smoke", URL: "https://preview.example.com"})
	if err != nil || !rep.Passed || len(rep.Screenshots) != 1 {
		t.Fatalf("SandboxPlaywrightExecutor failed: rep=%+v err=%v", rep, err)
	}
}
