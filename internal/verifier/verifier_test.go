package verifier

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"github.com/wapo-org/wapo-review/internal/agent"
	"github.com/wapo-org/wapo-review/internal/workspace"
)

type scriptedLoopModel struct {
	responses []*schema.Message
	idx       int
	seen      [][]*schema.Message
}

func (m *scriptedLoopModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}
func (m *scriptedLoopModel) Generate(_ context.Context, msgs []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	m.seen = append(m.seen, append([]*schema.Message(nil), msgs...))
	if m.idx >= len(m.responses) {
		return nil, errors.New("out of responses")
	}
	r := m.responses[m.idx]
	m.idx++
	return r, nil
}
func (m *scriptedLoopModel) Stream(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return nil, errors.New("not implemented")
}

func TestLiveSubmitFindingSelfCorrectionLoopAndOnDiffLine(t *testing.T) {
	root := t.TempDir()
	src := strings.Join([]string{
		"package auth",
		"",
		"func Check(tok string) bool {",
		"    // line 4",
		"    // line 5",
		"    // line 6",
		"    // line 7",
		"    // line 8",
		"    // line 9",
		"    if tok == \"\" {",
		"        return true // BUG: empty token accepted",
		"    }",
		"    return false",
		"}",
	}, "\n")
	if err := os.WriteFile(filepath.Join(root, "auth.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	barePatch := "@@ -9,4 +10,3 @@\n+    if tok == \"\" {\n+        return true // BUG: empty token accepted\n+    }"

	ws, err := workspace.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v := New(root, []string{"auth.go"}, map[string]string{"auth.go": barePatch})

	// Scripted ReviewLoop:
	// Turn 1: submits WRONG line (line 2) -> gets hint pointing to line 11 + NearbyLines!
	// Turn 2: self-corrects to line 11 -> ACCEPTED with OnDiffLine=true!
	// Turn 3: submits duplicate -> rejected!
	// Turn 4: marks auth.go reviewed and posts lead -> finishes cleanly!
	sm := &scriptedLoopModel{
		responses: []*schema.Message{
			{Role: schema.Assistant, ToolCalls: []schema.ToolCall{{
				ID:       "t1",
				Function: schema.FunctionCall{Name: "submit_finding", Arguments: `{"file":"auth.go","start_line":2,"end_line":2,"severity":"critical","category":"security","title":"Empty token accepted","body":"The empty token branch returns true and bypasses authentication.","evidence_quote":"return true // BUG: empty token accepted","confidence":"high"}`},
			}}},
			{Role: schema.Assistant, ToolCalls: []schema.ToolCall{{
				ID:       "t2",
				Function: schema.FunctionCall{Name: "submit_finding", Arguments: `{"file":"auth.go","start_line":11,"end_line":11,"severity":"critical","category":"security","title":"Empty token accepted","body":"The empty token branch returns true and bypasses authentication.","evidence_quote":"return true // BUG: empty token accepted","confidence":"high"}`},
			}}},
			{Role: schema.Assistant, ToolCalls: []schema.ToolCall{{
				ID:       "t3",
				Function: schema.FunctionCall{Name: "submit_finding", Arguments: `{"file":"auth.go","start_line":11,"end_line":11,"severity":"critical","category":"security","title":"Empty token accepted","body":"This duplicate finding repeats the authentication bypass.","evidence_quote":"return true // BUG: empty token accepted","confidence":"high"}`},
			}}},
			{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
				{ID: "t4", Function: schema.FunctionCall{Name: "mark_file_reviewed", Arguments: `{"file":"auth.go"}`}},
				{ID: "t5", Function: schema.FunctionCall{Name: "post_lead", Arguments: `{"target_file":"handler.go","target_symbol":"Handle","question":"Does caller rely on Check?"}`}},
			}},
			{Role: schema.Assistant, Content: "shard-1 complete"},
		},
	}

	reviewed := map[string]bool{}
	loop := &agent.ReviewLoop{
		Model: sm,
		Tools: []tool.InvokableTool{
			NewSubmitFindingTool(v, ws, "shard-1"),
			NewMarkFileReviewedTool(func(f string) { reviewed[f] = true }),
			workspace.NewPostLeadTool(ws, "shard-1"),
		},
		Guards:   []agent.CompletionGuard{agent.RequireAllItemsCompleted([]string{"auth.go"})},
		MaxTurns: 8,
		OnToolResult: func(rec agent.ToolRecord, ev *agent.ReviewEvidence) {
			for f := range reviewed {
				ev.CompletedItems[f] = true
			}
		},
	}

	res, err := loop.Run(context.Background(), "Review auth.go")
	if err != nil {
		t.Fatalf("ReviewLoop failed: %v", err)
	}
	// Turn 1 tool response must have contained the line-11 self-correction hint.
	if !strings.Contains(res.Turns[0].ToolRecords[0].Result, "line 11") {
		t.Fatalf("expected turn 1 rejection to include line 11 hint, got: %s", res.Turns[0].ToolRecords[0].Result)
	}
	// Turn 2 accepted with OnDiffLine=true.
	if !strings.Contains(res.Turns[1].ToolRecords[0].Result, `"accepted":true`) || !strings.Contains(res.Turns[1].ToolRecords[0].Result, `"on_diff_line":true`) {
		t.Fatalf("expected turn 2 accepted with on_diff_line=true, got: %s", res.Turns[1].ToolRecords[0].Result)
	}
	// Turn 3 rejected as duplicate.
	if !strings.Contains(res.Turns[2].ToolRecords[0].Result, "duplicate") {
		t.Fatalf("expected turn 3 duplicate rejection, got: %s", res.Turns[2].ToolRecords[0].Result)
	}

	findings, err := ws.ReadAllFindings()
	if err != nil || len(findings) != 1 || !findings[0].OnDiffLine || findings[0].StartLine != 11 {
		t.Fatalf("expected 1 persisted finding at line 11 with OnDiffLine=true, got %+v err=%v", findings, err)
	}
	leads, err := ws.ReadAllLeads()
	if err != nil || len(leads) != 1 || leads[0].FromShard != "shard-1" || leads[0].TargetFile != "handler.go" {
		t.Fatalf("expected 1 persisted lead from shard-1, got %+v err=%v", leads, err)
	}
}

func TestMarkReviewedStructuredCallbacks(t *testing.T) {
	const args = `{"file":"auth.go","summary":"Checked token validation and remaining branches for distinct bugs","hunks_checked":3}`
	var legacy string
	legacyTool := NewMarkFileReviewedTool(func(file string) { legacy = file })
	info, err := legacyTool.Info(context.Background())
	if err != nil || info.ParamsOneOf == nil {
		t.Fatalf("legacy schema missing: %v", err)
	}
	if _, err := legacyTool.InvokableRun(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	if legacy != "auth.go" {
		t.Fatalf("legacy callback got %q", legacy)
	}
	var file, summary string
	var hunks int
	detailed := NewMarkFileReviewedDetailedTool(func(f, s string, h int) { file, summary, hunks = f, s, h })
	if _, err := detailed.InvokableRun(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	if file != "auth.go" || summary == "" || hunks != 3 {
		t.Fatalf("detailed callback got %q %q %d", file, summary, hunks)
	}
}

func TestVerifyAndRecordConcurrentExactDuplicate(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "auth.go"), []byte("package auth\nreturn false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ws, err := workspace.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v := New(root, []string{"auth.go"}, nil)
	d := FindingDraft{File: "auth.go", StartLine: 2, EndLine: 2, Title: "Reject token", Body: "Invalid token accepted", EvidenceQuote: "return false", Confidence: "high"}
	const workers = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted, duplicates := 0, 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _, err := v.VerifyAndRecord(d, ws, "shard")
			if err != nil {
				t.Errorf("VerifyAndRecord: %v", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if resp.Accepted {
				accepted++
			} else if strings.Contains(strings.Join(resp.Errors, " "), "duplicate") {
				duplicates++
			} else {
				t.Errorf("expected duplicate rejection, got %+v", resp)
			}
		}()
	}
	wg.Wait()
	findings, err := ws.ReadAllFindings()
	if err != nil || accepted != 1 || duplicates != workers-1 || len(findings) != 1 {
		t.Fatalf("accepted=%d duplicates=%d findings=%d err=%v", accepted, duplicates, len(findings), err)
	}
}

func TestVerifyAndRecordNearDuplicateRules(t *testing.T) {
	root := t.TempDir()
	source := "package auth\ncheckToken()\nwriteAudit()\nreturn false\n"
	if err := os.WriteFile(filepath.Join(root, "auth.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	ws, err := workspace.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v := New(root, []string{"auth.go"}, nil)
	base := FindingDraft{File: "auth.go", StartLine: 2, EndLine: 2, Title: "Token validation bypass", Body: "Token check is skipped", EvidenceQuote: "checkToken()", Confidence: "high"}
	if resp, _, err := v.VerifyAndRecord(base, ws, "one"); err != nil || !resp.Accepted {
		t.Fatalf("initial finding rejected: %+v err=%v", resp, err)
	}
	nearSameEvidence := base
	nearSameEvidence.StartLine = 3
	nearSameEvidence.EndLine = 3
	nearSameEvidence.Title = "Different wording"
	if resp, _ := v.Verify(nearSameEvidence, ws); resp.Accepted || !strings.Contains(strings.Join(resp.Errors, " "), "near these lines") {
		t.Fatalf("expected same evidence near-duplicate rejection, got %+v", resp)
	}
	nearSameTitle := base
	nearSameTitle.StartLine = 4
	nearSameTitle.EndLine = 4
	nearSameTitle.EvidenceQuote = "return false"
	if resp, _ := v.Verify(nearSameTitle, ws); resp.Accepted || !strings.Contains(strings.Join(resp.Errors, " "), "near these lines") {
		t.Fatalf("expected same title near-duplicate rejection, got %+v", resp)
	}
	distinct := FindingDraft{File: "auth.go", StartLine: 3, EndLine: 3, Title: "Audit event is missing", Body: "This branch skips audit logging", EvidenceQuote: "writeAudit()", Confidence: "high"}
	if resp, _, err := v.VerifyAndRecord(distinct, ws, "two"); err != nil || !resp.Accepted {
		t.Fatalf("distinct nearby finding rejected: %+v err=%v", resp, err)
	}
}

func TestFindingQualityRejectsMalformedAndUncertain(t *testing.T) {
	for _, tc := range []struct{ title, body string }{
		{"(cannot)", "This concrete description is long enough to pass."},
		{"bug", "This concrete description is long enough to pass."},
		{"Token guard bypass", "This might be correct?"},
		{"Token guard bypass", "Not sure if this condition is reachable in production."},
	} {
		if !isRetractedOrPlaceholderFinding(tc.title, tc.body) {
			t.Errorf("expected reject for title=%q body=%q", tc.title, tc.body)
		}
	}
	if isRetractedOrPlaceholderFinding("Empty token bypass", "An empty token is accepted because this branch returns true.") {
		t.Fatal("concrete finding unexpectedly rejected")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"P0":       "critical",
		"p1":       "high",
		"P2":       "medium",
		"p3":       "low",
		"error":    "high",
		"warning":  "medium",
		"CRITICAL": "critical",
		"":         "medium",
	}
	for in, want := range cases {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}
