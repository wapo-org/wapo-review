package consolidator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"github.com/wapo-org/wapo-review/internal/analyzer"
	"github.com/wapo-org/wapo-review/internal/verifier"
	"github.com/wapo-org/wapo-review/internal/workspace"
)

type consolidatorScriptModel struct {
	responses []*schema.Message
	infos     []*schema.ToolInfo
}

func (m *consolidatorScriptModel) WithTools(infos []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	m.infos = infos
	return m, nil
}

func (m *consolidatorScriptModel) Generate(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
	if len(m.responses) == 0 {
		return nil, errors.New("no response")
	}
	r := m.responses[0]
	m.responses = m.responses[1:]
	return r, nil
}

func (m *consolidatorScriptModel) Stream(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return nil, errors.New("unused")
}

func TestDeduplicateExactAndOverlapping(t *testing.T) {
	got := Consolidate([]workspace.VerifiedFinding{{ID: "a", File: "x.go", StartLine: 10, Severity: "medium", Category: "logic", Title: "bad", Body: "brief", Fingerprint: "same"}, {ID: "b", File: "x.go", StartLine: 12, Severity: "high", Category: "logic", Title: "bad", Body: "richer details", Fingerprint: "same"}}, nil, nil)
	if len(got.Findings) != 1 || got.Findings[0].Severity != "high" || len(got.Findings[0].Sources) != 2 {
		t.Fatalf("unexpected merge: %#v", got.Findings)
	}
	got = Consolidate([]workspace.VerifiedFinding{{ID: "a", File: "x.go", StartLine: 10, Severity: "low", Category: "logic", Title: "same"}, {ID: "b", File: "x.go", StartLine: 13, Severity: "high", Category: "logic", Title: "same"}}, nil, nil)
	if len(got.Findings) != 1 {
		t.Fatalf("overlapping findings not merged: %#v", got.Findings)
	}
}
func TestFormatReviewCapsAndMarksOverflow(t *testing.T) {
	fs := make([]ConsolidatedFinding, 27)
	for i := range fs {
		fs[i] = ConsolidatedFinding{ID: string(rune('a' + i)), File: "x.go", StartLine: i*5 + 1, Severity: "low", Category: "logic", Title: "Finding", Body: "Body", OnDiffLine: true, NewCode: true}
	}
	fs = append(fs, ConsolidatedFinding{ID: "off", File: "z.go", Severity: "info", Title: "Off diff", OnDiffLine: false})
	r := FormatPRReview(ConsolidatedResult{Findings: fs}, 25)
	if len(r.Comments) != 25 || r.Event != "COMMENT" {
		t.Fatalf("comments=%d event=%s", len(r.Comments), r.Event)
	}
	if !contains(r.Body, "<details><summary>Additional findings (3)</summary>") || !contains(r.Body, "<!-- wapo-review-finding:") {
		t.Fatalf("missing overflow/marker: %s", r.Body)
	}
	if FormatPRReview(ConsolidatedResult{}, 25).Event != "APPROVE" {
		t.Fatal("clean review should approve")
	}
	if FormatPRReview(ConsolidatedResult{Findings: []ConsolidatedFinding{{Severity: "critical", NewCode: true}}}, 25).Event != "REQUEST_CHANGES" {
		t.Fatal("critical finding should request changes")
	}
}
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestAnalyzerFindingsNoDuplicateLinesAndCloneOffInline(t *testing.T) {
	staticFindings := []analyzer.Finding{
		{
			RuleID:    "CLONE.duplicate-block",
			Category:  "duplication",
			Severity:  "low",
			File:      "src/b.ts",
			StartLine: 14,
			EndLine:   24,
			Message:   "Duplicate code block matches src/a.ts:14",
			NewCode:   true,
		},
		{
			RuleID:    "SECURITY.secret",
			Category:  "security",
			Severity:  "critical",
			File:      "src/auth.ts",
			StartLine: 9,
			EndLine:   9,
			Message:   "Hardcoded AWS key detected",
			NewCode:   true,
		},
	}
	res := Consolidate(nil, staticFindings, nil)
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(res.Findings))
	}
	review := FormatPRReview(res, 25)
	if len(review.Comments) != 1 || review.Comments[0]["path"] != "src/auth.ts" {
		t.Fatalf("expected only SECURITY.secret inline (CLONE kept off inline), got %#v", review.Comments)
	}
	commentBody, _ := review.Comments[0]["body"].(string)
	if strings.Count(commentBody, "Hardcoded AWS key detected") != 1 {
		t.Fatalf("expected message once in inline comment, got: %q", commentBody)
	}
	if strings.Count(review.Body, "Duplicate code block matches src/a.ts:14") != 1 {
		t.Fatalf("expected clone message once in overflow summary, got: %q", review.Body)
	}
}

func TestConsolidateDropsRetractedFindings(t *testing.T) {
	got := Consolidate([]workspace.VerifiedFinding{
		{ID: "1", File: "a.ts", StartLine: 10, Severity: "medium", Title: "ignore", Body: "actually fine. no bug."},
		{ID: "2", File: "a.ts", StartLine: 20, Severity: "medium", Title: "Real race condition", Body: "Actually on second thought, false positive."},
		{ID: "3", File: "a.ts", StartLine: 30, Severity: "high", Title: "Real bug", Body: "Concurrent writes overwrite state."},
	}, nil, nil)
	if len(got.Findings) != 1 || got.Findings[0].ID != "3" {
		t.Fatalf("expected only real bug kept, got %#v", got.Findings)
	}
}

func TestAgentOptionsVerifierAndToolSchema(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "auth.go"), []byte("package auth\nfunc Check() bool {\n return true // unsafe\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ws, err := workspace.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"file":"auth.go","start_line":3,"end_line":3,"severity":"high","category":"auth","title":"Unsafe authorization result","body":"The check grants access unconditionally.","evidence_quote":"return true // unsafe","confidence":"high"}`
	bad := `{"file":"auth.go","start_line":3,"end_line":3,"severity":"high","category":"auth","title":"Unsupported check","body":"This is unsupported.","evidence_quote":"return false","confidence":"high"}`
	m := &consolidatorScriptModel{responses: []*schema.Message{
		{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
			{ID: "valid", Function: schema.FunctionCall{Name: "submit_finding", Arguments: valid}},
			{ID: "bad", Function: schema.FunctionCall{Name: "submit_finding", Arguments: bad}},
		}},
		{Role: schema.Assistant, Content: "done"},
	}}
	v := verifier.New(root, []string{"auth.go"}, map[string]string{"auth.go": "@@ -1,2 +1,3 @@\n+ return true // unsafe"})
	res, err := ConsolidateWithAgentWithOptions(context.Background(), m, ws, nil, []workspace.Lead{{TargetFile: "auth.go", InvariantType: "auth"}}, ConsolidateAgentOptions{ExtraTools: []tool.InvokableTool{workspace.NewReadLeadsTool(ws)}, Verifier: v})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Title != "Unsafe authorization result" {
		t.Fatalf("unexpected findings: %+v", res.Findings)
	}
	stored, err := ws.ReadAllFindings()
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	var found bool
	for _, info := range m.infos {
		if info.Name == "submit_finding" {
			found = info.ParamsOneOf != nil
		}
	}
	if !found {
		t.Fatal("submit_finding did not expose a JSON parameter schema")
	}
}
