package gate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wapo-org/wapo-review/internal/analyzer"
	"github.com/wapo-org/wapo-review/internal/githubapp"
)

func TestEvaluateDecisionsAndComplexityGate(t *testing.T) {
	pass := Evaluate(Input{
		Findings:             []analyzer.Finding{{RuleID: "STYLE.a", Severity: "medium", NewCode: true}},
		Complexities:         []analyzer.FunctionComplexity{{Name: "ok", Score: 8, Delta: 3}},
		MaxCritical:          0,
		MaxHigh:              0,
		MaxNewCognitive:      15,
		Sandbox:              map[string]bool{"unit": true},
		RequiredSandboxGates: []string{"unit"},
	})
	if pass.Decision != "passed" {
		t.Fatalf("expected passed, got %+v", pass)
	}

	neutral := Evaluate(Input{
		MaxCritical:          0,
		MaxHigh:              0,
		Sandbox:              map[string]bool{},
		RequiredSandboxGates: []string{"unit"},
	})
	if neutral.Decision != "neutral" {
		t.Fatalf("expected neutral when required sandbox gate missing, got %+v", neutral)
	}

	fail := Evaluate(Input{
		Findings:        []analyzer.Finding{{RuleID: "SECURITY.secret", Severity: "critical", File: "./src/a.ts", StartLine: 0, EndLine: 0, Message: "secret", NewCode: true}},
		Complexities:    []analyzer.FunctionComplexity{{Name: "heavy", Score: 22, Delta: 10}},
		MaxCritical:     0,
		MaxHigh:         0,
		MaxNewCognitive: 15,
		Sandbox:         map[string]bool{},
		RequiredSandboxGates: []string{"unit"},
	})
	// Missing sandbox gate must not downgrade a failure to neutral.
	if fail.Decision != "failed" {
		t.Fatalf("expected failed decision preserved, got %+v", fail)
	}
}

func TestPublishGateCheckRunSanitizesAnnotations(t *testing.T) {
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":777}`))
	}))
	defer srv.Close()

	res := Evaluate(Input{
		Findings: []analyzer.Finding{
			{RuleID: "SECURITY.secret", Severity: "critical", File: "./src/app.ts", StartLine: 0, EndLine: -5, Message: "leak", NewCode: true},
		},
		MaxCritical: 0,
	})
	id, err := PublishGateCheckRun(context.Background(), &githubapp.Client{BaseURL: srv.URL, Token: "tok"}, "org/repo", "headsha", res)
	if err != nil || id != 777 {
		t.Fatalf("PublishGateCheckRun failed: id=%d err=%v", id, err)
	}
	if payload["status"] != "completed" || payload["conclusion"] != "failure" {
		t.Fatalf("expected atomic completed/failure check run, got %+v", payload)
	}
	out, _ := payload["output"].(map[string]any)
	anns, _ := out["annotations"].([]any)
	if len(anns) != 1 {
		t.Fatalf("expected 1 sanitized annotation, got %+v", anns)
	}
	a0, _ := anns[0].(map[string]any)
	if a0["path"] != "src/app.ts" || a0["start_line"].(float64) < 1 || a0["end_line"].(float64) < 1 {
		t.Fatalf("annotation not properly sanitized: %+v", a0)
	}
	if !strings.Contains(out["summary"].(string), "| Condition | Status | Detail |") {
		t.Fatalf("expected markdown table in summary, got %v", out["summary"])
	}
}
