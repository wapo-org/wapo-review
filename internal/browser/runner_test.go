package browser

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWaitActionRunnerAndStepJSON(t *testing.T) {
	if !strings.Contains(PlaywrightRunnerScript, `case "wait":`) ||
		!strings.Contains(PlaywrightRunnerScript, `waitFor({ state: "visible"`) ||
		!strings.Contains(PlaywrightRunnerScript, `page.waitForTimeout(waitMs)`) {
		t.Fatal("generated Playwright runner does not support wait action")
	}

	var plan CheckPlan
	if err := json.Unmarshal([]byte(`{"steps":[{"action":"wait","target":"#ready","ms":250,"timeout_ms":1200}]}`), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 1 || plan.Steps[0].Action != "wait" || plan.Steps[0].Target != "#ready" || plan.Steps[0].Ms != 250 || plan.Steps[0].TimeoutMs != 1200 {
		t.Fatalf("wait step did not round-trip from JSON: %+v", plan.Steps)
	}
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"ms":250`) || !strings.Contains(string(b), `"timeout_ms":1200`) {
		t.Fatalf("wait timing fields missing from JSON: %s", b)
	}
}

func TestStagehandExtractFallsBackToVisiblePageText(t *testing.T) {
	start := strings.Index(PlaywrightRunnerScript, `case "stagehand_extract":`)
	end := strings.Index(PlaywrightRunnerScript[start:], `default:`)
	if start < 0 || end < 0 {
		t.Fatal("stagehand_extract action not found in generated runner")
	}
	action := PlaywrightRunnerScript[start : start+end]
	if !strings.Contains(action, `timeout: 2000`) ||
		!strings.Contains(action, `document.body?.innerText`) ||
		strings.Contains(action, `page.innerText(step.target`) {
		t.Fatal("stagehand_extract must bound selector lookup and fall back to visible page text")
	}
}
