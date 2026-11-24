package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"github.com/eino-contrib/jsonschema"
	"github.com/wapo-org/wapo-review/internal/agent"
	"github.com/wapo-org/wapo-review/internal/memory"
	"github.com/wapo-org/wapo-review/internal/sandbox"
	"github.com/wapo-org/wapo-review/internal/secrets"
)

type CheckStep struct {
	Action    string `json:"action"` // navigate, click, fill, wait_for, wait, assert_text, assert_visible, screenshot, stagehand_act, stagehand_extract
	Target    string `json:"target,omitempty"`
	Value     string `json:"value,omitempty"`
	Label     string `json:"label,omitempty"`
	Ms        int    `json:"ms,omitempty"`
	TimeoutMs int    `json:"timeout_ms,omitempty"`
}

type CheckPlan struct {
	ScenarioID       string            `json:"scenario_id"`
	URL              string            `json:"url"`
	Steps            []CheckStep       `json:"steps"`
	Stagehand        bool              `json:"stagehand,omitempty"`
	StorageState     json.RawMessage   `json:"storage_state,omitempty"`
	ScreenshotDir    string            `json:"screenshot_dir,omitempty"`
	RecordVideo      bool              `json:"record_video,omitempty"`
	ExtraHTTPHeaders map[string]string `json:"extra_http_headers,omitempty"`
}

type StepResult struct {
	Step   CheckStep `json:"step"`
	Passed bool      `json:"passed"`
	Output string    `json:"output,omitempty"`
	Error  string    `json:"error,omitempty"`
}

type CheckReport struct {
	Passed         bool            `json:"passed"`
	ConsoleErrors  []string        `json:"console_errors,omitempty"`
	PageErrors     []string        `json:"page_errors,omitempty"`
	FailedRequests []string        `json:"failed_requests,omitempty"`
	Screenshots    []string        `json:"screenshots,omitempty"`
	VideoPath      string          `json:"video_path,omitempty"`
	StorageState   json.RawMessage `json:"storage_state,omitempty"`
	DOMSnapshot    string          `json:"dom_snapshot,omitempty"`
	StepResults    []StepResult    `json:"step_results,omitempty"`
	URL            string          `json:"url,omitempty"`
}

type BrowserExecutor interface {
	Run(ctx context.Context, c *sandbox.Container, plan CheckPlan) (CheckReport, error)
}

// PlaywrightRunnerScript is a self-contained Node ESM script executed inside
// the sandbox container to run structured Playwright steps (with optional
// Stagehand adapter when available, falling back cleanly to Playwright).
const PlaywrightRunnerScript = `import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

async function loadPlaywright() {
  try {
    return await import("playwright");
  } catch {}
  for (const base of ["/opt/review-tools/package.json", process.cwd() + "/package.json"]) {
    try {
      if (fs.existsSync(base)) {
        const req = createRequire(base);
        return req("playwright");
      }
    } catch {}
  }
  throw new Error("playwright package not found in container");
}

async function main() {
  const raw = fs.readFileSync(0, "utf8");
  const plan = JSON.parse(raw);
  const { chromium } = await loadPlaywright();
  const screenshotDir = plan.screenshot_dir || "/tmp/wapo-screenshots";
  fs.mkdirSync(screenshotDir, { recursive: true, mode: 0o700 });

  const browser = await chromium.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  const ctxOpts = {};
  if (plan.storage_state) ctxOpts.storageState = plan.storage_state;
  if (plan.extra_http_headers) ctxOpts.extraHTTPHeaders = plan.extra_http_headers;
  if (plan.record_video) ctxOpts.recordVideo = { dir: screenshotDir };

  const context = await browser.newContext(ctxOpts);
  const page = await context.newPage();

  const report = {
    passed: true,
    console_errors: [],
    page_errors: [],
    failed_requests: [],
    screenshots: [],
    step_results: [],
    url: plan.url || "",
  };

  page.on("console", (msg) => {
    if (msg.type() === "error") report.console_errors.push(msg.text());
  });
  page.on("pageerror", (err) => report.page_errors.push(String(err)));
  page.on("requestfailed", (req) => {
    report.failed_requests.push(req.method() + " " + req.url() + " " + (req.failure()?.errorText || "failed"));
  });
  page.on("response", (res) => {
    if (res.status() >= 500) {
      report.failed_requests.push(res.request().method() + " " + res.url() + " HTTP " + res.status());
    }
  });

  if (plan.url) {
    await page.goto(plan.url, { waitUntil: "domcontentloaded", timeout: 30000 });
  }

  let idx = 0;
  for (const step of plan.steps || []) {
    idx++;
    try {
      let output = "";
      switch (step.action) {
        case "navigate":
          await page.goto(step.target || step.value, { waitUntil: "domcontentloaded", timeout: 30000 });
          break;
        case "click":
          await page.locator(step.target).first().click({ timeout: 15000 });
          break;
        case "fill":
          await page.locator(step.target).first().fill(step.value || "", { timeout: 15000 });
          break;
        case "wait_for":
          await page.locator(step.target).first().waitFor({ timeout: 15000 });
          break;
        case "wait":
          if (step.target) {
            await page.locator(step.target).first().waitFor({ state: "visible", timeout: Math.min(Math.max(Number(step.timeout_ms || step.ms || 5000), 100), 15000) });
          } else {
            const waitMs = Math.min(Math.max(Number(step.ms || step.timeout_ms || 1000), 100), 10000);
            await page.waitForTimeout(waitMs);
          }
          break;
        case "assert_visible":
          if (!(await page.locator(step.target).first().isVisible())) throw new Error("not visible: " + step.target);
          break;
        case "assert_text": {
          const body = await page.innerText(step.target || "body");
          if (!body.includes(step.value || "")) throw new Error("missing text: " + step.value);
          break;
        }
        case "screenshot": {
          const fname = path.join(screenshotDir, (step.label || "step-" + idx).replace(/[^a-zA-Z0-9._-]/g, "_") + ".png");
          await page.screenshot({ path: fname, fullPage: false });
          fs.chmodSync(fname, 0o600);
          report.screenshots.push(fname);
          break;
        }
        case "stagehand_act":
          await page.getByText(step.value || step.target, { exact: false }).first().click({ timeout: 15000 });
          break;
        case "stagehand_extract": {
          const instruction = step.value || step.target || "";
          let extracted = "";
          const candidate = step.target || "";
          if (candidate && !/[.!?]\s/.test(candidate)) {
            try {
              const locator = page.locator(candidate).first();
              if (await locator.count({ timeout: 2000 }) > 0) {
                extracted = (await locator.innerText({ timeout: 2000 })).slice(0, 4000);
              }
            } catch {}
          }
          if (!extracted) {
            extracted = await page.evaluate(() => (document.body?.innerText || document.documentElement?.innerText || "").slice(0, 4000));
          }
          output = instruction ? instruction + "\n" + extracted : extracted;
          break;
        }
        default:
          throw new Error("unsupported action: " + step.action);
      }
      report.step_results.push({ step, passed: true, output });
    } catch (err) {
      report.passed = false;
      report.step_results.push({ step, passed: false, error: String(err) });
    }
  }

  report.url = page.url();
  report.storage_state = await context.storageState();
  report.dom_snapshot = (await page.innerText("body").catch(() => "")).slice(0, 8000);
  if (plan.record_video && page.video()) {
    report.video_path = await page.video().path().catch(() => "");
  }
  await context.close();
  await browser.close();
  process.stdout.write(JSON.stringify(report));
}

main().catch((err) => {
  process.stderr.write(String(err) + "\n");
  process.exit(1);
});
`

type SandboxPlaywrightExecutor struct {
	Timeout          time.Duration
	StagehandAdapter bool
	RunnerCommand    []string // optional custom command override; defaults to embedded Node Playwright runner
}

func (e *SandboxPlaywrightExecutor) Run(ctx context.Context, c *sandbox.Container, p CheckPlan) (CheckReport, error) {
	if c == nil || *c == nil {
		return CheckReport{}, errors.New("sandbox container is required")
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	data, err := json.Marshal(p)
	if err != nil {
		return CheckReport{}, err
	}

	command := e.RunnerCommand
	if len(command) == 0 {
		const scriptPath = "/tmp/wapo-browser-runner.mjs"
		if err := (*c).WriteFile(ctx, scriptPath, []byte(PlaywrightRunnerScript), 0o600, ""); err != nil {
			return CheckReport{}, fmt.Errorf("write browser runner script: %w", err)
		}
		command = []string{"node", scriptPath}
	}

	r, err := (*c).Exec(ctx, sandbox.ExecOpts{
		Command:        command,
		Stdin:          data,
		Timeout:        timeout,
		MaxOutputBytes: 2 << 20,
	})
	if err != nil {
		return CheckReport{}, err
	}
	if r.ExitCode != 0 {
		return CheckReport{}, fmt.Errorf("browser runner exited %d: %s", r.ExitCode, strings.TrimSpace(r.Stderr))
	}
	var report CheckReport
	if err := json.Unmarshal([]byte(strings.TrimSpace(r.Stdout)), &report); err != nil {
		return CheckReport{}, fmt.Errorf("decode browser check report: %w", err)
	}
	return report, nil
}

type HandsOnRunner struct {
	Loop           *agent.ReviewLoop
	Executor       BrowserExecutor
	Container      *sandbox.Container
	Checkpoint     *sandbox.CheckpointManager
	Profile        *secrets.QAProfile
	Memory         []memory.Note
	DefaultHeaders map[string]string
	ScreenshotDir  string
	Telemetry      RunTelemetry
	Reports        []CheckReport

	mu        sync.Mutex
	lastState sandbox.BrowserState
}

func (h *HandsOnRunner) Run(ctx context.Context, request string) (agent.Result, error) {
	if h.Loop == nil || h.Executor == nil {
		return agent.Result{}, errors.New("review loop and browser executor are required")
	}
	var promptExtra strings.Builder
	promptExtra.WriteString("\nQA profile (descriptions only): use the scoped vault CLI inside the sandbox for approved test credentials. Never request or expose raw secret values.\n")
	if h.Profile != nil {
		promptExtra.WriteString(fmt.Sprint(h.Profile.Describe()))
		promptExtra.WriteByte('\n')
	}
	if memCtx := memory.FormatContext(h.Memory, "hands_on", request, 4000); memCtx != "" {
		promptExtra.WriteString(memCtx)
		promptExtra.WriteByte('\n')
	}

	// Copy loop config so repeated runs do not duplicate tools/guards/prompts.
	loopCopy := *h.Loop
	loopCopy.SystemPrompt = strings.TrimSpace(h.Loop.SystemPrompt + "\n" + promptExtra.String())
	loopCopy.Tools = append(append([]tool.InvokableTool(nil), h.Loop.Tools...),
		checkTool{h},
		checkpointTool{h: h, rollback: false},
		checkpointTool{h: h, rollback: true},
	)
	loopCopy.Guards = append(append([]agent.CompletionGuard(nil), h.Loop.Guards...), agent.RequireToolCalled("run_browser_check"))
	return loopCopy.Run(ctx, request)
}

type checkTool struct{ h *HandsOnRunner }

func (t checkTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name:        "run_browser_check",
		Desc:        "Run a structured Playwright/Stagehand browser check plan inside the sandbox. Step actions include navigate, click, fill, wait_for, wait, assert_text, assert_visible, screenshot, stagehand_act, and stagehand_extract. The wait action accepts ms or timeout_ms and can wait for a target selector to become visible.",
		ParamsOneOf: schema.NewParamsOneOfByJSONSchema(jsonschema.Reflect(CheckPlan{})),
	}, nil
}

func (t checkTool) InvokableRun(ctx context.Context, raw string, _ ...tool.Option) (string, error) {
	var p CheckPlan
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return "", err
	}
	t.h.mu.Lock()
	if len(p.StorageState) == 0 && len(t.h.lastState.StorageState) > 0 {
		p.StorageState = t.h.lastState.StorageState
	}
	if t.h.ScreenshotDir != "" {
		p.ScreenshotDir = t.h.ScreenshotDir
	}
	if len(t.h.DefaultHeaders) > 0 {
		if p.ExtraHTTPHeaders == nil {
			p.ExtraHTTPHeaders = map[string]string{}
		}
		for k, v := range t.h.DefaultHeaders {
			if _, exists := p.ExtraHTTPHeaders[k]; !exists {
				p.ExtraHTTPHeaders[k] = v
			}
		}
	}
	t.h.mu.Unlock()

	r, err := t.h.Executor.Run(ctx, t.h.Container, p)
	if err != nil {
		return "", err
	}
	t.h.mu.Lock()
	t.h.Telemetry.BrowserCheckExecutions++
	t.h.Telemetry.ScreenshotsCaptured += len(r.Screenshots)
	t.h.Reports = append(t.h.Reports, r)
	if r.URL != "" || len(r.StorageState) > 0 {
		t.h.lastState = sandbox.BrowserState{
			URL:          r.URL,
			StorageState: r.StorageState,
			StepIndex:    t.h.Telemetry.BrowserCheckExecutions,
		}
	}
	t.h.mu.Unlock()

	b, _ := json.Marshal(r)
	return string(b), nil
}

type checkpointArgs struct {
	ID           string          `json:"id,omitempty"`
	Label        string          `json:"label,omitempty"`
	URL          string          `json:"url,omitempty"`
	StorageState json.RawMessage `json:"storage_state,omitempty"`
}

type checkpointTool struct {
	h        *HandsOnRunner
	rollback bool
}

func (t checkpointTool) Info(context.Context) (*schema.ToolInfo, error) {
	name, desc := "save_checkpoint", "Save paired workspace and browser checkpoint"
	if t.rollback {
		name, desc = "rollback_checkpoint", "Restore paired workspace and browser checkpoint"
	}
	return &schema.ToolInfo{
		Name:        name,
		Desc:        desc,
		ParamsOneOf: schema.NewParamsOneOfByJSONSchema(jsonschema.Reflect(checkpointArgs{})),
	}, nil
}

func (t checkpointTool) InvokableRun(ctx context.Context, raw string, _ ...tool.Option) (string, error) {
	if t.h.Checkpoint == nil {
		return "", errors.New("checkpoint manager is unavailable")
	}
	var in checkpointArgs
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return "", err
	}
	if t.rollback {
		cp, err := t.h.Checkpoint.Rollback(ctx, in.ID)
		if err != nil {
			return "", err
		}
		t.h.mu.Lock()
		t.h.Telemetry.Rollbacks++
		t.h.lastState = cp.State
		t.h.mu.Unlock()
		b, _ := json.Marshal(cp)
		return string(b), nil
	}
	t.h.mu.Lock()
	state := sandbox.BrowserState{URL: in.URL, StorageState: in.StorageState}
	if state.URL == "" {
		state.URL = t.h.lastState.URL
	}
	if len(state.StorageState) == 0 {
		state.StorageState = t.h.lastState.StorageState
	}
	t.h.mu.Unlock()
	label := in.Label
	if label == "" {
		label = "browser"
	}
	cp, err := t.h.Checkpoint.Save(ctx, label, state)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(cp)
	return string(b), nil
}
