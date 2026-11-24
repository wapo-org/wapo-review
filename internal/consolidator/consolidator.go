package consolidator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"github.com/eino-contrib/jsonschema"
	"github.com/wapo-org/wapo-review/internal/agent"
	"github.com/wapo-org/wapo-review/internal/analyzer"
	"github.com/wapo-org/wapo-review/internal/redact"
	"github.com/wapo-org/wapo-review/internal/verifier"
	"github.com/wapo-org/wapo-review/internal/workspace"
)

type ConsolidatedFinding struct {
	ID          string   `json:"id"`
	File        string   `json:"file"`
	StartLine   int      `json:"start_line"`
	EndLine     int      `json:"end_line"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Body        string   `json:"body"`
	Evidence    string   `json:"evidence,omitempty"`
	Confidence  string   `json:"confidence,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	OnDiffLine  bool     `json:"on_diff_line"`
	NewCode     bool     `json:"new_code"`
	Sources     []string `json:"sources"`
}

type ConsolidatedResult struct {
	Findings           []ConsolidatedFinding `json:"findings"`
	QualityGate        string                `json:"quality_gate,omitempty"`
	QualityGateSummary string                `json:"quality_gate_summary,omitempty"`
	ShardCoverage      string                `json:"shard_coverage,omitempty"`
	BrowserSummary     string                `json:"browser_summary,omitempty"`
	BrowserReport      string                `json:"browser_report,omitempty"`
	VisualSummary      string                `json:"visual_summary,omitempty"`
}

type Review struct {
	Event, Body string
	Comments    []map[string]any
}

func fromWorkspace(f workspace.VerifiedFinding) ConsolidatedFinding {
	source := "shard"
	if f.ID != "" {
		source += ":" + f.ID
	}
	return ConsolidatedFinding{ID: f.ID, File: f.File, StartLine: f.StartLine, EndLine: f.EndLine, Severity: f.Severity, Category: f.Category, Title: f.Title, Body: f.Body, Evidence: f.EvidenceQuote, Confidence: f.Confidence, Fingerprint: f.Fingerprint, OnDiffLine: f.OnDiffLine, NewCode: f.OnDiffLine, Sources: []string{source}}
}
func fromAnalyzer(f analyzer.Finding) ConsolidatedFinding {
	id := f.Fingerprint
	if id == "" {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s", f.RuleID, f.File, f.StartLine, f.Message)))
		id = hex.EncodeToString(sum[:12])
	}
	// Function-level complexity and clone alerts belong in Check Runs and summary
	// sections so inline PR diff comments stay 100% high-signal bug/security findings.
	onDiff := f.NewCode && !strings.HasPrefix(f.RuleID, "COMPLEXITY.") && !strings.HasPrefix(f.RuleID, "CLONE.")
	return ConsolidatedFinding{ID: id, File: f.File, StartLine: f.StartLine, EndLine: f.EndLine, Severity: f.Severity, Category: f.Category, Title: f.Message, Body: "", Evidence: f.Evidence, Fingerprint: f.Fingerprint, OnDiffLine: onDiff, NewCode: f.NewCode, Sources: []string{"analyzer:" + f.RuleID}}
}

func isRetractedFinding(title, body string) bool {
	t := strings.ToLower(strings.TrimSpace(strings.Trim(title, ".!?:;\"'`")))
	switch t {
	case "", "ignore", "ignored", "none", "n/a", "no bug", "not a bug", "false positive", "nevermind", "never mind", "discard", "retract", "retracted", "skip":
		return true
	}
	b := strings.ToLower(strings.TrimSpace(body))
	for _, suffix := range []string{"no bug.", "no bug", "not a bug.", "not a bug", "false positive.", "false positive"} {
		if strings.HasSuffix(b, suffix) {
			return true
		}
	}
	return false
}

func Consolidate(shard []workspace.VerifiedFinding, static []analyzer.Finding, leads []workspace.Lead) ConsolidatedResult {
	out := make([]ConsolidatedFinding, 0, len(shard)+len(static))
	for _, f := range shard {
		if isRetractedFinding(f.Title, f.Body) {
			continue
		}
		out = append(out, fromWorkspace(f))
	}
	for _, f := range static {
		out = append(out, fromAnalyzer(f))
	}
	return ConsolidatedResult{Findings: deduplicate(out), ShardCoverage: fmt.Sprintf("%d shard findings, %d cross-shard leads", len(shard), len(leads))}
}

func rank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "p0", "sev0", "blocker":
		return 6
	case "high", "p1", "sev1", "error", "major":
		return 5
	case "medium", "p2", "sev2", "moderate":
		return 4
	case "warning", "warn":
		return 3
	case "low", "p3", "p4", "sev3", "minor":
		return 2
	case "info", "note":
		return 1
	}
	return 0
}
func similar(a, b ConsolidatedFinding) bool {
	return strings.EqualFold(strings.TrimSpace(a.Category), strings.TrimSpace(b.Category)) && strings.EqualFold(strings.TrimSpace(a.Title), strings.TrimSpace(b.Title))
}
func deduplicate(fs []ConsolidatedFinding) []ConsolidatedFinding {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		if fs[i].StartLine != fs[j].StartLine {
			return fs[i].StartLine < fs[j].StartLine
		}
		return fs[i].ID < fs[j].ID
	})
	out := make([]ConsolidatedFinding, 0, len(fs))
	for _, f := range fs {
		match := -1
		for i := range out {
			p := out[i]
			exact := f.Fingerprint != "" && f.Fingerprint == p.Fingerprint
			near := f.File == p.File && abs(f.StartLine-p.StartLine) <= 3 && similar(f, p)
			if exact || near {
				match = i
				break
			}
		}
		if match < 0 {
			out = append(out, f)
			continue
		}
		p := &out[match]
		p.Sources = appendUnique(p.Sources, f.Sources...)
		if rank(f.Severity) > rank(p.Severity) || (rank(f.Severity) == rank(p.Severity) && evidenceScore(f) > evidenceScore(*p)) {
			sources := p.Sources
			*p = f
			p.Sources = sources
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank(out[i].Severity) != rank(out[j].Severity) {
			return rank(out[i].Severity) > rank(out[j].Severity)
		}
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].StartLine < out[j].StartLine
	})
	return out
}
func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
func evidenceScore(f ConsolidatedFinding) int {
	return len(f.Evidence) + len(f.Body) + len(f.Confidence)
}
func appendUnique(dst []string, src ...string) []string {
	for _, s := range src {
		found := false
		for _, d := range dst {
			if d == s {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, s)
		}
	}
	return dst
}

type jsonTool struct {
	name   string
	schema any
	run    func(context.Context, string) (string, error)
}

func (t jsonTool) Info(context.Context) (*schema.ToolInfo, error) {
	info := &schema.ToolInfo{Name: t.name, Desc: "Consolidator review operation: " + t.name}
	if t.schema != nil {
		info.ParamsOneOf = schema.NewParamsOneOfByJSONSchema(jsonschema.Reflect(t.schema))
	}
	return info, nil
}
func (t jsonTool) InvokableRun(ctx context.Context, s string, _ ...tool.Option) (string, error) {
	return t.run(ctx, s)
}

// ConsolidateWithAgent performs deterministic consolidation first. Agent failures preserve that result.
func ConsolidateWithAgent(ctx context.Context, m model.ToolCallingChatModel, ws *workspace.SharedWorkspace, static []analyzer.Finding, leads []workspace.Lead) (ConsolidatedResult, error) {
	return ConsolidateWithAgentWithOptions(ctx, m, ws, static, leads, ConsolidateAgentOptions{})
}

type ConsolidateAgentOptions struct {
	ExtraTools   []tool.InvokableTool
	Verifier     *verifier.Verifier
	GraphContext string
	MaxTurns     int
}

func ConsolidateWithAgentWithOptions(ctx context.Context, m model.ToolCallingChatModel, ws *workspace.SharedWorkspace, static []analyzer.Finding, leads []workspace.Lead, opts ConsolidateAgentOptions) (ConsolidatedResult, error) {
	shard := []workspace.VerifiedFinding{}
	if ws != nil {
		var err error
		shard, err = ws.ReadAllFindings()
		if err != nil {
			return ConsolidatedResult{}, err
		}
	}
	result := Consolidate(shard, static, leads)
	if m == nil || ws == nil || (len(leads) == 0 && opts.GraphContext == "" && len(opts.ExtraTools) == 0) {
		return result, nil
	}
	encoded, _ := json.Marshal(leads)
	tools := []tool.InvokableTool{
		jsonTool{name: "read_shared_findings", run: func(context.Context, string) (string, error) { b, e := json.Marshal(shard); return string(b), e }},
		jsonTool{name: "read_leads", run: func(context.Context, string) (string, error) { return string(encoded), nil }},
		jsonTool{name: "submit_finding", schema: func() any {
			if opts.Verifier != nil {
				return verifier.FindingDraft{}
			}
			return workspace.VerifiedFinding{}
		}(), run: func(_ context.Context, raw string) (string, error) {
			if opts.Verifier != nil {
				var draft verifier.FindingDraft
				if err := json.Unmarshal([]byte(raw), &draft); err != nil {
					return "", err
				}
				response, finding := opts.Verifier.Verify(draft, ws)
				if response.Accepted {
					if err := ws.AppendFinding("consolidator", finding); err != nil {
						return "", err
					}
					result.Findings = deduplicate(append(result.Findings, fromWorkspace(finding)))
				}
				encoded, err := json.Marshal(response)
				return string(encoded), err
			}
			var f workspace.VerifiedFinding
			if err := json.Unmarshal([]byte(raw), &f); err != nil {
				return "", err
			}
			if f.File == "" || f.Title == "" {
				return `{"accepted":false}`, nil
			}
			if f.ID == "" {
				sum := sha256.Sum256([]byte(raw))
				f.ID = hex.EncodeToString(sum[:12])
			}
			result.Findings = deduplicate(append(result.Findings, fromWorkspace(f)))
			return `{"accepted":true}`, nil
		}},
	}
	tools = append(tools, opts.ExtraTools...)
	maxTurns := opts.MaxTurns
	if maxTurns <= 0 {
		maxTurns = 8
		if len(opts.ExtraTools) > 0 {
			maxTurns = 14
		}
	}
	systemPrompt := "Investigate unresolved cross-shard leads using shared findings and leads. Submit only actionable findings anchored to changed files. Do not modify files."
	userPrompt := "Review the unresolved leads and synthesize supported root causes across shards. Use read_leads and read_shared_findings before submitting a finding."
	if len(opts.ExtraTools) > 0 {
		systemPrompt += " Source tools are available. Inspect target files with read_file and grep, verify state-machine, parity, auth, and other invariant leads against repository code, and reject speculative or unverified leads. Submit findings only with exact evidence_quote text and accurate line numbers."
		userPrompt += " Use read_file and grep to inspect the actual target code before deciding whether each lead is valid."
	}
	if opts.GraphContext != "" {
		userPrompt += "\n\nCross-file invariant context:\n" + opts.GraphContext
	}
	loop := agent.ReviewLoop{Model: m, Tools: tools, Redactor: redact.New(), MaxTurns: maxTurns, MaxNudges: 1, SystemPrompt: systemPrompt}
	if _, err := loop.Run(ctx, userPrompt); err != nil {
		// Preserve deterministic consolidation on LLM failure.
		return result, nil
	}
	return result, nil
}

func FormatPRReview(res ConsolidatedResult, maxInline int) Review {
	if maxInline <= 0 {
		maxInline = 25
	}
	fs := deduplicate(append([]ConsolidatedFinding(nil), res.Findings...))
	review := Review{Event: "APPROVE"}
	var body strings.Builder
	if res.QualityGateSummary != "" {
		body.WriteString(res.QualityGateSummary)
		body.WriteString("\n\n")
	}
	if res.ShardCoverage != "" {
		fmt.Fprintf(&body, "Shard coverage: %s\n\n", res.ShardCoverage)
	}
	if res.BrowserSummary != "" || res.VisualSummary != "" || res.BrowserReport != "" {
		body.WriteString("## Browser and visual QA\n")
		if res.BrowserSummary != "" {
			fmt.Fprintf(&body, "- Browser: %s\n", res.BrowserSummary)
		}
		if res.VisualSummary != "" {
			fmt.Fprintf(&body, "- Visual: %s\n", res.VisualSummary)
		}
		if strings.TrimSpace(res.BrowserReport) != "" {
			fmt.Fprintf(&body, "\n<details><summary>Browser QA details</summary>\n\n%s\n\n</details>\n", strings.TrimSpace(res.BrowserReport))
		}
		body.WriteString("\n")
	}
	var overflow []ConsolidatedFinding
	for _, f := range fs {
		if f.NewCode && (rank(f.Severity) >= 5 || res.QualityGate == "failed") {
			review.Event = "REQUEST_CHANGES"
		} else if review.Event == "APPROVE" && rank(f.Severity) >= 2 {
			review.Event = "COMMENT"
		}
		if f.OnDiffLine && f.StartLine >= 1 && len(review.Comments) < maxInline {
			review.Comments = append(review.Comments, map[string]any{"path": f.File, "line": f.StartLine, "side": "RIGHT", "body": findingBody(f)})
		} else {
			overflow = append(overflow, f)
		}
	}
	if res.QualityGate == "failed" {
		review.Event = "REQUEST_CHANGES"
	}
	if len(overflow) > 0 {
		fmt.Fprintf(&body, "<details><summary>Additional findings (%d)</summary>\n\n", len(overflow))
		for _, f := range overflow {
			title := strings.TrimSpace(f.Title)
			detail := strings.TrimSpace(f.Body)
			if detail == "" || strings.EqualFold(title, detail) {
				fmt.Fprintf(&body, "- **%s:%d [%s]** %s <!-- wapo-review-finding:%s -->\n", f.File, f.StartLine, f.Severity, title, f.ID)
			} else {
				fmt.Fprintf(&body, "- **%s:%d [%s] %s**\n  %s <!-- wapo-review-finding:%s -->\n", f.File, f.StartLine, f.Severity, title, detail, f.ID)
			}
		}
		body.WriteString("\n</details>\n")
	}
	review.Body = strings.TrimSpace(body.String())
	return review
}
func findingBody(f ConsolidatedFinding) string {
	title := strings.TrimSpace(f.Title)
	detail := strings.TrimSpace(f.Body)
	sev := strings.ToUpper(strings.TrimSpace(f.Severity))
	header := title
	if sev != "" {
		header = fmt.Sprintf("**[%s]** %s", sev, title)
	}
	if detail == "" || strings.EqualFold(title, detail) {
		return fmt.Sprintf("%s\n\n<!-- wapo-review-finding:%s -->", header, f.ID)
	}
	return fmt.Sprintf("%s\n\n%s\n\n<!-- wapo-review-finding:%s -->", header, detail, f.ID)
}
