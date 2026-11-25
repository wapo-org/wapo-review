package verifier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"github.com/eino-contrib/jsonschema"
	"github.com/wapo-org/wapo-review/internal/analyzer"
	"github.com/wapo-org/wapo-review/internal/workspace"
)

type FindingDraft struct {
	File          string `json:"file"`
	StartLine     int    `json:"start_line"`
	EndLine       int    `json:"end_line"`
	Severity      string `json:"severity"`
	Category      string `json:"category"`
	Title         string `json:"title"`
	Body          string `json:"body"`
	EvidenceQuote string `json:"evidence_quote"`
	SuggestedFix  string `json:"suggested_fix,omitempty"`
	Confidence    string `json:"confidence"`
}

type VerifyResponse struct {
	Accepted    bool     `json:"accepted"`
	FindingID   string   `json:"finding_id,omitempty"`
	Errors      []string `json:"errors,omitempty"`
	Hints       []string `json:"hints,omitempty"`
	NearbyLines string   `json:"nearby_lines,omitempty"`
	OnDiffLine  bool     `json:"on_diff_line"`
}

type Verifier struct {
	mu      sync.Mutex
	Root    string
	PRFiles map[string]bool
	Patches map[string]string
}

func New(root string, prFiles []string, patches map[string]string) *Verifier {
	m := map[string]bool{}
	for _, p := range prFiles {
		m[filepath.ToSlash(filepath.Clean(p))] = true
	}
	return &Verifier{Root: root, PRFiles: m, Patches: patches}
}

func isRetractedOrPlaceholderFinding(title, body string) bool {
	title = strings.TrimSpace(title)
	if len([]rune(title)) < 8 || (len(title) >= 2 && ((title[0] == '(' && title[len(title)-1] == ')') || (title[0] == '[' && title[len(title)-1] == ']'))) {
		return true
	}
	t := strings.ToLower(strings.TrimSpace(strings.Trim(title, ".!?:;\"'`")))
	switch t {
	case "", "ignore", "ignored", "none", "n/a", "no bug", "not a bug", "false positive", "nevermind", "never mind", "discard", "retract", "retracted", "skip":
		return true
	}
	b := strings.ToLower(strings.TrimSpace(body))
	if len([]rune(b)) < 20 || strings.HasSuffix(b, "?") {
		return true
	}
	for _, phrase := range []string{"likely object parse?", "not sure if", "might not be a bug", "unsure whether", "could be intentional?"} {
		if strings.Contains(b, phrase) {
			return true
		}
	}
	for _, suffix := range []string{"no bug.", "no bug", "not a bug.", "not a bug", "false positive.", "false positive", "please ignore.", "ignore this."} {
		if strings.HasSuffix(b, suffix) {
			return true
		}
	}
	return false
}

func (v *Verifier) Verify(d FindingDraft, ws *workspace.SharedWorkspace) (VerifyResponse, workspace.VerifiedFinding) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.verify(d, ws)
}

func (v *Verifier) VerifyAndRecord(d FindingDraft, ws *workspace.SharedWorkspace, shardID string) (VerifyResponse, workspace.VerifiedFinding, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	resp, vf := v.verify(d, ws)
	if !resp.Accepted || ws == nil {
		return resp, vf, nil
	}
	if err := ws.AppendFinding(shardID, vf); err != nil {
		return VerifyResponse{}, workspace.VerifiedFinding{}, err
	}
	return resp, vf, nil
}

func (v *Verifier) verify(d FindingDraft, ws *workspace.SharedWorkspace) (VerifyResponse, workspace.VerifiedFinding) {
	if len([]rune(strings.TrimSpace(d.Title))) < 8 || (len(d.Title) >= 2 && ((d.Title[0] == '(' && d.Title[len(d.Title)-1] == ')') || (d.Title[0] == '[' && d.Title[len(d.Title)-1] == ']'))) {
		return VerifyResponse{Errors: []string{"title is too short or malformed; provide a concise, specific bug title"}}, workspace.VerifiedFinding{}
	}
	if isRetractedOrPlaceholderFinding(d.Title, d.Body) {
		return VerifyResponse{Errors: []string{"finding body appears uncertain or incomplete, or the finding is retracted; verify the code before submitting"}}, workspace.VerifiedFinding{}
	}
	p := filepath.ToSlash(filepath.Clean(d.File))
	if !v.PRFiles[p] {
		return VerifyResponse{Errors: []string{"file is not in this PR"}, Hints: v.closest(p)}, workspace.VerifiedFinding{}
	}
	full := filepath.Join(v.Root, filepath.FromSlash(p))
	b, err := readVerifierFile(full)
	if err != nil {
		return VerifyResponse{Errors: []string{"file does not exist in repository"}, Hints: v.closest(p)}, workspace.VerifiedFinding{}
	}
	lines := strings.Split(string(b), "\n")
	if d.StartLine < 1 || d.EndLine < d.StartLine || d.EndLine > len(lines) {
		return VerifyResponse{
			Errors: []string{fmt.Sprintf("line range must be within 1..%d", len(lines))},
			Hints:  []string{fmt.Sprintf("file %s has %d lines", p, len(lines))},
		}, workspace.VerifiedFinding{}
	}

	want := normalize(d.EvidenceQuote)
	if want == "" {
		return VerifyResponse{Errors: []string{"evidence_quote is required"}}, workspace.VerifiedFinding{}
	}

	loWin := max(1, d.StartLine-5)
	hiWin := min(len(lines), d.EndLine+5)
	windowText := normalize(strings.Join(lines[loWin-1:hiWin], "\n"))
	match := strings.Contains(windowText, want)
	if !match {
		r := VerifyResponse{Errors: []string{"evidence quote not found near submitted lines"}}
		// Search entire file (single line or sliding window) so model gets exact self-correction hint.
		foundLine := findEvidenceLine(lines, want)
		if foundLine > 0 {
			lo := max(1, foundLine-2)
			hi := min(len(lines), foundLine+2)
			r.Hints = append(r.Hints, fmt.Sprintf("matching evidence found at line %d; resubmit with corrected start_line/end_line", foundLine))
			var sb strings.Builder
			for n := lo; n <= hi; n++ {
				fmt.Fprintf(&sb, "%d | %s\n", n, lines[n-1])
			}
			r.NearbyLines = strings.TrimRight(sb.String(), "\n")
		} else {
			r.Hints = append(r.Hints, "re-read the file and quote an exact snippet from the target lines")
		}
		return r, workspace.VerifiedFinding{}
	}

	// Support both bare GitHub per-file patches (starting with @@) and full unified diffs.
	patchText := v.Patches[p]
	if patchText != "" && !strings.Contains(patchText, "+++ b/") {
		patchText = "+++ b/" + p + "\n" + patchText
	}
	diff := analyzer.ParseUnifiedDiff(patchText)
	onDiff := false
	for n := d.StartLine; n <= d.EndLine; n++ {
		if diff.IsNew(p, n) {
			onDiff = true
			break
		}
	}

	h := sha256.Sum256([]byte(strings.ToLower(p) + "\x00" + strings.ToLower(strings.TrimSpace(d.Title)) + "\x00" + want))
	id := hex.EncodeToString(h[:12])
	if ws != nil {
		if all, err := ws.ReadAllFindings(); err == nil {
			for _, f := range all {
				if f.Fingerprint == id {
					return VerifyResponse{Errors: []string{"duplicate finding already submitted in shared workspace"}}, workspace.VerifiedFinding{}
				}
				file := filepath.ToSlash(filepath.Clean(f.File))
				lineDistance := f.StartLine - d.StartLine
				if lineDistance < 0 {
					lineDistance = -lineDistance
				}
				if file == p && lineDistance <= 3 && (strings.EqualFold(strings.TrimSpace(f.Title), strings.TrimSpace(d.Title)) || normalize(f.EvidenceQuote) == want) {
					return VerifyResponse{Errors: []string{"duplicate finding already submitted near these lines"}}, workspace.VerifiedFinding{}
				}
			}
		}
	}

	vf := workspace.VerifiedFinding{
		ID:            id,
		File:          p,
		StartLine:     d.StartLine,
		EndLine:       d.EndLine,
		Severity:      NormalizeSeverity(d.Severity),
		Category:      d.Category,
		Title:         d.Title,
		Body:          d.Body,
		EvidenceQuote: d.EvidenceQuote,
		SuggestedFix:  d.SuggestedFix,
		Confidence:    d.Confidence,
		OnDiffLine:    onDiff,
		Fingerprint:   id,
		CreatedAt:     time.Now().UTC(),
	}
	return VerifyResponse{Accepted: true, FindingID: id, OnDiffLine: onDiff}, vf
}

const maxVerifierFileBytes = 32 << 20

func readVerifierFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxVerifierFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxVerifierFileBytes {
		return nil, fmt.Errorf("file exceeds verifier size limit")
	}
	return data, nil
}

// NormalizeSeverity maps common LLM severity aliases (e.g. P0/P1/P2/P3, error/warning)
// into the canonical critical|high|medium|low|info scale.
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "p0", "sev0", "sev-0", "blocker":
		return "critical"
	case "high", "p1", "sev1", "sev-1", "error", "major":
		return "high"
	case "medium", "p2", "sev2", "sev-2", "warn", "warning", "moderate":
		return "medium"
	case "low", "p3", "p4", "sev3", "sev-3", "minor", "nit":
		return "low"
	case "info", "note":
		return "info"
	default:
		return "medium"
	}
}

func findEvidenceLine(lines []string, wantNorm string) int {
	for i, l := range lines {
		if strings.Contains(normalize(l), wantNorm) {
			return i + 1
		}
	}
	// Multi-line fallback: scan 4-line windows.
	for i := 0; i < len(lines); i++ {
		end := min(len(lines), i+4)
		if strings.Contains(normalize(strings.Join(lines[i:end], "\n")), wantNorm) {
			return i + 1
		}
	}
	return 0
}

func (v *Verifier) closest(p string) []string {
	var paths []string
	for x := range v.PRFiles {
		paths = append(paths, x)
	}
	sort.Strings(paths)
	if len(paths) > 0 {
		return []string{"closest PR paths: " + strings.Join(paths[:min(3, len(paths))], ", ")}
	}
	return nil
}

func normalize(s string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToLower(s) {
		if unicode.IsSpace(r) {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

type submitTool struct {
	v     *Verifier
	w     *workspace.SharedWorkspace
	shard string
}

func NewSubmitFindingTool(v *Verifier, w *workspace.SharedWorkspace, shardID string) tool.InvokableTool {
	return submitTool{v: v, w: w, shard: shardID}
}

func (t submitTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name:        "submit_finding",
		Desc:        "Verify and submit a candidate code review finding against actual repository lines and PR diff",
		ParamsOneOf: schema.NewParamsOneOfByJSONSchema(jsonschema.Reflect(FindingDraft{})),
	}, nil
}

func (t submitTool) InvokableRun(_ context.Context, raw string, _ ...tool.Option) (string, error) {
	var d FindingDraft
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		resp := VerifyResponse{Errors: []string{"invalid JSON payload: " + err.Error()}}
		b, _ := json.Marshal(resp)
		return string(b), nil
	}
	resp, _, err := t.v.VerifyAndRecord(d, t.w, t.shard)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(resp)
	return string(b), err
}

type markFileArgs struct {
	File         string `json:"file"`
	Summary      string `json:"summary,omitempty"`
	HunksChecked int    `json:"hunks_checked,omitempty"`
}

type markTool struct {
	cb func(file, summary string, hunks int)
}

func NewMarkFileReviewedTool(onReviewed func(file string)) tool.InvokableTool {
	return markTool{cb: func(file, _ string, _ int) {
		if onReviewed != nil {
			onReviewed(file)
		}
	}}
}

func NewMarkFileReviewedDetailedTool(onMarked func(file, summary string, hunks int)) tool.InvokableTool {
	return markTool{cb: onMarked}
}

func (t markTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name:        "mark_file_reviewed",
		Desc:        "Mark an assigned file reviewed. Supply a brief summary of changed hunks and invariants checked, including whether remaining hunks were checked for a distinct issue even if one bug was submitted.",
		ParamsOneOf: schema.NewParamsOneOfByJSONSchema(jsonschema.Reflect(markFileArgs{})),
	}, nil
}

func (t markTool) InvokableRun(_ context.Context, raw string, _ ...tool.Option) (string, error) {
	var in markFileArgs
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return "", err
	}
	if t.cb != nil {
		t.cb(in.File, in.Summary, in.HunksChecked)
	}
	return `{"reviewed":true}`, nil
}
