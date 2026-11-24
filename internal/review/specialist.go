package review

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/cloudwego/eino/components/tool"
	"github.com/wapo-org/wapo-review/internal/agent"
	"github.com/wapo-org/wapo-review/internal/analyzer"
	"github.com/wapo-org/wapo-review/internal/graph"
	"github.com/wapo-org/wapo-review/internal/memory"
	"github.com/wapo-org/wapo-review/internal/orchestrator"
	"github.com/wapo-org/wapo-review/internal/sandbox"
	"github.com/wapo-org/wapo-review/internal/semantic"
	"github.com/wapo-org/wapo-review/internal/sharder"
	"github.com/wapo-org/wapo-review/internal/verifier"
	"github.com/wapo-org/wapo-review/internal/workspace"
	"golang.org/x/sync/errgroup"
)

type SpecialistFeedback struct {
	Complexities     []analyzer.FunctionComplexity
	FindingsByFile   map[string]int
	TurnsPerHunk     map[string]float64
	CrossShardFiles  map[string][]string
	LeadTargets      map[string]int
	ExistingFindings []workspace.VerifiedFinding
}

type SpecialistBatch struct {
	ID               string
	Focus            string
	Files            []sharder.PRFile
	Checklist        []string
	LineNumberedDiff string
	Score            int
	EstTokens        int
	Hunks            int
	TriggerReasons   map[string][]string
}

type specialistSummary struct {
	Batches  int
	Files    int
	Findings int
	Rejected int
	Turns    int
	ByFocus  map[string]int
}

type scoredPRFile struct {
	file    sharder.PRFile
	score   int
	reasons []string
	hunks   int
}

var specialistFocusOrder = []string{"accounting_lifecycle", "state_machine", "auth_crypto_parity", "abstraction_contract", "logic_bs"}

var specialistChecklists = map[string][]string{
	"abstraction_contract": {
		"Verify every changed or removed export, schema, type, route, and callback signature against ALL real callers and importers using grep and read_file; check optional and retired fields too.",
		"Trace wrapper and adapter calls end to end. Confirm they forward every required parameter, including userId, options, stream flags, and headers, without dropping or swapping fields.",
		"Compare paired cross-package and service contracts such as protocol, web, api, and convex. Identify concrete compatibility failures for old callers, fields, or routes.",
	},
	"logic_bs": {
		"Trace control flow for branch inversions, cursor keys mutated during indexed sort or pagination, resurrected soft-delete tombstones, off-by-one bounds, UTF-16 surrogate and UTF-8 byte math, and partial-failure state corruption.",
		"Challenge guards and fixes: verify actual byte/rate bounds, pre-buffer versus post-buffer checks, double-escaped JSON accounting, swallowed errors, silent no-ops, dropped options or busy-lease events, dead or leaky wrappers, and tautological compatibility guards or tests.",
		"Zero false positives: never submit style nits or uncertain guesses. Prove an exact wrong runtime outcome with a concrete trigger and exact evidence_quote.",
	},
	"state_machine": {
		"Enumerate every state transition and concurrent writer or delivery interleaving across callers and database tables. Follow transitions through persistence and callbacks.",
		"Check approval, pause, resume, and cancel races, including decisions arriving mid-turn or while paused. Verify start and idempotency keys cannot bind to terminal or cancelling runs.",
		"Trace busy-lease, lock, and slot-replacement accounting on errors, timeouts, refused boots, retries, and concurrent deliveries.",
	},
	"accounting_lifecycle": {
		"Check purge, delete, and compaction batches against byte and document limits, including Convex 1 MiB document and 16 MiB query bounds. Trace orphaned pre-deletion blobs and tickets and unscheduled sweep crons.",
		"Verify replay and idempotency protection across compaction, retries, and billing-period boundaries, including stable keys and exactly-once effects.",
		"Trace partial-failure spend, quota, credit, and replaced-writer slot accounting, including refused boots and error rollback. Check auth source, revocation, and cleanup completeness for destructive account actions.",
	},
	"auth_crypto_parity": {
		"Trace key-ID versus raw-secret use, such as SHA-256 digest versus raw key, and verify hashing and keying consistency across every caller.",
		"Compare keyrings, ciphertext versions (v1/v2), and envelope encoding across services, modules, migrations, and rotation scripts. Verify legacy data remains readable where required.",
		"Check key invalidation slice/revision CAS binding, consent enforcement, and auth/header trust boundaries at every entry point.",
	},
}

const specialistInvestigationRules = "For EVERY assigned file, you MUST inspect surrounding functions, callers, or sibling/paired modules using read_file or grep before calling mark_file_reviewed — never rubber-stamp a file from the diff hunk alone.\n" +
	"Pre-injected Stage 1 findings are listed ONLY so you don't duplicate them. Treat files with existing Stage 1 findings as high-probability homes for a 2nd or 3rd distinct bug in other hunks.\n" +
	"Never submit uncertain, malformed, or speculative findings; every submission must have a specific title (>= 12 chars), concrete trigger/failure scenario, and exact evidence_quote.\n"

func SelectSpecialistBatches(files []sharder.PRFile, maxBatches, tokenBudget int) []SpecialistBatch {
	return SelectSpecialistBatchesWithFeedback(files, nil, SpecialistFeedback{}, maxBatches, tokenBudget)
}

func SelectSpecialistBatchesWithFeedback(files []sharder.PRFile, idx *graph.CodebaseIndex, fb SpecialistFeedback, maxBatches, tokenBudget int) []SpecialistBatch {
	if tokenBudget <= 0 {
		tokenBudget = 12000
	}
	prodCount := 0
	for _, f := range files {
		if !f.IsTest && strings.TrimSpace(f.Patch) != "" {
			prodCount++
		}
	}
	grouped := map[string][]scoredPRFile{}
	for _, f := range files {
		if f.IsTest || strings.TrimSpace(f.Patch) == "" {
			continue
		}
		scores, reasons, hunks := scoreSpecialistFile(f, idx, fb)
		qualified := make([]string, 0, 2)
		for _, focus := range specialistFocusOrder {
			if scores[focus] >= 2 {
				qualified = append(qualified, focus)
			}
		}
		sort.SliceStable(qualified, func(i, j int) bool {
			if scores[qualified[i]] != scores[qualified[j]] {
				return scores[qualified[i]] > scores[qualified[j]]
			}
			return focusIndex(qualified[i]) < focusIndex(qualified[j])
		})
		if len(qualified) > 2 {
			qualified = qualified[:2]
		}
		for _, focus := range qualified {
			grouped[focus] = append(grouped[focus], scoredPRFile{f, scores[focus], reasons[focus], hunks})
		}
	}
	if maxBatches <= 0 {
		maxBatches = (prodCount + 13) / 14
		if maxBatches < 5 {
			maxBatches = 5
		}
		if maxBatches > 20 {
			maxBatches = 20
		}
	}
	byFocus := map[string][]SpecialistBatch{}
	for _, focus := range specialistFocusOrder {
		byFocus[focus] = buildFocusBatches(focus, grouped[focus], idx, tokenBudget)
	}
	var batches []SpecialistBatch
	used := map[string]int{}
	rounds := 2
	if maxBatches >= 15 {
		rounds = 3
	}
	for round := 0; round < rounds; round++ {
		for _, focus := range specialistFocusOrder {
			if len(byFocus[focus]) > round && len(batches) < maxBatches {
				batches = append(batches, byFocus[focus][round])
				used[focus]++
			}
		}
	}
	type candidate struct {
		focus string
		batch SpecialistBatch
	}
	var rest []candidate
	for _, focus := range specialistFocusOrder {
		for _, b := range byFocus[focus][used[focus]:] {
			rest = append(rest, candidate{focus, b})
		}
	}
	sort.SliceStable(rest, func(i, j int) bool { return rest[i].batch.Score > rest[j].batch.Score })
	for _, c := range rest {
		if len(batches) >= maxBatches {
			break
		}
		batches = append(batches, c.batch)
	}
	for i := range batches {
		batches[i].ID = fmt.Sprintf("specialist-%s-%d", batches[i].Focus, i+1)
	}
	return batches
}

func focusIndex(f string) int {
	for i, v := range specialistFocusOrder {
		if f == v {
			return i
		}
	}
	return len(specialistFocusOrder)
}

func countChangedLines(patch string) int {
	n := 0
	for _, line := range strings.Split(patch, "\n") {
		if (strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++")) ||
			(strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---")) {
			n++
		}
	}
	return n
}

func hasRemovedGuardOrCleanup(patch string) bool {
	for _, line := range strings.Split(patch, "\n") {
		if !strings.HasPrefix(line, "-") || strings.HasPrefix(line, "---") {
			continue
		}
		l := strings.ToLower(line)
		for _, tok := range []string{"delete", "revoke", "clerk", "retain", "legacy", "v1.", "consent", "guard", "verify", "filter", "throw "} {
			if strings.Contains(l, tok) {
				return true
			}
		}
	}
	return false
}

func scoreSpecialistFile(f sharder.PRFile, idx *graph.CodebaseIndex, fb SpecialistFeedback) (map[string]int, map[string][]string, int) {
	scores, reasons := map[string]int{}, map[string][]string{}
	add := func(focus, reason string, points int) {
		scores[focus] += points
		reasons[focus] = append(reasons[focus], reason)
	}
	p, path := strings.ToLower(f.Patch), strings.ToLower(f.Path)
	hunks := strings.Count(f.Patch, "@@")
	changedLines := countChangedLines(f.Patch)
	removedGuardOrCleanup := hasRemovedGuardOrCleanup(f.Patch)
	maxDelta := 0
	for _, c := range fb.Complexities {
		if c.File == f.Path && c.Delta > maxDelta {
			maxDelta = c.Delta
		}
	}
	// Abstraction & contract signals (generic export scored lower than domain lenses so it never evicts them).
	if strings.Contains(p, "export type") || strings.Contains(p, "export interface") || strings.Contains(p, "schema") || strings.Contains(p, ".get(") || strings.Contains(p, ".post(") || strings.Contains(p, ".put(") || strings.Contains(p, ".delete(") || strings.Contains(p, "router.") || strings.Contains(path, "adapter") || strings.Contains(path, "wrapper") || strings.Contains(path, "protocol") || strings.Contains(path, "routes") || strings.Contains(path, "contract") {
		add("abstraction_contract", "public contract or route change", 3)
	} else if strings.Contains(p, "export function") || strings.Contains(p, "export const") || strings.Contains(p, "export class") || strings.Contains(path, "client") {
		add("abstraction_contract", "exported symbol or client boundary change", 2)
	}
	// Logic & bullshit signals (avoid bare `return` / `||` matching every file).
	if strings.Contains(p, "catch") || strings.Contains(p, "cursor") || strings.Contains(p, "paginate") || strings.Contains(p, "tombstone") || strings.Contains(p, "deletedat") || strings.Contains(p, "guard") || strings.Contains(p, "limit") || strings.Contains(p, "slice(") || strings.Contains(p, "while") {
		add("logic_bs", "logic, bounds, or fallback change", 3)
	}
	if strings.Contains(path, "workflow") || strings.Contains(path, "turn") || strings.Contains(path, "run") || strings.Contains(path, "state") || strings.Contains(path, "lease") || strings.Contains(path, "sandbox") || strings.Contains(p, "status") || strings.Contains(p, "transition") || strings.Contains(p, "mutex") || strings.Contains(p, "atomic") || strings.Contains(p, "approval") || strings.Contains(p, "cancel") || strings.Contains(p, "pause") {
		pts := 3
		if strings.Contains(path, "workflow") || strings.Contains(path, "turn") || strings.Contains(path, "run") || strings.Contains(path, "sandbox") || strings.Contains(path, "approval") {
			pts += 2
		}
		add("state_machine", "state or concurrency signal", pts)
	}
	lifecycleTerms := []string{"account", "ledger", "spend", "billing", "quota", "credit", "usage", "purge", "delete", "deletion", "sweep", "cron", "compact", "compaction", "retention", "cleanup", "blob", "upload", "ticket", "receipt", "period", "slot", "capacity", "refund", "reserve", "settle", "store", "sizeguard", "hydrate", "batch"}
	lifecycleStructural := []string{".delete(", ".patch(", ".insert(", "ctx.storage", "for (", "for (;;)", "while", "paginate", "take(", "collect(", "rpc.mutation"}
	lifecycleMatch := false
	for _, term := range lifecycleTerms {
		if strings.Contains(path, term) || strings.Contains(p, term) {
			lifecycleMatch = true
			break
		}
	}
	lifecycleStructure := false
	for _, signal := range lifecycleStructural {
		if strings.Contains(p, signal) {
			lifecycleStructure = true
			break
		}
	}
	lifecyclePathHit := strings.Contains(path, "account") || strings.Contains(path, "ledger") || strings.Contains(path, "spend") || strings.Contains(path, "billing") || strings.Contains(path, "quota") || strings.Contains(path, "cron") || strings.Contains(path, "webtools") || strings.Contains(path, "deletion") || strings.Contains(path, "purge")
	if lifecyclePathHit || (lifecycleMatch && lifecycleStructure) {
		pts := 3
		if lifecyclePathHit {
			pts += 2
		}
		if lifecycleMatch && lifecycleStructure {
			pts++
		}
		add("accounting_lifecycle", "accounting or lifecycle signal", pts)
	}
	authPathHit := strings.Contains(path, "auth") || strings.Contains(path, "secret") || strings.Contains(path, "key") || strings.Contains(path, "encrypt") || strings.Contains(path, "user") || strings.Contains(path, "session")
	if authPathHit || strings.Contains(p, "encrypt") || strings.Contains(p, "decrypt") || strings.Contains(p, "sha256") || strings.Contains(p, "consent") || strings.Contains(p, "token") || strings.Contains(p, "hmac") || strings.Contains(p, "clerk") {
		pts := 3
		if authPathHit {
			pts += 2
		}
		add("auth_crypto_parity", "authentication or cryptography signal", pts)
	}
	if maxDelta > 0 {
		add("logic_bs", fmt.Sprintf("complexity delta +%d", maxDelta), min(6, maxDelta/4))
	}
	if removedGuardOrCleanup {
		addEach(scores, reasons, "removed guard, compat, or cleanup logic", 4)
	}
	if (hunks >= 3 || changedLines >= 20 || len(f.Patch) >= 1200 || maxDelta >= 4) && fb.FindingsByFile[f.Path] == 0 {
		addEach(scores, reasons, "0 general findings across substantial diff", 4)
	}
	if hunks >= 3 && fb.TurnsPerHunk[f.Path] > 0 && fb.TurnsPerHunk[f.Path] < .8 {
		addEach(scores, reasons, "skimmed in general pass", 3)
	}
	if len(fb.CrossShardFiles[f.Path]) > 0 || fb.LeadTargets[f.Path] > 0 {
		addEach(scores, reasons, "cross-shard or lead hotspot", 3)
	}
	if fb.FindingsByFile[f.Path] > 0 {
		addEach(scores, reasons, "existing finding; check distinct bugs", 2)
	}
	if idx != nil {
		if peers := idx.PairedModules(f.Path); len(peers) > 0 {
			add("abstraction_contract", "paired module", 3)
		}
		if peers := idx.SharedTablePeers(f.Path); len(peers) > 0 {
			add("accounting_lifecycle", "shared table relationship", 2)
			add("state_machine", "shared table relationship", 2)
		}
		if len(idx.ImportersOf(f.Path)) > 0 || len(idx.ImportsOf(f.Path)) > 0 {
			add("abstraction_contract", "cross-package import relationship", 2)
		}
	}
	return scores, reasons, hunks
}

func addEach(scores map[string]int, reasons map[string][]string, reason string, points int) {
	for _, f := range specialistFocusOrder {
		if scores[f] > 0 {
			scores[f] += points
			reasons[f] = append(reasons[f], reason)
		}
	}
}

func buildFocusBatches(focus string, files []scoredPRFile, idx *graph.CodebaseIndex, budget int) []SpecialistBatch {
	if len(files) == 0 {
		return nil
	}
	byPath := make(map[string]scoredPRFile, len(files))
	prFiles := make([]sharder.PRFile, 0, len(files))
	for _, f := range files {
		byPath[f.file.Path] = f
		prFiles = append(prFiles, f.file)
	}
	clusters := sharder.ClusterFilesByGraph(prFiles, idx, sharder.ClusterOptions{
		MaxFiles:    3,
		MaxHunks:    14,
		TokenBudget: budget,
		PreferGraph: true,
	})
	out := make([]SpecialistBatch, 0, len(clusters))
	for _, cluster := range clusters {
		b := SpecialistBatch{Focus: focus, TriggerReasons: map[string][]string{}}
		for _, f := range cluster {
			sf := byPath[f.Path]
			b.Files = append(b.Files, f)
			b.Checklist = append(b.Checklist, f.Path)
			b.Hunks += sf.hunks
			b.EstTokens += sharder.EstFileTokens(f)
			b.Score += sf.score
			b.TriggerReasons[f.Path] = sf.reasons
		}
		b.LineNumberedDiff = formatSpecialistDiff(b.Files)
		out = append(out, b)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Checklist[0] < out[j].Checklist[0]
	})
	return out
}
func formatSpecialistDiff(files []sharder.PRFile) string {
	var b strings.Builder
	for i, f := range files {
		if i > 0 {
			b.WriteString("\n\n")
		}
		fmt.Fprintf(&b, "=== %s ===\n%s", f.Path, sharder.FormatLineNumberedDiff(f.Path, f.Patch))
	}
	return b.String()
}

func (p *Pipeline) runSpecialistPass(ctx context.Context, in orchestrator.ReviewInput, prs []sharder.PRFile, idx *graph.CodebaseIndex, ret *semantic.Retriever, ws *workspace.SharedWorkspace, ver *verifier.Verifier, container sandbox.Container, memNotes []memory.Note) specialistSummary {
	return p.runSpecialistPassWithFeedback(ctx, in, prs, idx, ret, ws, ver, container, memNotes, SpecialistFeedback{})
}

func (p *Pipeline) runSpecialistPassWithFeedback(ctx context.Context, in orchestrator.ReviewInput, prs []sharder.PRFile, idx *graph.CodebaseIndex, ret *semantic.Retriever, ws *workspace.SharedWorkspace, ver *verifier.Verifier, container sandbox.Container, memNotes []memory.Note, fb SpecialistFeedback) specialistSummary {
	batches := SelectSpecialistBatchesWithFeedback(prs, idx, fb, 0, 12000)
	summary := specialistSummary{Batches: len(batches), ByFocus: map[string]int{}}
	for _, b := range batches {
		summary.Files += len(b.Files)
		summary.ByFocus[b.Focus]++
	}
	if p.ModelFactory == nil || len(batches) == 0 {
		return summary
	}
	limit := p.MaxShardConcurrency
	if limit < 1 {
		limit = 8
	}
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(limit)
	for _, batch := range batches {
		batch := batch
		g.Go(func() error {
			m, err := p.ModelFactory(gctx)
			if err != nil || m == nil {
				return nil
			}
			reviewed := map[string]bool{}
			var revMu sync.Mutex
			accepted, rejected := 0, 0
			tools := []tool.InvokableTool{verifier.NewSubmitFindingTool(ver, ws, batch.ID), verifier.NewMarkFileReviewedDetailedTool(func(f, _ string, _ int) { revMu.Lock(); reviewed[f] = true; revMu.Unlock() }), workspace.NewPostLeadTool(ws, batch.ID), workspace.NewReadSharedFindingsTool(ws), newSandboxReadFileTool(container), newSandboxGrepTool(container)}
			var sys strings.Builder
			sys.WriteString("You are a principal specialist auditor conducting a second-order deep pass for concrete bugs. Do not report style nits. Use exact evidence quotes and prove runtime impact. Do not spend Turn 1 calling read_shared_findings unless checking unrelated files.\n")
			sys.WriteString(specialistInvestigationRules)
			for _, item := range specialistChecklists[batch.Focus] {
				sys.WriteString("- " + item + "\n")
			}
			sys.WriteString("Call mark_file_reviewed for every assigned file after checking all changed hunks.")
			for path, reasons := range batch.TriggerReasons {
				fmt.Fprintf(&sys, "\n%s selected because %s", path, strings.Join(reasons, ", "))
			}
			findings := fb.ExistingFindings
			if len(findings) == 0 {
				findings, _ = ws.ReadAllFindings()
			}
			allowed := map[string]bool{}
			for _, f := range batch.Files {
				allowed[f.Path] = true
				if idx != nil {
					for _, n := range append(append(idx.ImportsOf(f.Path), idx.ImportersOf(f.Path)...), idx.SharedTablePeers(f.Path)...) {
						allowed[n] = true
					}
				}
			}
			var prompt strings.Builder
			fmt.Fprintf(&prompt, "Specialist batch %s (focus: %s)\nChecklist files: %s\n\n", batch.ID, batch.Focus, strings.Join(batch.Checklist, ", "))
			prompt.WriteString("## Why these files were selected\n")
			for path, rs := range batch.TriggerReasons {
				fmt.Fprintf(&prompt, "- %s: %s\n", path, strings.Join(rs, ", "))
			}
			prompt.WriteString("\n## Already-reported findings for these files & neighbors (DO NOT re-report; hunt strictly for distinct missed bugs)\n")
			for _, f := range findings {
				if allowed[f.File] {
					fmt.Fprintf(&prompt, "- %s:%d %s: %s\n", f.File, f.StartLine, f.Title, f.EvidenceQuote)
				}
			}
			prompt.WriteString("\n")
			if idx != nil {
				if gc := idx.FormatGraphContext(batch.Checklist, 2500); gc != "" {
					fmt.Fprintf(&prompt, "## Repo map\n%s\n\n", gc)
				}
			}
			if ret != nil {
				if rc, e := ret.RetrieveContext(gctx, batch.Checklist, 2500); e == nil && rc != "" {
					fmt.Fprintf(&prompt, "## Related context\n%s\n\n", rc)
				}
			}
			fmt.Fprintf(&prompt, "## Line-numbered diff\n%s\n", batch.LineNumberedDiff)
			if mc := memory.FormatContext(memNotes, "code_review", strings.Join(batch.Checklist, " "), 2000); mc != "" {
				sys.WriteString("\n\nRepository memory:\n" + mc)
			}
			loop := &agent.ReviewLoop{Model: m, SystemPrompt: sys.String(), Tools: tools, Guards: []agent.CompletionGuard{agent.RequireAllItemsCompleted(batch.Checklist)}, MaxTurns: 20, MaxNudges: 1, Redactor: p.Redactor, OnToolResult: func(rec agent.ToolRecord, ev *agent.ReviewEvidence) {
				revMu.Lock()
				if rec.Name == "submit_finding" {
					if strings.Contains(rec.Result, `"accepted":true`) {
						accepted++
					} else if strings.Contains(rec.Result, `"accepted":false`) {
						rejected++
					}
				}
				for f := range reviewed {
					ev.CompletedItems[f] = true
				}
				revMu.Unlock()
			}}
			res, runErr := loop.Run(gctx, prompt.String())
			mu.Lock()
			summary.Findings += accepted
			summary.Rejected += rejected
			summary.Turns += len(res.Turns)
			mu.Unlock()
			status := "completed"
			errStr := ""
			if runErr != nil {
				status = "partial"
				errStr = runErr.Error()
			}
			p.logInfo("specialist_done", "run_id", in.RunID, "batch", batch.ID, "focus", batch.Focus, "status", status, "error", errStr, "turns", len(res.Turns), "findings", accepted, "rejected", rejected, "files", len(batch.Files), "hunks", batch.Hunks, "triggers", len(batch.TriggerReasons), "tokens_in", res.Usage.InputTokens, "tokens_out", res.Usage.OutputTokens)
			return nil
		})
	}
	_ = g.Wait()
	return summary
}
