package review

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"github.com/wapo-org/wapo-review/internal/analyzer"
	"github.com/wapo-org/wapo-review/internal/graph"
	"github.com/wapo-org/wapo-review/internal/orchestrator"
	"github.com/wapo-org/wapo-review/internal/sandbox"
	"github.com/wapo-org/wapo-review/internal/sharder"
	"github.com/wapo-org/wapo-review/internal/verifier"
	"github.com/wapo-org/wapo-review/internal/workspace"
)

func TestSelectSpecialistBatchesGroupsHighRiskFiles(t *testing.T) {
	files := []sharder.PRFile{
		{Path: "workflows/turnCommit.ts", Patch: "@@ -1 +1 @@\n+commitTurn(state)"},
		{Path: "turns.ts", Patch: "@@ -1 +1 @@\n+turn state"},
		{Path: "runs.ts", Patch: "@@ -1 +1 @@\n+run workflow"},
		{Path: "account.ts", Patch: "@@ -1 +1 @@\n+account credit"},
		{Path: "sandboxSpend.ts", Patch: "@@ -1 +1 @@\n+sandbox spend ledger"},
		{Path: "platformLedger.ts", Patch: "@@ -1 +1 @@\n+platform ledger compact"},
		{Path: "execution.ts", Patch: "@@ -1 +1 @@\n+execution token"},
		{Path: "embed.ts", Patch: "@@ -1 +1 @@\n+embed key sha256"},
		{Path: "secrets.ts", Patch: "@@ -1 +1 @@\n+secret keyring"},
		{Path: "app.ts", Patch: "@@ -1 +1 @@\n+auth token"},
		{Path: "turn_test.go", Patch: "@@ -1 +1 @@\n+turn", IsTest: true},
		{Path: "api/schema.ts", Patch: "@@ -1 +1 @@\n+export interface Schema { value: string }"},
		{Path: "logic/pager.ts", Patch: "@@ -1 +1 @@\n+return cursor limit"},
		{Path: "turn_test.go", Patch: "@@ -1 +1 @@\n+turn", IsTest: true},
		{Path: "settings.css", Patch: "@@ -1 +1 @@\n+color: red"},
		{Path: "README.md", Patch: "@@ -1 +1 @@\n+notes"},
		{Path: "empty.ts", Patch: ""},
	}
	batches := SelectSpecialistBatches(files, 6, 12000)
	if len(batches) < 3 {
		t.Fatalf("got %d batches, want >=3: %#v", len(batches), batches)
	}
	seenFocus := map[string]bool{}
	for _, b := range batches {
		seenFocus[b.Focus] = true
		if len(b.Files) > 3 {
			t.Fatalf("batch %s has %d files (>3)", b.ID, len(b.Files))
		}
		if len(b.Checklist) != len(b.Files) {
			t.Fatalf("batch %s checklist=%v must match files", b.ID, b.Checklist)
		}
		for i, f := range b.Files {
			if b.Checklist[i] != f.Path {
				t.Errorf("batch %s checklist[%d]=%q, want file path %q", b.ID, i, b.Checklist[i], f.Path)
			}
			if f.IsTest || f.Path == "settings.css" || f.Path == "README.md" || f.Path == "empty.ts" {
				t.Errorf("selected benign/test file %q", f.Path)
			}
		}
		if strings.TrimSpace(b.LineNumberedDiff) == "" {
			t.Errorf("empty diff for %s", b.ID)
		}
	}
	for _, focus := range specialistFocusOrder {
		if !seenFocus[focus] {
			t.Errorf("missing focus %q", focus)
		}
	}
}

func TestSpecialistV2FocusesAndBalancedQuotas(t *testing.T) {
	var files []sharder.PRFile
	for i := 0; i < 15; i++ {
		files = append(files, sharder.PRFile{Path: fmt.Sprintf("workflow/state%d.go", i), Patch: "@@ -1 +1 @@\n+status transition mutex"})
	}
	files = append(files,
		sharder.PRFile{Path: "api/schema.ts", Patch: "@@ -1 +1 @@\n+export interface Schema { value: string }"},
		sharder.PRFile{Path: "logic/pager.ts", Patch: "@@ -1 +1 @@\n+return cursor paginate limit"},
		sharder.PRFile{Path: "billing/ledger.ts", Patch: "@@ -1 +1 @@\n+purge compact replay"},
		sharder.PRFile{Path: "auth/keyring.ts", Patch: "@@ -1 +1 @@\n+encrypt sha256 consent"},
	)
	batches := SelectSpecialistBatchesWithFeedback(files, nil, SpecialistFeedback{}, 5, 12000)
	seen := map[string]bool{}
	for _, batch := range batches {
		seen[batch.Focus] = true
	}
	for _, focus := range []string{"abstraction_contract", "logic_bs", "state_machine", "accounting_lifecycle", "auth_crypto_parity"} {
		if !seen[focus] {
			t.Errorf("balanced batches omitted focus %q: %+v", focus, batches)
		}
	}
}

func TestAccountingLifecycleRoutesAndPacksLifecycleFiles(t *testing.T) {
	files := []sharder.PRFile{
		{Path: "cloud/convex/account.ts", Patch: "@@ -1 +1 @@\n+await ctx.db.patch(accountId, { deletedAt: now });"},
		{Path: "cloud/convex/sandboxSpend.ts", Patch: "@@ -1 +1 @@\n+await ctx.db.insert(\"spend\", { accountId, amount });"},
		{Path: "cloud/convex/platformLedger.ts", Patch: "@@ -1 +1 @@\n+for (const row of rows) await ctx.db.patch(row._id, { settled: true });"},
		{Path: "cloud/convex/crons.ts", Patch: "@@ -1 +1 @@\n+await ctx.db.insert(\"sweep\", { scheduledAt: now });"},
	}
	batches := SelectSpecialistBatches(files, 20, 12000)
	accountingFiles := map[string]bool{}
	multiFileAccountingBatch := false
	for _, batch := range batches {
		if batch.Focus != "accounting_lifecycle" {
			continue
		}
		if len(batch.Files) > 1 {
			multiFileAccountingBatch = true
		}
		for _, f := range batch.Files {
			accountingFiles[f.Path] = true
		}
	}
	for _, f := range files {
		if !accountingFiles[f.Path] {
			t.Errorf("%s was not routed to accounting_lifecycle", f.Path)
		}
	}
	if !multiFileAccountingBatch {
		t.Fatalf("accounting_lifecycle files did not form a multi-file batch: %+v", batches)
	}
}

func TestSpecialistInvestigationRulesRequireInspectionAndConcreteFindings(t *testing.T) {
	for _, required := range []string{
		"For EVERY assigned file",
		"read_file or grep",
		"before calling mark_file_reviewed",
		"Pre-injected Stage 1 findings",
		"2nd or 3rd distinct bug",
		"Never submit uncertain, malformed, or speculative findings",
		"title (>= 12 chars)",
		"concrete trigger/failure scenario",
		"exact evidence_quote",
	} {
		if !strings.Contains(specialistInvestigationRules, required) {
			t.Errorf("investigation prompt missing %q", required)
		}
	}
}

func TestSpecialistV2MultiLensFeedbackAndCrossDirectoryClustering(t *testing.T) {
	files := []sharder.PRFile{
		{Path: "packages/protocol/index.ts", Patch: "@@ -1 +1 @@\n+export function route() { if (cursor) return Schema; }\n@@ -2 +2 @@\n+limit"},
		{Path: "apps/web/client.ts", Patch: "@@ -1 +1 @@\n+import { route } from 'protocol';\n@@ -2 +2 @@\n+export const client = route;"},
		{Path: "services/pager.ts", Patch: "@@ -1 +1 @@\n+return cursor limit\n@@ -2 +2 @@\n+limit\n@@ -3 +3 @@\n+size"},
	}
	idx := graph.NewCodebaseIndex(map[string][]byte{
		"packages/protocol/index.ts": []byte("export function route() { return 1 }"),
		"apps/web/client.ts":         []byte("import { route } from '../../packages/protocol'; export const client = route"),
	}, "", "", "")
	fb := SpecialistFeedback{Complexities: []analyzer.FunctionComplexity{{File: "services/pager.ts", Delta: 29}}, FindingsByFile: map[string]int{}, TurnsPerHunk: map[string]float64{"services/pager.ts": .4}, CrossShardFiles: map[string][]string{"services/pager.ts": {"x"}}}
	batches := SelectSpecialistBatchesWithFeedback(files, idx, fb, 15, 12000)
	present := map[string]map[string]bool{}
	for _, b := range batches {
		if present[b.Focus] == nil {
			present[b.Focus] = map[string]bool{}
		}
		for _, f := range b.Files {
			present[b.Focus][f.Path] = true
		}
	}
	if !present["abstraction_contract"]["packages/protocol/index.ts"] || !present["logic_bs"]["packages/protocol/index.ts"] {
		t.Fatalf("multi-signal file did not qualify for two lenses: %+v", present)
	}
	foundCluster := false
	for _, b := range batches {
		if b.Focus == "abstraction_contract" && present[b.Focus]["packages/protocol/index.ts"] && present[b.Focus]["apps/web/client.ts"] {
			for _, f := range b.Files {
				if f.Path == "packages/protocol/index.ts" {
					foundCluster = true
				}
			}
		}
	}
	if !foundCluster {
		t.Fatalf("cross-directory import pair was not clustered: %+v", batches)
	}
	_, reasons, _ := scoreSpecialistFile(files[2], nil, fb)
	joined := strings.Join(reasons["logic_bs"], " ")
	for _, phrase := range []string{"complexity delta +29", "0 general findings", "skimmed", "cross-shard"} {
		if !strings.Contains(joined, phrase) {
			t.Errorf("missing feedback reason %q in %q", phrase, joined)
		}
	}
}

func TestAccountDeletionSingleHunkNotEvictedFromAccountingLifecycle(t *testing.T) {
	patch := "@@ -1,27 +1,56 @@\n+import { z } from 'zod';\n+const PurgeBatchSchema = z.strictObject({ done: z.boolean() });\n-export function accountEraser(rpc, ownership, deleteExternal) {\n-  if (result.ready && !externalDone) { await deleteExternal(userId); }\n-  ...(externalDone ? {} : {retainClerk: true}),\n+export function accountEraser(rpc, ownership) {\n+  for (;;) {\n+    const result = await rpc.mutation('account:purge', { userId });\n+    if (result.done) return;\n+  }\n+}"
	f := sharder.PRFile{Path: "cloud/apps/api/src/account-deletion.ts", Patch: patch}
	batches := SelectSpecialistBatchesWithFeedback([]sharder.PRFile{f}, nil, SpecialistFeedback{FindingsByFile: map[string]int{}}, 10, 12000)
	foundAccounting := false
	for _, b := range batches {
		if b.Focus == "accounting_lifecycle" {
			for _, bf := range b.Files {
				if bf.Path == f.Path {
					foundAccounting = true
				}
			}
		}
	}
	if !foundAccounting {
		t.Fatalf("account-deletion.ts was evicted from accounting_lifecycle: %+v", batches)
	}
}

func TestSelectSpecialistBatchesEnforcesCapsAndDoesNotDropLargeFile(t *testing.T) {
	var files []sharder.PRFile
	for i := 0; i < 8; i++ {
		files = append(files, sharder.PRFile{
			Path:  "workflow/turn" + string(rune('a'+i)) + ".go",
			Patch: "@@ -1 +1 @@\n+turn",
		})
	}
	files = append(files, sharder.PRFile{
		Path:  "secrets/keyring.go",
		Patch: "@@ -1 +1 @@\n+secret keyring encrypt decrypt sha256 hmac token auth",
	})
	batches := SelectSpecialistBatches(files, 2, 10)
	if len(batches) != 2 {
		t.Fatalf("got %d batches, want cap 2", len(batches))
	}
	foundKeyring := false
	for _, b := range batches {
		if len(b.Files) > 3 {
			t.Errorf("batch %s has %d files", b.ID, len(b.Files))
		}
		for _, f := range b.Files {
			if f.Path == "secrets/keyring.go" {
				foundKeyring = true
			}
		}
	}
	if !foundKeyring {
		t.Fatalf("large high-risk file secrets/keyring.go was dropped or not prioritized: %#v", batches)
	}
	_ = foundKeyring
}

func TestRunSpecialistPassSubmitsVerifiedFinding(t *testing.T) {
	repoDir := t.TempDir()
	relPath := "workflows/turnCommit.ts"
	fullPath := filepath.Join(repoDir, relPath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	content := "export function commitTurn(state: string) {\n  if (state === 'paused') return approveNow();\n  return false;\n}\n"
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	patch := "@@ -1,3 +1,4 @@\n export function commitTurn(state: string) {\n+  if (state === 'paused') return approveNow();\n   return false;\n }"
	ws, err := workspace.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ver := verifier.New(repoDir, []string{relPath}, map[string]string{relPath: patch})
	c := &sandbox.LocalContainer{Root: repoDir}

	m := &scriptedModel{
		responses: []*schema.Message{
			{
				Role: schema.Assistant,
				ToolCalls: []schema.ToolCall{
					{ID: "tc1", Function: schema.FunctionCall{Name: "read_shared_findings", Arguments: `{}`}},
				},
			},
			{
				Role: schema.Assistant,
				ToolCalls: []schema.ToolCall{
					{
						ID: "tc2",
						Function: schema.FunctionCall{
							Name:      "submit_finding",
							Arguments: `{"file":"workflows/turnCommit.ts","start_line":2,"end_line":2,"severity":"high","category":"concurrency","title":"Approval commits while paused","body":"Calling approveNow when paused races with turn pause.","evidence_quote":"if (state === 'paused') return approveNow();","confidence":"high"}`,
						},
					},
					{
						ID: "tc3",
						Function: schema.FunctionCall{
							Name:      "mark_file_reviewed",
							Arguments: `{"file":"workflows/turnCommit.ts"}`,
						},
					},
				},
			},
			{Role: schema.Assistant, Content: "Specialist audit complete."},
		},
	}

	p := &Pipeline{
		ModelFactory: func(context.Context) (model.ToolCallingChatModel, error) { return m, nil },
	}
	prs := []sharder.PRFile{{Path: relPath, Status: "modified", Patch: patch}}
	sum := p.runSpecialistPass(context.Background(), orchestrator.ReviewInput{RunID: "test:1", Repo: "org/app", PRNumber: 1}, prs, nil, nil, ws, ver, c, nil)
	if sum.Batches < 1 || sum.Files < 1 || sum.Findings != 1 || sum.Rejected != 0 {
		t.Fatalf("unexpected specialist summary: %+v", sum)
	}
	all, err := ws.ReadAllFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Title != "Approval commits while paused" {
		t.Fatalf("unexpected workspace findings: %+v", all)
	}
}
