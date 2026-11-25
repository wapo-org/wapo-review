package graph

import (
	"strings"
	"testing"
)

func TestIndexIncrementalCopyCyclesTestsPageRankAndCache(t *testing.T) {
	files := map[string][]byte{
		"src/auth.ts":         []byte("import { db } from './db';\nexport function verifyToken() { return db(); }\n"),
		"src/db.ts":           []byte("import { verifyToken } from './auth';\nexport function db() { return verifyToken(); }\n"),
		"src/billing.ts":      []byte("export function charge() { return 1; }\n"),
		"src/auth.test.ts":    []byte("import { verifyToken } from './auth';\nverifyToken();\n"),
		"src/billing.test.ts": []byte("import { charge } from './billing';\ncharge();\n"),
	}
	idx := NewCodebaseIndex(files, "tenant1", "org_repo", "base1")
	if idx.ParsedFilesCount != 5 {
		t.Fatalf("expected 5 parsed files, got %d", idx.ParsedFilesCount)
	}

	// Cycle detection (auth.ts <-> db.ts)
	cycles := idx.FindCycles()
	if len(cycles) != 1 || len(cycles[0]) != 2 {
		t.Fatalf("expected 1 cycle of length 2 (auth.ts <-> db.ts), got %+v", cycles)
	}

	// Targeted TestsFor (auth.ts should match auth.test.ts, NOT billing.test.ts)
	authTests := idx.TestsFor("src/auth.ts")
	if len(authTests) != 1 || authTests[0] != "src/auth.test.ts" {
		t.Fatalf("expected only [src/auth.test.ts] for src/auth.ts, got %v", authTests)
	}

	// PageRank boosts changed file and neighbors
	ranks := idx.PageRank([]string{"src/auth.ts"})
	if ranks["src/auth.ts"] <= ranks["src/billing.ts"] {
		t.Fatalf("expected changed file src/auth.ts to outrank src/billing.ts: %+v", ranks)
	}
	repoMap := idx.RenderRepoMap([]string{"src/auth.ts"})
	if !strings.HasPrefix(repoMap, "src/auth.ts") {
		t.Fatalf("expected repo map to lead with src/auth.ts, got:\n%s", repoMap)
	}

	// IncrementalCopy reparses ONLY changed files and removes deleted files
	inc := idx.IncrementalCopy("tenant1", "org_repo", "head2", map[string][]byte{
		"src/auth.ts": []byte("export function verifyTokenV2() { return true; }\n"),
	}, []string{"src/billing.ts"})
	if inc.ParsedFilesCount != 1 {
		t.Fatalf("expected incremental ParsedFilesCount=1, got %d", inc.ParsedFilesCount)
	}
	if _, exists := inc.Files["src/billing.ts"]; exists {
		t.Fatal("expected deleted file src/billing.ts removed")
	}
	if len(inc.SymbolsNamed("verifyTokenV2")) != 1 {
		t.Fatalf("expected new symbol verifyTokenV2 after incremental copy")
	}
	if len(inc.FindCycles()) != 0 {
		t.Fatalf("expected cycle broken after removing import in src/auth.ts, got %+v", inc.FindCycles())
	}

	// Cache Save / Load / SeedBase / Prune with protection
	cache := NewProfilerCache(t.TempDir())
	if err := cache.Save(idx, "base1"); err != nil {
		t.Fatalf("Save base1 failed: %v", err)
	}
	if err := cache.Save(inc, "base1"); err != nil {
		t.Fatalf("Save head2 failed: %v", err)
	}
	extra := inc.IncrementalCopy("tenant1", "org_repo", "head3", nil, nil)
	if err := cache.Save(extra, "base1"); err != nil {
		t.Fatalf("Save head3 failed: %v", err)
	}
	baseSHA, seeded, err := cache.SeedBase("tenant1", "org_repo", "base1")
	if err != nil || baseSHA != "base1" || len(seeded.Files) != 5 {
		t.Fatalf("SeedBase unexpected: sha=%q err=%v", baseSHA, err)
	}
	removed, err := cache.Prune("tenant1", "org_repo", 2, "base1")
	if err != nil || removed != 1 {
		t.Fatalf("expected 1 entry pruned while protecting base1, removed=%d err=%v", removed, err)
	}
	if _, err := cache.Load("tenant1", "org_repo", "base1"); err != nil {
		t.Fatalf("protected base1 should still load: %v", err)
	}
}

func TestSeedBaseRejectsDifferentRequestedBase(t *testing.T) {
	cache := NewProfilerCache(t.TempDir())
	idx := NewCodebaseIndex(map[string][]byte{"a.go": []byte("package a")}, "t", "r", "base-one")
	if err := cache.Save(idx, "base-one"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cache.SeedBase("t", "r", "base-two"); err == nil {
		t.Fatal("SeedBase returned a different base SHA")
	}
}

func TestInvariantNeighbors(t *testing.T) {
	files := map[string][]byte{
		"apps/api/src/secrets.ts": []byte(`db.query("accounts");`),
		"convex/agent/secrets.ts": []byte(`db.insert("accounts", value);`),
		"convex/jobs.ts":          []byte(`db.query("jobs");`),
	}
	idx := NewCodebaseIndex(files, "t", "r", "s")
	if got := idx.SharedTablePeers("apps/api/src/secrets.ts"); len(got) != 1 || got[0] != "convex/agent/secrets.ts" {
		t.Fatalf("shared table peers: %v", got)
	}
	if got := idx.PairedModules("apps/api/src/secrets.ts"); len(got) != 1 || got[0] != "convex/agent/secrets.ts" {
		t.Fatalf("paired modules: %v", got)
	}
	if got := idx.FormatGraphContext([]string{"apps/api/src/secrets.ts"}, 2000); !strings.Contains(got, "Invariant neighbors") || !strings.Contains(got, "convex/agent/secrets.ts") {
		t.Fatalf("missing invariant neighbors: %s", got)
	}
}

func TestExportedSymbolsAndContractPeers(t *testing.T) {
	idx := NewCodebaseIndex(map[string][]byte{
		"packages/protocol/src/index.ts":      []byte("export function Message() {}\nfunction _private() {}\n"),
		"apps/web/src/client.ts":              []byte("import { Message } from '../../../../packages/protocol/src/index';\n"),
		"packages/protocol/src/index.test.ts": []byte("import { Message } from './index';\n"),
	}, "t", "r", "s")
	if got := idx.ExportedSymbols("packages/protocol/src/index.ts"); len(got) != 1 || got[0] != "Message" {
		t.Fatalf("exported symbols: %v", got)
	}
	if got := idx.ContractPeers("packages/protocol/src/index.ts"); len(got) != 1 || got[0] != "apps/web/src/client.ts" {
		t.Fatalf("contract peers: %v", got)
	}
}

func TestPairedModulesByExportedSymbolOverlap(t *testing.T) {
	idx := NewCodebaseIndex(map[string][]byte{
		"apps/api/src/crypto.ts":       []byte("export function sealSecret() {}\nexport function unsealSecret() {}\n"),
		"convex/agent/keyring.ts":      []byte("export function sealSecret() {}\nexport function unsealSecret() {}\n"),
		"convex/agent/keyring.test.ts": []byte("export function sealSecret() {}\nexport function unsealSecret() {}\n"),
	}, "t", "r", "s")
	got := idx.PairedModules("apps/api/src/crypto.ts")
	if len(got) != 1 || got[0] != "convex/agent/keyring.ts" {
		t.Fatalf("symbol-overlap paired modules: %v", got)
	}
}

func TestSharedStatusPeersAndGraphContext(t *testing.T) {
	idx := NewCodebaseIndex(map[string][]byte{
		"turnCommit.ts": []byte("const a = 'pending'; const b = 'committing';"),
		"turns.ts":      []byte("const a = 'pending'; const b = 'committing';"),
		"runs.ts":       []byte("const a = 'pending'; const b = 'committing';"),
		"unrelated.ts":  []byte("const a = 'ready';"),
		"turns.test.ts": []byte("const a = 'pending'; const b = 'committing';"),
	}, "t", "r", "s")
	got := idx.SharedStatusPeers("turnCommit.ts")
	if len(got) != 2 || got[0] != "runs.ts" || got[1] != "turns.ts" {
		t.Fatalf("shared status peers: %v", got)
	}
	context := idx.FormatGraphContext([]string{"turnCommit.ts"}, 2000)
	if !strings.Contains(context, "shared_status: runs.ts, turns.ts") {
		t.Fatalf("missing shared status context: %s", context)
	}
}
