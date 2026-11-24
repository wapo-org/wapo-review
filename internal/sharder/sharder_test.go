package sharder

import (
	"fmt"
	"strings"
	"testing"

	"github.com/wapo-org/wapo-review/internal/graph"
)

func TestShardFilesFastPathAffinityAndSplitting(t *testing.T) {
	// 1. Small changes -> single unified shard fast path.
	small := []PRFile{
		{Path: "src/a.ts", Patch: "@@ -1,1 +1,2 @@\n const a = 1;\n+const b = 2;"},
		{Path: "src/a.test.ts", IsTest: true, Patch: "@@ -1,1 +1,2 @@\n+test();"},
	}
	fast := ShardFiles(small, nil, 10000)
	if len(fast) != 1 || len(fast[0].Files) != 2 {
		t.Fatalf("expected 1 fast-path shard with 2 files, got %+v", fast)
	}
	if !strings.Contains(fast[0].LineNumberedDiff, "   2 | +const b = 2;") {
		t.Fatalf("expected bare GitHub patch line-numbered, got:\n%s", fast[0].LineNumberedDiff)
	}

	// 2. >6 files: keep call-chain (webhook.ts <-> webhookRoute.ts <-> http.ts) in SAME shard!
	sources := map[string][]byte{
		"src/webhooks/webhook.ts":      []byte("export function handleWebhook() { return 1; }\n"),
		"src/routes/webhookRoute.ts":   []byte("import { handleWebhook } from '../webhooks/webhook';\nexport function mountWebhook() { return handleWebhook(); }\n"),
		"src/server/http.ts":           []byte("import { mountWebhook } from '../routes/webhookRoute';\nexport function startHTTP() { return mountWebhook(); }\n"),
		"src/billing/a.ts":             []byte("export function a() {}\n"),
		"src/billing/b.ts":             []byte("export function b() {}\n"),
		"src/billing/c.ts":             []byte("export function c() {}\n"),
		"src/billing/d.ts":             []byte("export function d() {}\n"),
		"src/billing/e.ts":             []byte("export function e() {}\n"),
		"src/billing/f.ts":             []byte("export function f() {}\n"),
		"src/billing/g.ts":             []byte("export function g() {}\n"),
		"src/webhooks/webhook.test.ts": []byte("import { handleWebhook } from './webhook';\nhandleWebhook();\n"),
	}
	idx := graph.NewCodebaseIndex(sources, "t", "r", "sha")
	var files []PRFile
	for p := range sources {
		files = append(files, PRFile{
			Path:   p,
			IsTest: strings.Contains(p, ".test."),
			Patch:  "@@ -1,1 +1,2 @@\n+// change",
		})
	}
	shards := ShardFiles(files, idx, 20000)
	if len(shards) < 2 {
		t.Fatalf("expected >=2 shards for 10 prod files, got %d", len(shards))
	}

	// Verify webhook chain + its test all landed in the same shard, and NO shard has >3 production files.
	shardOf := map[string]string{}
	for _, s := range shards {
		prodCount := 0
		for _, f := range s.Files {
			shardOf[f.Path] = s.ID
			if !f.IsTest {
				prodCount++
			}
		}
		if prodCount > 3 {
			t.Fatalf("shard %s exceeded 3 production files (%d): %+v", s.ID, prodCount, s.Checklist)
		}
	}
	if shardOf["src/webhooks/webhook.ts"] == "" ||
		shardOf["src/webhooks/webhook.ts"] != shardOf["src/routes/webhookRoute.ts"] ||
		shardOf["src/webhooks/webhook.ts"] != shardOf["src/server/http.ts"] {
		t.Fatalf("expected call chain in same shard, got %+v", shardOf)
	}
	if shardOf["src/webhooks/webhook.test.ts"] != shardOf["src/webhooks/webhook.ts"] {
		t.Fatalf("expected paired test attached to webhook shard, got %+v", shardOf)
	}

	// 3. Token budget splitting.
	var big []PRFile
	for i := 0; i < 8; i++ {
		big = append(big, PRFile{Path: fmt.Sprintf("pkg/f%d.go", i), Patch: strings.Repeat("+line\n", 400)})
	}
	tokShards := ShardFiles(big, nil, 1500)
	if len(tokShards) < 3 {
		t.Fatalf("expected token budget to split into >=3 shards, got %d", len(tokShards))
	}
}

func TestHunkSplittingAndCrossShardLinks(t *testing.T) {
	files := []PRFile{
		{Path: "src/a.ts", Patch: strings.Repeat("@@ -1 +1 @@\n+x\n", 8)},
		{Path: "src/b.ts", Patch: strings.Repeat("@@ -1 +1 @@\n+y\n", 8)},
	}
	idx := graph.NewCodebaseIndex(map[string][]byte{"src/a.ts": []byte(`db.query("accounts");`), "src/b.ts": []byte(`db.insert("accounts", value);`)}, "t", "r", "s")
	shards := ShardFiles(files, idx, 12000)
	if len(shards) != 2 {
		t.Fatalf("expected hunk budget to split dense two-file PR, got %d shards", len(shards))
	}
	if shards[0].Hunks != 8 || len(shards[0].CrossShardLinks) == 0 {
		t.Fatalf("missing hunk count or cross-shard link: %+v", shards[0])
	}
}

func TestPublicSizingAndGraphClustering(t *testing.T) {
	patch := "@@ -1 +1 @@\n+x\n@@ -3 +3 @@\n+y"
	if CountHunks(patch) != 2 {
		t.Fatalf("CountHunks = %d", CountHunks(patch))
	}
	f := PRFile{Path: "x.go", Patch: "12345678"}
	if EstFileTokens(f) != 2 {
		t.Fatalf("EstFileTokens = %d", EstFileTokens(f))
	}

	sources := map[string][]byte{
		"packages/protocol/src/message.ts": []byte(`db.query("accounts");`),
		"apps/api/src/message.ts":          []byte(`import { Message } from '../../../packages/protocol/src/message'; db.insert("accounts", value);`),
	}
	idx := graph.NewCodebaseIndex(sources, "t", "r", "s")
	files := []PRFile{
		{Path: "packages/protocol/src/message.ts", Patch: "@@ -1 +1 @@\n+x"},
		{Path: "apps/api/src/message.ts", Patch: "@@ -1 +1 @@\n+y"},
		{Path: "huge/file.ts", Patch: strings.Repeat("x", 80)},
	}
	buckets := ClusterFilesByGraph(files, idx, ClusterOptions{MaxFiles: 2, MaxHunks: 2, TokenBudget: 10, PreferGraph: true})
	locations := map[string]int{}
	for i, bucket := range buckets {
		if len(bucket) > 2 {
			t.Fatalf("bucket exceeds file limit: %v", bucket)
		}
		for _, file := range bucket {
			locations[file.Path] = i
		}
	}
	if len(locations) != len(files) {
		t.Fatalf("files dropped: locations=%v", locations)
	}
	if locations["packages/protocol/src/message.ts"] != locations["apps/api/src/message.ts"] {
		t.Fatalf("graph pair split: %v", locations)
	}
}
