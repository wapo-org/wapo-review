package semantic

import (
	"context"
	"strings"
	"testing"

	"github.com/wapo-org/wapo-review/internal/graph"
)

type stubEmbedder struct {
	prefer string
}

func (s stubEmbedder) Embed(_ context.Context, texts []string) ([][]float32, error) {
	vecs := make([][]float32, len(texts))
	for i, t := range texts {
		if i == 0 || strings.Contains(t, s.prefer) {
			vecs[i] = []float32{1, 0}
		} else {
			vecs[i] = []float32{0, 1}
		}
	}
	return vecs, nil
}

func TestRetrieverBM25GraphEmbeddingsAndContextBudget(t *testing.T) {
	files := map[string][]byte{
		"internal/auth/token.go": []byte("package auth\nfunc ValidateJWTToken(tok string) bool { return tok != \"\" }\n"),
		"internal/api/handler.go": []byte("package api\nimport \"auth\"\nfunc HandleWebhook() bool { return ValidateJWTToken(\"x\") }\n"),
		"internal/ui/theme.go": []byte("package ui\nfunc RenderDarkTheme() string { return \"dark\" }\n"),
	}
	idx := graph.NewCodebaseIndex(files, "t1", "r1", "sha1")
	r := &Retriever{Index: idx}
	r.IndexFiles(files)
	if len(r.Chunks) < 3 {
		t.Fatalf("expected >= 3 code chunks, got %d", len(r.Chunks))
	}

	// BM25 lexical + graph query should surface ValidateJWTToken first.
	res := r.Search("ValidateJWTToken webhook", []string{"internal/api/handler.go"}, 2)
	if len(res) != 2 {
		t.Fatalf("expected topK=2 results, got %d", len(res))
	}
	if res[0].Chunk.File != "internal/api/handler.go" && res[0].Chunk.File != "internal/auth/token.go" {
		t.Fatalf("unexpected top BM25+graph result: %+v", res[0])
	}

	// Embedding reranker boosts semantically preferred chunk.
	r.Embedder = stubEmbedder{prefer: "RenderDarkTheme"}
	reranked, err := r.SearchWithEmbeddings(context.Background(), "token theme", nil, 3)
	if err != nil || len(reranked) == 0 {
		t.Fatalf("SearchWithEmbeddings failed: err=%v len=%d", err, len(reranked))
	}
	if reranked[0].Chunk.File != "internal/ui/theme.go" {
		t.Fatalf("expected embedding rerank to promote theme.go, got %+v", reranked[0])
	}

	// RetrieveContext respects maxChars budget.
	ctxText, err := r.RetrieveContext(context.Background(), []string{"internal/auth/token.go"}, 140)
	if err != nil {
		t.Fatalf("RetrieveContext failed: %v", err)
	}
	if len(ctxText) == 0 || len(ctxText) > 140 {
		t.Fatalf("expected non-empty context within 140 chars, got len=%d:\n%s", len(ctxText), ctxText)
	}
}
