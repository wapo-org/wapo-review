package semantic

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"

	"github.com/wapo-org/wapo-review/internal/ast"
	"github.com/wapo-org/wapo-review/internal/graph"
)

type Embedder interface {
	Embed(context.Context, []string) ([][]float32, error)
}

type Result struct {
	Chunk ast.CodeChunk
	Score float64
}

type Retriever struct {
	Index    *graph.CodebaseIndex
	Embedder Embedder
	Chunks   []ast.CodeChunk

	docFreq  map[string]int
	docTerms []map[string]int
	docLen   []int
	avgDL    float64
}

func (r *Retriever) IndexFiles(files map[string][]byte) {
	r.Chunks = nil
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		f, err := ast.ExtractFileFacts(p, files[p])
		if err == nil {
			r.Chunks = append(r.Chunks, f.Chunks...)
		}
	}
	r.rebuildBM25()
}

func (r *Retriever) rebuildBM25() {
	r.docFreq = map[string]int{}
	r.docTerms = make([]map[string]int, len(r.Chunks))
	r.docLen = make([]int, len(r.Chunks))
	totalLen := 0
	for i, c := range r.Chunks {
		tf := tokenCounts(c.File + " " + c.Symbol + " " + c.Text)
		r.docTerms[i] = tf
		dl := 0
		for tok, cnt := range tf {
			dl += cnt
			r.docFreq[tok]++
		}
		r.docLen[i] = dl
		totalLen += dl
	}
	if len(r.Chunks) > 0 {
		r.avgDL = float64(totalLen) / float64(len(r.Chunks))
	} else {
		r.avgDL = 1
	}
	if r.avgDL < 1 {
		r.avgDL = 1
	}
}

// Search combines BM25 lexical scoring with code-graph proximity (seed file,
// callers, callees, importers).
func (r *Retriever) Search(query string, seeds []string, topK int) []Result {
	if len(r.Chunks) == 0 {
		return nil
	}
	if len(r.docTerms) != len(r.Chunks) {
		r.rebuildBM25()
	}
	qTokens := tokenCounts(query)
	seedSet := make(map[string]bool, len(seeds))
	for _, s := range seeds {
		seedSet[s] = true
	}

	const (
		k1 = 1.5
		b  = 0.75
	)
	N := float64(len(r.Chunks))
	out := make([]Result, 0, len(r.Chunks))

	for i, c := range r.Chunks {
		tf := r.docTerms[i]
		dl := float64(r.docLen[i])
		score := 0.0
		for tok := range qTokens {
			f := float64(tf[tok])
			if f == 0 {
				continue
			}
			df := float64(r.docFreq[tok])
			idf := math.Log(1.0 + (N-df+0.5)/(df+0.5))
			score += idf * (f * (k1 + 1.0)) / (f + k1*(1.0-b+b*(dl/r.avgDL)))
		}
		if seedSet[c.File] {
			score += 2.0
		}
		if r.Index != nil {
			for _, p := range r.Index.CalleesOf(c.File) {
				if seedSet[p] {
					score += 1.0
				}
			}
			for _, p := range r.Index.CallersOf(c.File) {
				if seedSet[p] {
					score += 1.0
				}
			}
			for _, p := range r.Index.ImportersOf(c.File) {
				if seedSet[p] {
					score += 0.75
				}
			}
		}
		if score > 0 {
			out = append(out, Result{Chunk: c, Score: score})
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if topK > 0 && len(out) > topK {
		out = out[:topK]
	}
	return out
}

// SearchWithEmbeddings runs hybrid BM25+graph search and, when Embedder is
// configured, reranks top candidates using cosine similarity.
func (r *Retriever) SearchWithEmbeddings(ctx context.Context, query string, seeds []string, topK int) ([]Result, error) {
	candLimit := topK * 4
	if candLimit < 20 {
		candLimit = 20
	}
	cands := r.Search(query, seeds, candLimit)
	if len(cands) == 0 || r.Embedder == nil {
		if topK > 0 && len(cands) > topK {
			cands = cands[:topK]
		}
		return cands, nil
	}
	texts := make([]string, 0, len(cands)+1)
	texts = append(texts, query)
	for _, c := range cands {
		texts = append(texts, c.Chunk.File+"\n"+c.Chunk.Symbol+"\n"+c.Chunk.Text)
	}
	vecs, err := r.Embedder.Embed(ctx, texts)
	if err != nil || len(vecs) != len(texts) {
		if topK > 0 && len(cands) > topK {
			cands = cands[:topK]
		}
		return cands, err
	}
	qVec := vecs[0]
	for i := range cands {
		sim := cosineSimilarity(qVec, vecs[i+1])
		if sim > 0 {
			cands[i].Score += 3.0 * sim
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].Score > cands[j].Score })
	if topK > 0 && len(cands) > topK {
		cands = cands[:topK]
	}
	return cands, nil
}

func (r *Retriever) RetrieveContext(ctx context.Context, changed []string, maxChars int) (string, error) {
	if maxChars <= 0 {
		maxChars = 12000
	}
	query := strings.Join(changed, " ")
	results, _ := r.SearchWithEmbeddings(ctx, query, changed, 30)
	var b strings.Builder
	for _, x := range results {
		entry := fmt.Sprintf("// %s:%d-%d (%s)\n%s\n\n", x.Chunk.File, x.Chunk.StartLine, x.Chunk.EndLine, x.Chunk.Symbol, strings.TrimSpace(x.Chunk.Text))
		if b.Len()+len(entry) > maxChars {
			break
		}
		b.WriteString(entry)
	}
	return strings.TrimSpace(b.String()), nil
}

func cosineSimilarity(a, b []float32) float64 {
	if len(a) == 0 || len(a) != len(b) {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		fa, fb := float64(a[i]), float64(b[i])
		dot += fa * fb
		normA += fa * fa
		normB += fb * fb
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

func tokenCounts(s string) map[string]int {
	out := map[string]int{}
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out[strings.ToLower(b.String())]++
			b.Reset()
		}
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if unicode.IsUpper(r) && b.Len() > 0 {
				flush()
			}
			b.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}
