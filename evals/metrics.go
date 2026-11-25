package evals

import (
	"encoding/json"
	"math"
)

type Metrics struct {
	TP                 int     `json:"tp"`
	FP                 int     `json:"fp"`
	FN                 int     `json:"fn"`
	Precision          float64 `json:"precision"`
	Recall             float64 `json:"recall"`
	F1                 float64 `json:"f1"`
	FalsePositiveRate  float64 `json:"false_positive_rate"`
	FileLevelRecall    float64 `json:"file_level_recall"`
	LineAnchorAccuracy float64 `json:"line_anchor_accuracy"`
	PearsonR           float64 `json:"pearson_r"`
	MAE                float64 `json:"mae"`
	ExactMatchRate     float64 `json:"exact_match_rate"`
}
type BenchmarkReport struct {
	SchemaVersion string  `json:"schema_version"`
	CorpusID      string  `json:"corpus_id,omitempty"`
	Metrics       Metrics `json:"metrics"`
	Details       any     `json:"details,omitempty"`
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}
func Precision(tp, fp int) float64 { return ratio(tp, tp+fp) }
func Recall(tp, fn int) float64    { return ratio(tp, tp+fn) }
func F1(p, r float64) float64 {
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}
func FalsePositiveRate(fp, tn int) float64        { return ratio(fp, fp+tn) }
func FileLevelRecall(hit, total int) float64      { return ratio(hit, total) }
func LineAnchorAccuracy(exact, total int) float64 { return ratio(exact, total) }
func PearsonR(xs, ys []float64) float64 {
	if len(xs) != len(ys) || len(xs) < 2 {
		return 0
	}
	var mx, my float64
	for i := range xs {
		mx += xs[i]
		my += ys[i]
	}
	mx /= float64(len(xs))
	my /= float64(len(ys))
	var cov, vx, vy float64
	for i := range xs {
		dx, dy := xs[i]-mx, ys[i]-my
		cov += dx * dy
		vx += dx * dx
		vy += dy * dy
	}
	if vx == 0 || vy == 0 {
		return 0
	}
	return cov / math.Sqrt(vx*vy)
}
func MAE(xs, ys []float64) float64 {
	if len(xs) == 0 || len(xs) != len(ys) {
		return 0
	}
	var sum float64
	for i := range xs {
		sum += math.Abs(xs[i] - ys[i])
	}
	return sum / float64(len(xs))
}
func ExactMatchRate(xs, ys []float64) float64 {
	if len(xs) == 0 || len(xs) != len(ys) {
		return 0
	}
	n := 0
	for i := range xs {
		if xs[i] == ys[i] {
			n++
		}
	}
	return float64(n) / float64(len(xs))
}
func (r BenchmarkReport) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }
