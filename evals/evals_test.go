package evals

import (
	"path/filepath"
	"testing"
)

func TestLogicRegressionZeroFP(t *testing.T) {
	r, e := RunLogicRegression(filepath.Join("corpora", "logic_regression_v1.json"))
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("logic regression TP=%d FP=%d FN=%d", r.TP, r.FP, r.FN)
	if r.FP != 0 || r.CleanFalsePositives != 0 || r.TP == 0 {
		t.Fatalf("logic regression failed: %+v", r)
	}
}
func TestSonarCognitiveComplexityParity(t *testing.T) {
	r, e := RunSonarParity(filepath.Join("baselines"), filepath.Join("fixtures"))
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("Sonar parity r=%.6f MAE=%.6f files=%+v", r.PearsonR, r.MAE, r.Files)
	if r.PearsonR < .98 {
		t.Fatalf("Pearson r %.6f < .98", r.PearsonR)
	}
	if hasSnapshotTS(r.Files) && (r.SnapshotExpected == nil || r.SnapshotActual == nil || *r.SnapshotExpected != *r.SnapshotActual) {
		t.Fatal("snapshot.ts score differs from baseline")
	}
}
func TestMultilingualCorpusEval(t *testing.T) {
	r, e := RunMultilingualCorpus(filepath.Join("corpora", "multilingual_v1.json"))
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("multilingual metrics %+v", r)
	if r.Overall.Recall <= 0 || r.Overall.FalsePositiveRate > 0.5 {
		t.Fatalf("multilingual metrics outside bounds: %+v", r.Overall)
	}
}
func TestGoldenCasesAndMetrics(t *testing.T) {
	r, e := RunGoldenCases(filepath.Join("cases"))
	if e != nil {
		t.Fatal(e)
	}
	if r.Cases != 10 || !r.Repeatable {
		t.Fatalf("golden cases failed: %+v", r)
	}
	if PearsonR([]float64{1, 2, 3}, []float64{2, 4, 6}) != 1 || Precision(2, 1) != 2.0/3.0 || Recall(2, 1) != 2.0/3.0 || F1(1, 1) != 1 {
		t.Fatal("metric calculation failed")
	}
}
