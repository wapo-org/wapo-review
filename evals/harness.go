package evals

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/wapo-org/wapo-review/internal/analyzer"
	"github.com/wapo-org/wapo-review/internal/consolidator"
	"github.com/wapo-org/wapo-review/internal/graph"
	"github.com/wapo-org/wapo-review/internal/sharder"
)

type corpus struct {
	CorpusID string       `json:"corpus_id"`
	Cases    []corpusCase `json:"cases"`
}
type corpusCase struct {
	CaseID   string            `json:"case_id"`
	Language string            `json:"language"`
	Clean    bool              `json:"is_clean"`
	Files    map[string]string `json:"files"`
	Expected []bug             `json:"expected_bugs"`
}
type bug struct {
	File      string   `json:"file"`
	LineRange []int    `json:"line_range"`
	Rules     []string `json:"rule_ids"`
}
type LogicRegressionReport struct {
	Cases               int `json:"cases"`
	TP                  int `json:"tp"`
	FP                  int `json:"fp"`
	FN                  int `json:"fn"`
	CleanFalsePositives int `json:"clean_false_positives"`
}
type CorpusReport struct {
	CorpusID  string             `json:"corpus_id"`
	Cases     int                `json:"cases"`
	Languages map[string]Metrics `json:"languages"`
	Overall   Metrics            `json:"overall"`
}
type ParityFile struct {
	File     string  `json:"file"`
	Expected float64 `json:"expected"`
	Actual   float64 `json:"actual"`
	Delta    float64 `json:"delta"`
}
type SonarParityReport struct {
	PearsonR         float64      `json:"pearson_r"`
	MAE              float64      `json:"mae"`
	Files            []ParityFile `json:"files"`
	SnapshotExpected *float64     `json:"snapshot_expected,omitempty"`
	SnapshotActual   *float64     `json:"snapshot_actual,omitempty"`
}
type GoldenReport struct {
	Cases      int  `json:"cases"`
	Findings   int  `json:"findings"`
	Repeatable bool `json:"repeatable"`
}

func loadCorpus(path string) (corpus, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return corpus{}, e
	}
	var c corpus
	e = json.Unmarshal(b, &c)
	return c, e
}
func inputFiles(files map[string]string) map[string][]byte {
	out := map[string][]byte{}
	for p, s := range files {
		out[p] = []byte(s)
	}
	return out
}
func analyze(files map[string]string) []analyzer.Finding {
	in := inputFiles(files)
	return analyzer.RunAll(context.Background(), analyzer.RunInput{Files: in, Config: analyzer.RepoConfig{}})
}
func matches(f analyzer.Finding, b bug) bool {
	if f.File != b.File {
		return false
	}
	if len(b.Rules) > 0 {
		for _, r := range b.Rules {
			if r == f.RuleID {
				return true
			}
		}
		return false
	}
	if len(b.LineRange) == 2 {
		return f.StartLine <= b.LineRange[1]+3 && f.EndLine >= b.LineRange[0]-3
	}
	return true
}
func scoreCases(cases []corpusCase) Metrics {
	var m Metrics
	tn := 0
	for _, c := range cases {
		fs := analyze(c.Files)
		used := make([]bool, len(fs))
		for _, b := range c.Expected {
			found := -1
			for i, f := range fs {
				if !used[i] && matches(f, b) {
					found = i
					break
				}
			}
			if found >= 0 {
				used[found] = true
				m.TP++
			} else {
				m.FN++
			}
		}
		for i := range fs {
			if !used[i] {
				m.FP++
			}
		}
		if len(c.Expected) == 0 && len(fs) == 0 {
			tn++
		}
	}
	m.Precision = Precision(m.TP, m.FP)
	m.Recall = Recall(m.TP, m.FN)
	m.F1 = F1(m.Precision, m.Recall)
	m.FalsePositiveRate = FalsePositiveRate(m.FP, tn)
	return m
}
func RunLogicRegression(path string) (LogicRegressionReport, error) {
	c, e := loadCorpus(path)
	if e != nil {
		return LogicRegressionReport{}, e
	}
	r := LogicRegressionReport{Cases: len(c.Cases)}
	for _, tc := range c.Cases {
		fs := analyze(tc.Files)
		used := make([]bool, len(fs))
		for _, b := range tc.Expected {
			hit := -1
			for i, f := range fs {
				if !used[i] && matches(f, b) {
					hit = i
					break
				}
			}
			if hit >= 0 {
				used[hit] = true
				r.TP++
			} else {
				r.FN++
			}
		}
		for i := range fs {
			if !used[i] {
				r.FP++
				if tc.Clean {
					r.CleanFalsePositives++
				}
			}
		}
	}
	return r, nil
}
func RunMultilingualCorpus(path string) (CorpusReport, error) {
	c, e := loadCorpus(path)
	if e != nil {
		return CorpusReport{}, e
	}
	r := CorpusReport{CorpusID: c.CorpusID, Cases: len(c.Cases), Languages: map[string]Metrics{}}
	tn := map[string]int{}
	for _, tc := range c.Cases {
		m := scoreCases([]corpusCase{tc})
		old := r.Languages[tc.Language]
		old.TP += m.TP
		old.FP += m.FP
		old.FN += m.FN
		if tc.Clean && m.FP == 0 {
			tn[tc.Language]++
		}
		r.Languages[tc.Language] = old
	}
	for k, m := range r.Languages {
		m.Precision = Precision(m.TP, m.FP)
		m.Recall = Recall(m.TP, m.FN)
		m.F1 = F1(m.Precision, m.Recall)
		m.FalsePositiveRate = FalsePositiveRate(m.FP, tn[k])
		r.Languages[k] = m
		r.Overall.TP += m.TP
		r.Overall.FP += m.FP
		r.Overall.FN += m.FN
	}
	r.Overall.Precision = Precision(r.Overall.TP, r.Overall.FP)
	r.Overall.Recall = Recall(r.Overall.TP, r.Overall.FN)
	r.Overall.F1 = F1(r.Overall.Precision, r.Overall.Recall)
	var totalTN int
	for _, n := range tn {
		totalTN += n
	}
	r.Overall.FalsePositiveRate = FalsePositiveRate(r.Overall.FP, totalTN)
	return r, nil
}
func RunSonarParity(baselinesDir, fixturesDir string) (SonarParityReport, error) {
	snaps, err := filepath.Glob(filepath.Join(baselinesDir, "*sonarcloud_snapshot.json"))
	if err != nil || len(snaps) == 0 {
		return SonarParityReport{}, fmt.Errorf("no sonarcloud snapshot baseline found in %s", baselinesDir)
	}
	b, err := os.ReadFile(snaps[0])
	if err != nil {
		return SonarParityReport{}, err
	}
	var snap struct {
		Files []struct {
			Path                string `json:"path"`
			Language            string `json:"language"`
			CognitiveComplexity int    `json:"cognitive_complexity"`
		} `json:"files"`
	}
	if err := json.Unmarshal(b, &snap); err != nil {
		return SonarParityReport{}, err
	}

	// Pick first TS file in the snapshot to locate a matching local checkout.
	probeRel := ""
	for _, f := range snap.Files {
		if f.Language == "ts" && f.Path != "" {
			probeRel = filepath.FromSlash(f.Path)
			break
		}
	}

	repoRoot := os.Getenv("WAPO_SONAR_PARITY_REPO")
	if repoRoot == "" && probeRel != "" {
		candidates := []string{fixturesDir}
		if entries, err := os.ReadDir(filepath.Join("..", "..")); err == nil {
			for _, ent := range entries {
				if ent.IsDir() {
					candidates = append(candidates, filepath.Join("..", "..", ent.Name()))
				}
			}
		}
		for _, candidate := range candidates {
			if _, err := os.Stat(filepath.Join(candidate, probeRel)); err == nil {
				repoRoot = candidate
				break
			}
		}
	}
	if repoRoot == "" {
		return SonarParityReport{}, fmt.Errorf("sonar parity fixture repository not found (set WAPO_SONAR_PARITY_REPO)")
	}

	var report SonarParityReport
	var expectedVec, actualVec []float64
	var absErrSum float64
	for _, f := range snap.Files {
		if f.Language != "ts" && f.Language != "js" && f.Language != "py" {
			continue
		}
		if f.CognitiveComplexity <= 0 {
			continue
		}
		fullPath := filepath.Join(repoRoot, filepath.FromSlash(f.Path))
		src, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		fns, err := analyzer.CognitiveComplexities(f.Path, src)
		if err != nil {
			continue
		}
		actual := 0
		for _, fn := range fns {
			actual += fn.Score
		}
		exp := float64(f.CognitiveComplexity)
		act := float64(actual)
		delta := act - exp
		if delta < 0 {
			absErrSum += -delta
		} else {
			absErrSum += delta
		}
		expectedVec = append(expectedVec, exp)
		actualVec = append(actualVec, act)
		report.Files = append(report.Files, ParityFile{
			File:     f.Path,
			Expected: exp,
			Actual:   act,
			Delta:    delta,
		})
		if strings.HasSuffix(f.Path, "snapshot.ts") {
			eCopy, aCopy := exp, act
			report.SnapshotExpected = &eCopy
			report.SnapshotActual = &aCopy
		}
		if len(report.Files) >= 35 {
			break
		}
	}
	if len(report.Files) < 10 {
		return report, fmt.Errorf("too few matched SonarCloud files: %d", len(report.Files))
	}
	report.PearsonR = PearsonR(expectedVec, actualVec)
	report.MAE = absErrSum / float64(len(report.Files))
	return report, nil
}
func RunGoldenCases(dir string) (GoldenReport, error) {
	paths, e := filepath.Glob(filepath.Join(dir, "*.json"))
	if e != nil {
		return GoldenReport{}, e
	}
	sort.Strings(paths)
	r := GoldenReport{Cases: len(paths), Repeatable: true}
	if len(paths) != 10 {
		return r, fmt.Errorf("expected 10 golden cases, got %d", len(paths))
	}
	for _, p := range paths {
		var raw struct {
			Name     string            `json:"name"`
			Files    map[string]string `json:"files"`
			Expected []struct {
				Rule string `json:"rule_id"`
				File string `json:"file"`
			} `json:"expected"`
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return r, e
		}
		if e = json.Unmarshal(b, &raw); e != nil {
			return r, e
		}
		if raw.Name == "" || raw.Files == nil {
			return r, fmt.Errorf("invalid golden case %s", p)
		}
		a := analyze(raw.Files)
		b2 := analyze(raw.Files)
		if fmt.Sprint(a) != fmt.Sprint(b2) {
			r.Repeatable = false
		}
		r.Findings += len(a)
		idx := graph.NewCodebaseIndex(inputFiles(raw.Files), "eval", "eval", "eval")
		shards := sharder.ShardFiles([]sharder.PRFile{{Path: "eval.go", Patch: "@@ -0,0 +1 @@\n+x"}}, idx, 100)
		if len(shards) != 1 {
			return r, fmt.Errorf("sharder invariant failed")
		}
		_ = consolidator.Consolidate(nil, a, nil)
	}
	return r, nil
}
func hasSnapshotTS(fs []ParityFile) bool {
	for _, f := range fs {
		if strings.HasSuffix(f.File, "snapshot.ts") {
			return true
		}
	}
	return false
}
