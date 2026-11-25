package gate

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/wapo-org/wapo-review/internal/analyzer"
	"github.com/wapo-org/wapo-review/internal/githubapp"
)

type Result struct {
	Decision   string // "passed", "failed", "neutral"
	Conditions []Condition
	Summary    string
	Findings   []analyzer.Finding
}

type Condition struct {
	Name   string
	Passed bool
	Detail string
}

type Input struct {
	Findings             []analyzer.Finding
	Complexities         []analyzer.FunctionComplexity
	MaxCritical          int
	MaxHigh              int
	MaxNewCognitive      int
	Sandbox              map[string]bool
	RequiredSandboxGates []string
}

func Evaluate(in Input) Result {
	r := Result{Decision: "passed", Findings: in.Findings}
	critical, high := 0, 0
	for _, f := range in.Findings {
		if !f.NewCode {
			continue
		}
		switch strings.ToLower(f.Severity) {
		case "critical":
			critical++
		case "high":
			high++
		}
	}

	add := func(name string, ok bool, detail string) {
		r.Conditions = append(r.Conditions, Condition{Name: name, Passed: ok, Detail: detail})
		if !ok {
			r.Decision = "failed"
		}
	}

	add("Critical findings", critical <= in.MaxCritical, fmt.Sprintf("%d / %d", critical, in.MaxCritical))
	add("High findings", high <= in.MaxHigh, fmt.Sprintf("%d / %d", high, in.MaxHigh))

	if in.MaxNewCognitive > 0 {
		maxScore := 0
		for _, fn := range in.Complexities {
			if fn.Delta > 0 && fn.Score > maxScore {
				maxScore = fn.Score
			}
		}
		add("Max new cognitive complexity", maxScore <= in.MaxNewCognitive, fmt.Sprintf("%d / %d", maxScore, in.MaxNewCognitive))
	}

	for _, g := range in.RequiredSandboxGates {
		ok, exists := in.Sandbox[g]
		if !exists {
			if r.Decision == "passed" {
				r.Decision = "neutral"
			}
			r.Conditions = append(r.Conditions, Condition{Name: g, Passed: false, Detail: "result unavailable"})
		} else {
			add(g, ok, "sandbox gate")
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## Quality Gate: %s\n\n", r.Decision)
	b.WriteString("| Condition | Status | Detail |\n| --- | --- | --- |\n")
	for _, c := range r.Conditions {
		mark := "PASS"
		if !c.Passed {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", sanitizeCell(c.Name), mark, sanitizeCell(c.Detail))
	}
	r.Summary = b.String()
	return r
}

func sanitizeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = truncateUTF8(s, 200) + "..."
	}
	return s
}

func BuildAnnotations(fs []analyzer.Finding) []githubapp.Annotation {
	out := make([]githubapp.Annotation, 0, len(fs))
	for _, f := range fs {
		p := strings.TrimPrefix(strings.TrimPrefix(f.File, "./"), "/")
		if len(p) > 255 {
			p = truncateUTF8(p, 255)
		}
		if p == "" {
			continue
		}
		s := f.StartLine
		if s < 1 {
			s = 1
		}
		e := f.EndLine
		if e < s {
			e = s
		}
		msg := f.Message
		if len(msg) > 4000 {
			msg = truncateUTF8(msg, 4000)
		}
		details := f.Evidence
		if len(details) > 4000 {
			details = truncateUTF8(details, 4000)
		}
		level := "warning"
		if strings.EqualFold(f.Severity, "critical") || strings.EqualFold(f.Severity, "high") {
			level = "failure"
		}
		out = append(out, githubapp.Annotation{
			Path:      p,
			StartLine: s,
			EndLine:   e,
			Level:     level,
			Message:   msg,
			Title:     f.RuleID,
			Details:   details,
		})
	}
	return out
}

func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func PublishGateCheckRun(ctx context.Context, c *githubapp.Client, repo, headSHA string, r Result) (int64, error) {
	conclusion := "success"
	if r.Decision == "failed" {
		conclusion = "failure"
	} else if r.Decision != "passed" {
		conclusion = "neutral"
	}
	return c.CreateCompletedCheckRun(ctx, repo, "Wapo Review", headSHA, conclusion, "Wapo Review: "+r.Decision, r.Summary, BuildAnnotations(r.Findings))
}
