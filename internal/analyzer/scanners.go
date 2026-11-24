package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Finding struct {
	RuleID      string
	Category    string
	Severity    string
	File        string
	StartLine   int
	EndLine     int
	Message     string
	Evidence    string
	Fingerprint string
	NewCode     bool
	RepoWide    bool
}

type RunInput struct {
	Files     map[string][]byte
	BaseFiles map[string][]byte
	Diff      Diff
	Config    RepoConfig
}

func newFinding(rule, cat, sev, file string, start, end int, msg, evidence string) Finding {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s", rule, file, start, evidence)))
	return Finding{
		RuleID:      rule,
		Category:    cat,
		Severity:    sev,
		File:        file,
		StartLine:   start,
		EndLine:     end,
		Message:     msg,
		Evidence:    evidence,
		Fingerprint: fmt.Sprintf("%x", h[:12]),
	}
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{30,}`),
	regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(api[_-]?key|secret|token)\s*[:=]\s*["']([A-Za-z0-9_\-/+=]{20,})["']`),
}

var envVarNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{3,}$`)

func isEnvVarConstantLine(line string) bool {
	re := secretPatterns[3]
	if m := re.FindStringSubmatch(line); len(m) >= 3 && envVarNameRe.MatchString(m[2]) {
		return true
	}
	return false
}

var placeholderTokens = []string{"example", "placeholder", "changeme", "dummy", "your_", "xxxx", "fake_", "test_"}

func isPlaceholderLine(line string) bool {
	l := strings.ToLower(line)
	for _, p := range placeholderTokens {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func isTestPath(path string) bool {
	low := "/" + strings.Trim(filepath.ToSlash(strings.ToLower(path)), "/") + "/"
	base := filepath.Base(low)
	return strings.HasSuffix(base, "_test.go") || strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") ||
		strings.Contains(low, "/tests/") || strings.Contains(low, "/__tests__/") || strings.Contains(low, "/fixtures/") || strings.Contains(low, "/testdata/")
}

func secretCandidates(line string, pattern *regexp.Regexp) []string {
	if pattern == secretPatterns[3] {
		matches := pattern.FindAllStringSubmatch(line, -1)
		values := make([]string, 0, len(matches))
		for _, match := range matches {
			if len(match) > 2 {
				values = append(values, match[2])
			}
		}
		return values
	}
	return pattern.FindAllString(line, -1)
}

func ScanFile(path string, src []byte) []Finding {
	low := strings.ToLower(path)
	if isTestPath(path) {
		return nil
	}
	var out []Finding
	lines := strings.Split(string(src), "\n")
	isWorkflow := strings.Contains(low, ".github/workflows/")
	isDockerfile := strings.HasPrefix(strings.ToLower(filepath.Base(path)), "dockerfile")
	isContainerConfig := isDockerfile || strings.Contains(low, "docker-compose") || strings.Contains(low, "k8s/") || strings.Contains(low, "kubernetes/")
	isShell := strings.HasSuffix(low, ".sh") || strings.HasSuffix(low, ".bash") || strings.Contains(low, ".github/workflows/") || isDockerfile
	isIAM := strings.HasSuffix(low, ".json") || strings.HasSuffix(low, ".yaml") || strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".tf") || strings.Contains(low, "iam")
	isPackageJSON := strings.EqualFold(filepath.Base(path), "package.json")

	for i, line := range lines {
		for _, p := range secretPatterns {
			for _, candidate := range secretCandidates(line, p) {
				if isPlaceholderLine(candidate) || (p == secretPatterns[3] && envVarNameRe.MatchString(candidate)) {
					continue
				}
				if candidate != "" {
					out = append(out, newFinding("SECURITY.secret", "security", "critical", path, i+1, i+1, "Possible credential exposed", "[redacted]"))
					break
				}
			}
			if len(out) > 0 && out[len(out)-1].StartLine == i+1 && out[len(out)-1].RuleID == "SECURITY.secret" {
				break
			}
		}
		l := strings.ToLower(strings.TrimSpace(line))
		if isWorkflow || strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".yaml") {
			if strings.Contains(l, "pull_request_target") {
				out = append(out, newFinding("CI.pull-request-target", "ci", "high", path, i+1, i+1, "Privileged pull_request_target workflow trigger", "pull_request_target"))
			}
			if strings.HasPrefix(l, "uses:") || strings.Contains(l, " uses:") {
				if strings.HasSuffix(l, "@main") || strings.HasSuffix(l, "@master") {
					out = append(out, newFinding("CI.unpinned-action", "ci", "medium", path, i+1, i+1, "GitHub Action is not pinned to a release tag or commit SHA", strings.TrimSpace(line)))
				}
			}
		}
		if isContainerConfig {
			if strings.HasPrefix(l, "user root") || strings.Contains(l, "user root") {
				out = append(out, newFinding("CONTAINER.root-user", "security", "high", path, i+1, i+1, "Container runs as root user", strings.TrimSpace(line)))
			}
		}
		if isShell && strings.Contains(l, "curl") && (strings.Contains(l, "| sh") || strings.Contains(l, "| bash")) {
			out = append(out, newFinding("CONTAINER.curl-pipe-shell", "security", "high", path, i+1, i+1, "Downloads and pipes remote script directly into shell", strings.TrimSpace(line)))
		}
		if isIAM && strings.Contains(l, `"action"`) && strings.Contains(l, `"*"`) {
			out = append(out, newFinding("IAC.wildcard-iam", "security", "high", path, i+1, i+1, "Overly permissive wildcard IAM action", strings.TrimSpace(line)))
		}
	}

	if isPackageJSON {
		out = append(out, scanPackageJSON(path, src)...)
	}
	return out
}

func scanPackageJSON(path string, src []byte) []Finding {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
		Scripts         map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(src, &pkg); err != nil {
		return nil
	}
	var out []Finding
	checkDeps := func(deps map[string]string) {
		names := make([]string, 0, len(deps))
		for k := range deps {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			ver := strings.TrimSpace(deps[name])
			if ver == "*" || strings.EqualFold(ver, "latest") {
				out = append(out, newFinding(
					"SUPPLYCHAIN.unpinned-dependency",
					"supply-chain",
					"high",
					path,
					1,
					1,
					fmt.Sprintf("Dependency %q uses unpinned version %q", name, ver),
					name+"@"+ver,
				))
			}
		}
	}
	checkDeps(pkg.Dependencies)
	checkDeps(pkg.DevDependencies)
	for _, hook := range []string{"preinstall", "install", "postinstall"} {
		script := strings.ToLower(pkg.Scripts[hook])
		if script != "" && (strings.Contains(script, "curl ") || strings.Contains(script, "wget ") || strings.Contains(script, "bash -c")) {
			out = append(out, newFinding(
				"SUPPLYCHAIN.suspicious-install-script",
				"supply-chain",
				"high",
				path,
				1,
				1,
				fmt.Sprintf("Lifecycle script %q executes remote or shell command", hook),
				hook+": "+pkg.Scripts[hook],
			))
		}
	}
	return out
}

func isTestOrFixturePath(path string) bool {
	low := strings.ToLower(filepath.ToSlash(path))
	base := filepath.Base(low)
	return strings.Contains(base, ".test.") ||
		strings.Contains(base, ".spec.") ||
		strings.HasSuffix(base, "_test.go") ||
		strings.HasPrefix(base, "test_") ||
		strings.HasSuffix(base, "_test.py") ||
		strings.Contains(low, "/tests/") ||
		strings.Contains(low, "/__tests__/") ||
		strings.Contains(base, "fixture")
}

// DetectClones finds exact normalized duplicate code blocks (>= windowSize
// non-trivial lines) across production source files (skipping test/fixture boilerplate).
func DetectClones(files map[string][]byte, windowSize int) []Finding {
	if windowSize < 5 {
		windowSize = 6
	}
	type loc struct {
		file string
		line int
	}
	seen := map[string]loc{}
	var out []Finding

	paths := make([]string, 0, len(files))
	for p := range files {
		if isTestOrFixturePath(p) {
			continue
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		rawLines := strings.Split(string(files[p]), "\n")
		type normLine struct {
			origLine int
			text     string
		}
		var norm []normLine
		for i, l := range rawLines {
			t := strings.TrimSpace(l)
			if t == "" || strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || t == "{" || t == "}" {
				continue
			}
			norm = append(norm, normLine{origLine: i + 1, text: t})
		}
		if len(norm) < windowSize {
			continue
		}
		reported := false
		for i := 0; i <= len(norm)-windowSize; i++ {
			var b strings.Builder
			for j := 0; j < windowSize; j++ {
				b.WriteString(norm[i+j].text)
				b.WriteByte('\n')
			}
			block := b.String()
			if len(block) < 120 {
				continue
			}
			h := fmt.Sprintf("%x", sha256.Sum256([]byte(block)))
			if prev, exists := seen[h]; exists {
				if (prev.file != p || norm[i].origLine > prev.line+windowSize) && !reported {
					out = append(out, newFinding(
						"CLONE.duplicate-block",
						"maintainability",
						"medium",
						p,
						norm[i].origLine,
						norm[i+windowSize-1].origLine,
						fmt.Sprintf("Duplicate code block matches %s:%d", prev.file, prev.line),
						fmt.Sprintf("%s:%d", prev.file, prev.line),
					))
					reported = true
				}
			} else {
				seen[h] = loc{file: p, line: norm[i].origLine}
			}
		}
	}
	return out
}

func applyRuleConfig(f Finding, cfg RepoConfig) (Finding, bool) {
	rc, ok := cfg.Rules[f.RuleID]
	if !ok {
		return f, true
	}
	if rc.Enabled != nil && !*rc.Enabled {
		return f, false
	}
	if strings.TrimSpace(rc.Severity) != "" {
		f.Severity = strings.ToLower(strings.TrimSpace(rc.Severity))
	}
	return f, true
}

func RunAll(ctx context.Context, in RunInput) []Finding {
	var out []Finding
	includedFiles := make(map[string][]byte, len(in.Files))

	paths := make([]string, 0, len(in.Files))
	for p := range in.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		if ctx.Err() != nil {
			break
		}
		if in.Config.Excluded(path) {
			continue
		}
		src := in.Files[path]
		includedFiles[path] = src

		fs := ScanFile(path, src)
		fs = append(fs, AnalyzeLogic(path, src)...)
		_, compFindings := ComputeComplexityFindings(path, src, in.BaseFiles[path], in.Config.Complexity, in.Diff)
		fs = append(fs, compFindings...)

		for _, f := range fs {
			f, enabled := applyRuleConfig(f, in.Config)
			if !enabled {
				continue
			}
			if !f.NewCode {
				f.NewCode = in.Diff.IsNew(path, f.StartLine)
			}
			if len(in.Diff.Files) == 0 || f.NewCode || f.RepoWide {
				out = append(out, f)
			}
		}
	}

	// Cross-file duplicate block detection.
	for _, f := range DetectClones(includedFiles, 6) {
		f, enabled := applyRuleConfig(f, in.Config)
		if !enabled {
			continue
		}
		f.NewCode = in.Diff.IsNew(f.File, f.StartLine)
		if len(in.Diff.Files) == 0 || f.NewCode {
			out = append(out, f)
		}
	}

	seen := map[string]bool{}
	uniq := out[:0]
	for _, f := range out {
		if !seen[f.Fingerprint] {
			seen[f.Fingerprint] = true
			uniq = append(uniq, f)
		}
	}
	sort.Slice(uniq, func(i, j int) bool {
		if uniq[i].File != uniq[j].File {
			return uniq[i].File < uniq[j].File
		}
		if uniq[i].StartLine != uniq[j].StartLine {
			return uniq[i].StartLine < uniq[j].StartLine
		}
		return uniq[i].RuleID < uniq[j].RuleID
	})
	return uniq
}
