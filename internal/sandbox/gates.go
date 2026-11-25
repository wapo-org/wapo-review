package sandbox

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type Ecosystems struct {
	Node   bool
	NPM    bool
	PNPM   bool
	Yarn   bool
	Go     bool
	Python bool
	Pytest bool
	Rust   bool
	Java   bool
	Gradle bool
	Maven  bool
}

func DetectEcosystems(files []string) Ecosystems {
	var e Ecosystems
	for _, raw := range files {
		f := strings.TrimSpace(raw)
		if f == "" {
			continue
		}
		base := f
		if idx := strings.LastIndex(f, "/"); idx >= 0 {
			base = f[idx+1:]
		}
		switch {
		case base == "package.json":
			e.Node = true
		case base == "package-lock.json":
			e.NPM = true
		case base == "pnpm-lock.yaml":
			e.PNPM = true
		case base == "yarn.lock":
			e.Yarn = true
		case base == "go.mod":
			e.Go = true
		case base == "pyproject.toml" || base == "requirements.txt" || strings.HasSuffix(base, ".py"):
			e.Python = true
			if strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py") {
				e.Pytest = true
			}
		case base == "Cargo.toml":
			e.Rust = true
		case strings.HasPrefix(base, "build.gradle"):
			e.Java = true
			e.Gradle = true
		case base == "pom.xml":
			e.Java = true
			e.Maven = true
		}
	}
	return e
}

type GateSpec struct {
	ID             string
	Command        []string
	Timeout        time.Duration
	MaxOutputBytes int
}

type GateResult struct {
	ID         string
	Status     string // "passed", "failed", "error", "skipped"
	ExitCode   *int
	Duration   time.Duration
	OutputTail string
	Error      string
}

func (g GateResult) String() string { return fmt.Sprintf("%s: %s", g.ID, g.Status) }

// NormalizeDepInstallOutput strips noisy CLI help/usage boilerplate (such as
// `npm error Usage:` / `npm error Clean install a project` / `npm notice`) and
// caps the remaining diagnostic tail to maxChars so mid-stack PR install
// failures produce concise, actionable gate summaries.
func NormalizeDepInstallOutput(raw string, maxChars int) string {
	if maxChars <= 0 {
		maxChars = 4000
	}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	clean := make([]string, 0, len(lines))
	skipUsage := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "npm error Usage:") ||
			strings.HasPrefix(trimmed, "npm error Clean install a project") ||
			strings.HasPrefix(trimmed, "Usage: npm ci") {
			skipUsage = true
			continue
		}
		if skipUsage {
			if strings.HasPrefix(trimmed, "npm error A complete log") {
				skipUsage = false
			}
			continue
		}
		if strings.HasPrefix(trimmed, "npm notice") {
			continue
		}
		if trimmed == "" && len(clean) > 0 && clean[len(clean)-1] == "" {
			continue
		}
		clean = append(clean, line)
	}
	joined := strings.TrimSpace(strings.Join(clean, "\n"))
	if len(joined) > maxChars {
		joined = "...[truncated]\n" + joined[len(joined)-maxChars:]
	}
	return joined
}

// InstallDependencies detects the repository ecosystem and runs a lockfile-
// safe dependency installation inside the sandbox. Failures are returned as a
// structured failed GateResult (with err == nil) so downstream static analysis,
// profiling, and LLM code review continue uninterrupted.
func InstallDependencies(ctx context.Context, c Container) (*GateResult, error) {
	files, err := ListFiles(ctx, c, "")
	if err != nil {
		return nil, err
	}
	eco := DetectEcosystems(strings.Split(files.Stdout, "\n"))
	if !hasWorkspaceFile(files.Stdout, "requirements.txt") {
		eco.Python = false
	}
	return InstallDependenciesWithCommand(ctx, c, selectInstallCommand(eco))
}

func hasWorkspaceFile(files, name string) bool {
	for _, file := range strings.Split(files, "\n") {
		if strings.TrimSpace(file) == name {
			return true
		}
	}
	return false
}

func selectInstallCommand(eco Ecosystems) []string {
	switch {
	case eco.PNPM:
		return []string{"pnpm", "install", "--frozen-lockfile", "--ignore-scripts"}
	case eco.NPM:
		return []string{"npm", "ci", "--ignore-scripts"}
	case eco.Yarn:
		return []string{"yarn", "install", "--immutable"}
	case eco.Go:
		return []string{"go", "mod", "download"}
	case eco.Rust:
		return []string{"cargo", "fetch"}
	case eco.Python:
		return []string{"python3", "-m", "pip", "install", "--no-deps", "-r", "requirements.txt"}
	default:
		return nil
	}
}

// InstallDependenciesWithCommand executes the given install command and returns
// nil GateResult on success or a clean failed GateResult on non-zero exit.
func InstallDependenciesWithCommand(ctx context.Context, c Container, cmd []string) (*GateResult, error) {
	if len(cmd) == 0 {
		return nil, nil
	}
	st := time.Now()
	r, err := c.Exec(ctx, ExecOpts{
		Command:        cmd,
		Dir:            workspaceDir(c),
		Timeout:        10 * time.Minute,
		MaxOutputBytes: 200_000,
	})
	if err != nil {
		return &GateResult{
			ID:       "install_dependencies",
			Status:   "error",
			Duration: time.Since(st),
			Error:    err.Error(),
		}, nil
	}
	if r.ExitCode == 0 {
		return nil, nil
	}
	code := r.ExitCode
	combined := strings.TrimSpace(r.Stdout + "\n" + r.Stderr)
	return &GateResult{
		ID:         "install_dependencies",
		Status:     "failed",
		ExitCode:   &code,
		Duration:   time.Since(st),
		OutputTail: NormalizeDepInstallOutput(combined, 4000),
		Error:      fmt.Sprintf("dependency installation failed (exit %d)", code),
	}, nil
}

// RunGates runs every GateSpec independently; a failure or error in one gate
// never stops subsequent gates from running.
func RunGates(ctx context.Context, c Container, specs []GateSpec) []GateResult {
	out := make([]GateResult, 0, len(specs))
	ws := workspaceDir(c)
	for _, s := range specs {
		st := time.Now()
		r, err := c.Exec(ctx, ExecOpts{
			Command:        s.Command,
			Dir:            ws,
			Timeout:        s.Timeout,
			MaxOutputBytes: s.MaxOutputBytes,
		})
		g := GateResult{ID: s.ID, Duration: time.Since(st)}
		if err != nil {
			g.Status = "error"
			g.Error = err.Error()
		} else {
			code := r.ExitCode
			g.ExitCode = &code
			g.OutputTail = strings.TrimSpace(r.Stdout + "\n" + r.Stderr)
			if code == 0 {
				g.Status = "passed"
			} else {
				g.Status = "failed"
			}
		}
		out = append(out, g)
	}
	return out
}
