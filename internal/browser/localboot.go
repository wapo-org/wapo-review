package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wapo-org/wapo-review/internal/sandbox"
)

var ErrNoLocalAppDetected = errors.New("no runnable local web or API application detected")

type LocalServiceSpec struct {
	Name       string
	Role       string // "web" or "api"
	Framework  string
	RelDir     string // relative directory inside repo ("" for repo root)
	Command    string
	Port       int
	HealthPath string
	Env        map[string]string
}

type LocalAppPlan struct {
	InstallRelDir string
	InstallCmd    string
	Primary       *LocalServiceSpec
	Companion     *LocalServiceSpec
}

type LocalBootHandle struct {
	URL       string
	Framework string
	Services  []string
	Cleanup   func(context.Context)
}

type pkgJSON struct {
	Name            string            `json:"name"`
	Workspaces      any               `json:"workspaces"`
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

var portFlagRe = regexp.MustCompile(`(?:--port|-p)\s+(\d{2,5})`)

func parsePortFromScript(script string, fallback int) int {
	if m := portFlagRe.FindStringSubmatch(script); len(m) == 2 {
		if p, err := strconv.Atoi(m[1]); err == nil && p >= 1024 && p <= 65535 {
			return p
		}
	}
	return fallback
}

func hasDep(p pkgJSON, needles ...string) bool {
	for _, n := range needles {
		if _, ok := p.Dependencies[n]; ok {
			return true
		}
		if _, ok := p.DevDependencies[n]; ok {
			return true
		}
	}
	return false
}

func detectPackageManager(dir string) (installCmd, runPrefix string) {
	if _, err := os.Stat(filepath.Join(dir, "pnpm-lock.yaml")); err == nil {
		return "pnpm install --frozen-lockfile || pnpm install", "pnpm run"
	}
	if _, err := os.Stat(filepath.Join(dir, "yarn.lock")); err == nil {
		return "yarn install --frozen-lockfile || yarn install", "yarn"
	}
	if _, err := os.Stat(filepath.Join(dir, "bun.lockb")); err == nil {
		return "bun install --frozen-lockfile || bun install", "bun run"
	}
	if _, err := os.Stat(filepath.Join(dir, "package-lock.json")); err == nil {
		return "npm ci --no-audit --no-fund || npm install --no-audit --no-fund", "npm run"
	}
	return "npm install --no-audit --no-fund", "npm run"
}

func findWorkspaceInstallRoot(repoRoot, pkgRelDir string) string {
	cur := filepath.Join(repoRoot, pkgRelDir)
	repoClean := filepath.Clean(repoRoot)
	best := pkgRelDir
	for {
		for _, lock := range []string{"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "pnpm-workspace.yaml"} {
			if _, err := os.Stat(filepath.Join(cur, lock)); err == nil {
				if rel, err := filepath.Rel(repoClean, cur); err == nil {
					if rel == "." {
						best = ""
					} else {
						best = filepath.ToSlash(rel)
					}
				}
			}
		}
		if b, err := os.ReadFile(filepath.Join(cur, "package.json")); err == nil {
			var p pkgJSON
			if json.Unmarshal(b, &p) == nil && p.Workspaces != nil {
				if rel, err := filepath.Rel(repoClean, cur); err == nil {
					if rel == "." {
						best = ""
					} else {
						best = filepath.ToSlash(rel)
					}
				}
			}
		}
		if filepath.Clean(cur) == repoClean {
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return best
}

// DetectLocalServices inspects repoRoot (single-package or monorepo) and
// produces a generic local boot plan for browser integration QA.
func DetectLocalServices(repoRoot string) LocalAppPlan {
	var webCandidates []LocalServiceSpec
	var apiCandidates []LocalServiceSpec

	_ = filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		depth := 0
		if rel != "." {
			depth = strings.Count(rel, "/") + 1
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == ".venv" || name == "dist" || name == "build" || name == ".next" || name == "vendor" || name == "coverage" || depth > 4 {
				return filepath.SkipDir
			}
			return nil
		}
		dirRel := filepath.ToSlash(filepath.Dir(rel))
		if dirRel == "." {
			dirRel = ""
		}

		switch d.Name() {
		case "package.json":
			b, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			var p pkgJSON
			if json.Unmarshal(b, &p) != nil {
				return nil
			}
			installRoot := findWorkspaceInstallRoot(repoRoot, dirRel)
			_, runPrefix := detectPackageManager(filepath.Join(repoRoot, installRoot))

			// Web UI framework candidates
			if devScript, ok := p.Scripts["dev"]; ok && strings.TrimSpace(devScript) != "" {
				switch {
				case hasDep(p, "vite", "@vitejs/plugin-react", "@vitejs/plugin-vue", "@sveltejs/kit"):
					port := parsePortFromScript(devScript, 5173)
					cmd := fmt.Sprintf("%s dev -- --host 127.0.0.1 --port %d", runPrefix, port)
					if runPrefix == "yarn" {
						cmd = fmt.Sprintf("yarn dev --host 127.0.0.1 --port %d", port)
					}
					webCandidates = append(webCandidates, LocalServiceSpec{
						Name:       nonEmpty(p.Name, dirRel, "web"),
						Role:       "web",
						Framework:  "Vite",
						RelDir:     dirRel,
						Command:    cmd,
						Port:       port,
						HealthPath: "/",
					})
				case hasDep(p, "next"):
					port := parsePortFromScript(devScript, 3000)
					webCandidates = append(webCandidates, LocalServiceSpec{
						Name:       nonEmpty(p.Name, dirRel, "web"),
						Role:       "web",
						Framework:  "Next.js",
						RelDir:     dirRel,
						Command:    fmt.Sprintf("%s dev -- --hostname 127.0.0.1 --port %d", runPrefix, port),
						Port:       port,
						HealthPath: "/",
					})
				case hasDep(p, "nuxt", "astro", "react-scripts"):
					port := parsePortFromScript(devScript, 3000)
					webCandidates = append(webCandidates, LocalServiceSpec{
						Name:       nonEmpty(p.Name, dirRel, "web"),
						Role:       "web",
						Framework:  "WebApp",
						RelDir:     dirRel,
						Command:    fmt.Sprintf("%s dev", runPrefix),
						Port:       port,
						HealthPath: "/",
					})
				}
			}

			// API / backend server candidates
			if hasDep(p, "hono", "@hono/node-server", "express", "fastify", "koa", "@nestjs/core") {
				scriptName := ""
				for _, cand := range []string{"dev:local", "dev", "start"} {
					if s := strings.TrimSpace(p.Scripts[cand]); s != "" {
						scriptName = cand
						break
					}
				}
				if scriptName != "" {
					port := parsePortFromScript(p.Scripts[scriptName], 8787)
					if hasDep(p, "express", "fastify", "@nestjs/core") && port == 8787 {
						port = 3000
					}
					apiCandidates = append(apiCandidates, LocalServiceSpec{
						Name:       nonEmpty(p.Name, dirRel, "api"),
						Role:       "api",
						Framework:  "NodeAPI",
						RelDir:     dirRel,
						Command:    fmt.Sprintf("%s %s", runPrefix, scriptName),
						Port:       port,
						HealthPath: "/",
						Env:        map[string]string{"PORT": strconv.Itoa(port), "HOST": "127.0.0.1"},
					})
				}
			}

		case "pyproject.toml":
			b, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			lower := strings.ToLower(string(b))
			switch {
			case strings.Contains(lower, "fastapi") || strings.Contains(lower, "uvicorn"):
				apiCandidates = append(apiCandidates, LocalServiceSpec{
					Name:       nonEmpty(dirRel, "api"),
					Role:       "api",
					Framework:  "FastAPI",
					RelDir:     dirRel,
					Command:    "uvicorn main:app --host 127.0.0.1 --port 8000",
					Port:       8000,
					HealthPath: "/",
				})
			case strings.Contains(lower, "django"):
				apiCandidates = append(apiCandidates, LocalServiceSpec{
					Name:       nonEmpty(dirRel, "web"),
					Role:       "web",
					Framework:  "Django",
					RelDir:     dirRel,
					Command:    "python3 manage.py runserver 127.0.0.1:8000",
					Port:       8000,
					HealthPath: "/",
				})
			case strings.Contains(lower, "flask"):
				apiCandidates = append(apiCandidates, LocalServiceSpec{
					Name:       nonEmpty(dirRel, "api"),
					Role:       "api",
					Framework:  "Flask",
					RelDir:     dirRel,
					Command:    "flask run --host 127.0.0.1 --port 5000",
					Port:       5000,
					HealthPath: "/",
				})
			}
		}
		return nil
	})

	sort.SliceStable(webCandidates, func(i, j int) bool { return len(webCandidates[i].RelDir) < len(webCandidates[j].RelDir) })
	sort.SliceStable(apiCandidates, func(i, j int) bool { return len(apiCandidates[i].RelDir) < len(apiCandidates[j].RelDir) })

	var plan LocalAppPlan
	if len(webCandidates) > 0 {
		primary := webCandidates[0]
		plan.Primary = &primary
		for i := range apiCandidates {
			if apiCandidates[i].RelDir != primary.RelDir {
				comp := apiCandidates[i]
				if comp.Port == primary.Port {
					comp.Port++
					if comp.Env == nil {
						comp.Env = map[string]string{}
					}
					comp.Env["PORT"] = strconv.Itoa(comp.Port)
				}
				plan.Companion = &comp
				break
			}
		}
	} else if len(apiCandidates) > 0 {
		primary := apiCandidates[0]
		plan.Primary = &primary
	}

	if plan.Primary != nil && (plan.Primary.Framework == "Vite" || plan.Primary.Framework == "Next.js" || plan.Primary.Framework == "WebApp" || plan.Primary.Framework == "NodeAPI") {
		plan.InstallRelDir = findWorkspaceInstallRoot(repoRoot, plan.Primary.RelDir)
		plan.InstallCmd, _ = detectPackageManager(filepath.Join(repoRoot, plan.InstallRelDir))
	}
	return plan
}

func nonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return "app"
}

func containerPath(workspaceDir, relDir string) string {
	if relDir == "" || relDir == "." {
		return workspaceDir
	}
	return filepath.ToSlash(filepath.Join(workspaceDir, relDir))
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// BootLocalApp installs dependencies if needed and starts the PR's web/API
// application locally inside the isolated sandbox container so browser QA tests
// the exact checked-out PR code by default.
func BootLocalApp(ctx context.Context, container sandbox.Container, hostRepoDir string) (*LocalBootHandle, error) {
	if _, isLocal := container.(*sandbox.LocalContainer); isLocal {
		return nil, errors.New("refusing to execute untrusted local app commands on host container")
	}
	if container == nil {
		return nil, errors.New("sandbox container is required")
	}
	plan := DetectLocalServices(hostRepoDir)
	if plan.Primary == nil {
		return nil, ErrNoLocalAppDetected
	}
	wsDir := container.WorkspaceDir()

	// Install dependencies in the detected workspace root if node_modules is absent.
	if plan.InstallCmd != "" {
		installDir := containerPath(wsDir, plan.InstallRelDir)
		checkCmd := fmt.Sprintf("if [ ! -d %s/node_modules ]; then cd %s && (%s); fi", shellQuote(installDir), shellQuote(installDir), plan.InstallCmd)
		res, err := container.Exec(ctx, sandbox.ExecOpts{
			Command:        []string{"sh", "-c", checkCmd},
			Timeout:        4 * time.Minute,
			MaxOutputBytes: 64 * 1024,
		})
		if err != nil {
			return nil, fmt.Errorf("local dependency install failed: %w", err)
		}
		if res.ExitCode != 0 {
			tail := strings.TrimSpace(res.Stderr)
			if tail == "" {
				tail = strings.TrimSpace(res.Stdout)
			}
			if len(tail) > 500 {
				tail = tail[len(tail)-500:]
			}
			return nil, fmt.Errorf("local dependency install exited %d: %s", res.ExitCode, tail)
		}
	}

	var pidFiles []string
	var startedServices []string
	cleanup := func(cctx context.Context) {
		if len(pidFiles) == 0 {
			return
		}
		var parts []string
		for _, pf := range pidFiles {
			parts = append(parts, fmt.Sprintf(`if [ -f %s ]; then kill -TERM "$(cat %s)" 2>/dev/null || true; rm -f %s; fi`, shellQuote(pf), shellQuote(pf), shellQuote(pf)))
		}
		killCtx, cancel := context.WithTimeout(context.WithoutCancel(cctx), 5*time.Second)
		defer cancel()
		_, _ = container.Exec(killCtx, sandbox.ExecOpts{Command: []string{"sh", "-c", strings.Join(parts, "; ")}, Timeout: 5 * time.Second})
	}

	startService := func(spec LocalServiceSpec, logFile, pidFile string) error {
		dir := containerPath(wsDir, spec.RelDir)
		var envPrefix strings.Builder
		for k, v := range spec.Env {
			fmt.Fprintf(&envPrefix, "%s=%s ", k, shellQuote(v))
		}
		launch := fmt.Sprintf("cd %s && nohup env %s sh -c %s >%s 2>&1 </dev/null & echo $! > %s",
			shellQuote(dir), envPrefix.String(), shellQuote(spec.Command), shellQuote(logFile), shellQuote(pidFile))
		res, err := container.Exec(ctx, sandbox.ExecOpts{Command: []string{"sh", "-c", launch}, Timeout: 15 * time.Second})
		if err != nil || res.ExitCode != 0 {
			if err != nil {
				return err
			}
			return fmt.Errorf("failed to start %s (exit %d): %s", spec.Name, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		pidFiles = append(pidFiles, pidFile)
		startedServices = append(startedServices, fmt.Sprintf("%s(%s:%d)", spec.Name, spec.Framework, spec.Port))
		return nil
	}

	// Start companion API server first (best-effort; web UI may still render/function even if external DB env vars are missing).
	if plan.Companion != nil {
		_ = startService(*plan.Companion, "/tmp/wapo-companion.log", "/tmp/wapo-companion.pid")
		select {
		case <-ctx.Done():
			cleanup(ctx)
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	if err := startService(*plan.Primary, "/tmp/wapo-app.log", "/tmp/wapo-app.pid"); err != nil {
		cleanup(ctx)
		return nil, err
	}

	healthPath := plan.Primary.HealthPath
	if healthPath == "" {
		healthPath = "/"
	}
	targetURL := fmt.Sprintf("http://127.0.0.1:%d%s", plan.Primary.Port, healthPath)
	deadline := time.Now().Add(90 * time.Second)
	probeScript := fmt.Sprintf(`fetch(%q).then(r => process.exit(r.status < 500 ? 0 : 1)).catch(() => process.exit(1))`, targetURL)

	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			cleanup(ctx)
			return nil, err
		}
		probe, err := container.Exec(ctx, sandbox.ExecOpts{
			Command: []string{"node", "-e", probeScript},
			Timeout: 5 * time.Second,
		})
		if err == nil && probe.ExitCode == 0 {
			return &LocalBootHandle{
				URL:       fmt.Sprintf("http://127.0.0.1:%d", plan.Primary.Port),
				Framework: plan.Primary.Framework,
				Services:  startedServices,
				Cleanup:   cleanup,
			}, nil
		}
		// Check if primary process died early so we fail fast with logs.
		alive, _ := container.Exec(ctx, sandbox.ExecOpts{
			Command: []string{"sh", "-c", `kill -0 "$(cat /tmp/wapo-app.pid)" 2>/dev/null`},
			Timeout: 5 * time.Second,
		})
		if alive.ExitCode != 0 {
			logRes, _ := container.Exec(ctx, sandbox.ExecOpts{Command: []string{"tail", "-n", "30", "/tmp/wapo-app.log"}, Timeout: 5 * time.Second})
			cleanup(ctx)
			return nil, fmt.Errorf("local %s server exited before ready: %s", plan.Primary.Framework, strings.TrimSpace(logRes.Stdout))
		}
		select {
		case <-ctx.Done():
			cleanup(ctx)
			return nil, ctx.Err()
		case <-time.After(1500 * time.Millisecond):
		}
	}

	logRes, _ := container.Exec(ctx, sandbox.ExecOpts{Command: []string{"tail", "-n", "30", "/tmp/wapo-app.log"}, Timeout: 5 * time.Second})
	cleanup(ctx)
	return nil, fmt.Errorf("local %s server timed out waiting for %s: %s", plan.Primary.Framework, targetURL, strings.TrimSpace(logRes.Stdout))
}
