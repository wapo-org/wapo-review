package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s failed: %v\n%s", args, dir, err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func TestLocalContainerBoundedOutputAndTimeout(t *testing.T) {
	c := &LocalContainer{Root: t.TempDir()}

	r, err := c.Exec(context.Background(), ExecOpts{
		Command:        []string{"sh", "-c", "printf '0123456789abcdefghij'"},
		MaxOutputBytes: 10,
	})
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if !r.StdoutTruncated || !strings.HasSuffix(r.Stdout, "abcdefghij") {
		t.Fatalf("expected truncated tail ending in abcdefghij, got %+v", r)
	}

	r, err = c.Exec(context.Background(), ExecOpts{
		Command: []string{"sh", "-c", "sleep 5"},
		Timeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("timeout exec returned unexpected err: %v", err)
	}
	if r.ExitCode != 124 {
		t.Fatalf("expected exit 124 on timeout, got %d", r.ExitCode)
	}
}

func TestLocalContainerWriteFileAtRoot(t *testing.T) {
	root := t.TempDir()
	c := &LocalContainer{Root: root}
	if err := c.WriteFile(context.Background(), "config.json", []byte(`{"ok":true}`), 0o600, ""); err != nil {
		t.Fatalf("write at container root: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "config.json"))
	if err != nil || string(got) != `{"ok":true}` {
		t.Fatalf("unexpected file contents %q, err=%v", got, err)
	}
}

func TestEnvScrubbingNeverLeaksHostSecrets(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-super-secret-value")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
	t.Setenv("INFISICAL_CLIENT_SECRET", "infisical-secret")
	t.Setenv("WAPO_SAFE_TEST_VAR", "safe-ok")

	c := &LocalContainer{Root: t.TempDir()}
	r, err := c.Exec(context.Background(), ExecOpts{
		Command: []string{"sh", "-c", "printf 'O=%s|A=%s|I=%s|S=%s' \"$OPENAI_API_KEY\" \"$ANTHROPIC_API_KEY\" \"$INFISICAL_CLIENT_SECRET\" \"$WAPO_SAFE_TEST_VAR\""},
	})
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if r.Stdout != "O=|A=|I=|S=safe-ok" {
		t.Fatalf("expected host secrets scrubbed and safe var kept, got %q", r.Stdout)
	}
}

func TestBuildPodmanRunArgsHardenedDefaults(t *testing.T) {
	args := BuildPodmanRunArgs("wapo-test-1", PodmanConfig{
		Image:  "localhost/wapo-sandbox:latest",
		Labels: map[string]string{"wapo.run": "run-1"},
	})
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--network=none",
		"--memory=2g",
		"--cpus=2",
		"--pids-limit=512",
		"--label wapo.run=run-1",
		"--name wapo-test-1",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected %q in podman args, got %q", want, joined)
		}
	}
	if strings.Contains(joined, "--env") {
		t.Fatalf("podman run args must not inject credentials via --env: %q", joined)
	}
}

func TestActiveRegistryTrackingAndCleanup(t *testing.T) {
	reg := NewActiveRegistry()
	var cleaned []string
	reg.cleanup = func(_ context.Context, name string) error {
		cleaned = append(cleaned, name)
		return nil
	}
	reg.Add("c-b")
	reg.Add("c-a")
	if got := strings.Join(reg.Names(), ","); got != "c-a,c-b" {
		t.Fatalf("unexpected names: %s", got)
	}
	if err := reg.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if len(cleaned) != 2 || len(reg.Names()) != 0 {
		t.Fatalf("expected 2 cleaned and 0 remaining, got cleaned=%v remaining=%v", cleaned, reg.Names())
	}
}

func TestActiveRegistryKeepsFailedCleanupForRetry(t *testing.T) {
	reg := NewActiveRegistry()
	calls := 0
	reg.cleanup = func(context.Context, string) error {
		calls++
		if calls == 1 {
			return fmt.Errorf("temporary failure")
		}
		return nil
	}
	reg.Add("container")
	if err := reg.Cleanup(context.Background()); err == nil || len(reg.Names()) != 1 {
		t.Fatalf("failed cleanup should retain name, err=%v names=%v", err, reg.Names())
	}
	if err := reg.Cleanup(context.Background()); err != nil || len(reg.Names()) != 0 {
		t.Fatalf("retry cleanup failed, err=%v names=%v", err, reg.Names())
	}
}

func TestRepoToolsAndSymlinkEscapeProtection(t *testing.T) {
	ws := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("top-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	runGit(t, ws, "init", "-q")
	if err := os.MkdirAll(filepath.Join(ws, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "src", "app.ts"), []byte("line1\nexport const token = 42;\nline3\nline4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(ws, "src", "escape.txt")); err != nil {
		t.Fatal(err)
	}
	runGit(t, ws, "add", "src/app.ts")
	runGit(t, ws, "commit", "-q", "-m", "init")
	baseSHA := runGit(t, ws, "rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(ws, "src", "app.ts"), []byte("line1\nexport const token = 99;\nline3\nline4\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := &LocalContainer{Root: ws}
	ctx := context.Background()

	got, err := ReadFile(ctx, c, "src/app.ts", 2, 3)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	want := "2: export const token = 99;\n3: line3\n"
	if got != want {
		t.Fatalf("ReadFile got %q, want %q", got, want)
	}

	if _, err := ReadFile(ctx, c, "../escape", 1, 10); err == nil {
		t.Fatal("expected traversal path to be rejected")
	}
	if _, err := ReadFile(ctx, c, "src/escape.txt", 1, 10); err == nil {
		t.Fatal("expected symlink escape outside workspace to be rejected")
	}

	gr, err := Grep(ctx, c, "token = 99", "*.ts", 5)
	if err != nil {
		t.Fatalf("Grep failed: %v", err)
	}
	if !strings.Contains(gr.Stdout, "app.ts:2:") {
		t.Fatalf("expected match in app.ts:2, got %q", gr.Stdout)
	}

	lf, err := ListFiles(ctx, c, "src")
	if err != nil || !strings.Contains(lf.Stdout, "src/app.ts") {
		t.Fatalf("ListFiles unexpected result: %+v err=%v", lf, err)
	}

	diff, err := GitDiff(ctx, c, baseSHA, []string{"src/app.ts"})
	if err != nil || !strings.Contains(diff.Stdout, "+export const token = 99;") {
		t.Fatalf("GitDiff unexpected result: %+v err=%v", diff, err)
	}

	shown, err := GitShow(ctx, c, baseSHA, "src/app.ts")
	if err != nil || !strings.Contains(shown.Stdout, "token = 42") {
		t.Fatalf("GitShow unexpected result: %+v err=%v", shown, err)
	}
}

func TestCheckoutRepoBaseSHAAndPRHeadFallback(t *testing.T) {
	bare := filepath.Join(t.TempDir(), "origin.git")
	work := filepath.Join(t.TempDir(), "seed")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}

	runGit(t, bare, "init", "--bare", "-q")
	runGit(t, work, "init", "-q", "-b", "main")
	runGit(t, work, "remote", "add", "origin", bare)

	if err := os.WriteFile(filepath.Join(work, "a.txt"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", "a.txt")
	runGit(t, work, "commit", "-q", "-m", "base")
	baseSHA := runGit(t, work, "rev-parse", "HEAD")
	runGit(t, work, "push", "-q", "origin", "main")

	// Create PR branch with change, push to refs/pull/77/head.
	runGit(t, work, "checkout", "-q", "-b", "feat")
	if err := os.WriteFile(filepath.Join(work, "a.txt"), []byte("pr-change\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "commit", "-q", "-am", "pr change")
	headSHA := runGit(t, work, "rev-parse", "HEAD")
	runGit(t, work, "push", "-q", "origin", "HEAD:refs/pull/77/head")

	// Advance main forward (simulating a merged PR where origin/main moved on).
	runGit(t, work, "checkout", "-q", "main")
	if err := os.WriteFile(filepath.Join(work, "later.txt"), []byte("post-merge\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", "later.txt")
	runGit(t, work, "commit", "-q", "-m", "post-merge main")
	runGit(t, work, "push", "-q", "origin", "main")

	// Checkout with BaseSHA (merged PR scenario) + token passed via ephemeral header.
	ws1 := filepath.Join(t.TempDir(), "ws1")
	c1 := &LocalContainer{Root: ws1}
	res1, err := CheckoutRepo(context.Background(), c1, CheckoutSpec{
		RemoteURL: "file://" + bare,
		BaseRef:   "main",
		BaseSHA:   baseSHA,
		HeadSHA:   headSHA,
		PRNumber:  77,
		Merged:    true,
		Token:     "ghs_never_persist_this_token",
	})
	if err != nil {
		t.Fatalf("CheckoutRepo failed: %v", err)
	}
	if res1.HeadSHA != headSHA {
		t.Fatalf("expected HeadSHA=%s, got %s", headSHA, res1.HeadSHA)
	}
	if !res1.UsedBaseSHA || res1.DiffBase != baseSHA {
		t.Fatalf("expected DiffBase=%s (UsedBaseSHA=true), got %+v", baseSHA, res1)
	}
	diff, err := GitDiff(context.Background(), c1, res1.DiffBase, nil)
	if err != nil || !strings.Contains(diff.Stdout, "+pr-change") || strings.Contains(diff.Stdout, "later.txt") {
		t.Fatalf("merged PR diff should only show PR changes vs BaseSHA, got: %s (err=%v)", diff.Stdout, err)
	}
	cfgBytes, err := os.ReadFile(filepath.Join(ws1, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfgBytes), "ghs_never_persist_this_token") {
		t.Fatal("GitHub token leaked into .git/config")
	}

	// Checkout with only PRNumber (refs/pull/77/head fallback).
	ws2 := filepath.Join(t.TempDir(), "ws2")
	c2 := &LocalContainer{Root: ws2}
	res2, err := CheckoutRepo(context.Background(), c2, CheckoutSpec{
		RemoteURL: "file://" + bare,
		BaseRef:   "main",
		PRNumber:  77,
	})
	if err != nil {
		t.Fatalf("CheckoutRepo PR fallback failed: %v", err)
	}
	if !res2.UsedPRHeadFallback || res2.HeadSHA != headSHA {
		t.Fatalf("expected PR head fallback to %s, got %+v", headSHA, res2)
	}
}

func TestDependencyErrorNormalizationAndResilientGates(t *testing.T) {
	eco := DetectEcosystems([]string{"package.json", "package-lock.json", "go.mod", "tests/test_app.py"})
	if !eco.Node || !eco.NPM || !eco.Go || !eco.Python || !eco.Pytest {
		t.Fatalf("unexpected ecosystems: %+v", eco)
	}

	raw := strings.Join([]string{
		"npm notice New major version of npm available",
		"npm error code EUSAGE",
		"npm error `npm ci` can only install packages when your package.json and package-lock.json are in sync.",
		"npm error Missing: zod@3.24.0 from lock file",
		"npm error Clean install a project",
		"npm error Usage:",
		"npm error npm ci",
		"npm error Options:",
		"npm error [--include-workspace-root]",
		"npm error A complete log of this run can be found in: /root/.npm/_logs/debug.log",
	}, "\n")
	norm := NormalizeDepInstallOutput(raw, 4000)
	if strings.Contains(norm, "npm error Usage:") || strings.Contains(norm, "npm notice") || strings.Contains(norm, "--include-workspace-root") {
		t.Fatalf("expected npm usage/notice boilerplate stripped, got:\n%s", norm)
	}
	if !strings.Contains(norm, "Missing: zod@3.24.0 from lock file") {
		t.Fatalf("expected real lockfile diagnostic preserved, got:\n%s", norm)
	}

	c := &LocalContainer{Root: t.TempDir()}
	ctx := context.Background()
	depRes, err := InstallDependenciesWithCommand(ctx, c, []string{"sh", "-c", "printf 'npm error Missing: foo\\nnpm error Usage:\\nnpm error npm ci\\n' >&2; exit 1"})
	if err != nil {
		t.Fatalf("dep install failure must return err==nil and failed GateResult, got err=%v", err)
	}
	if depRes == nil || depRes.Status != "failed" || depRes.ExitCode == nil || *depRes.ExitCode != 1 {
		t.Fatalf("unexpected dep gate result: %+v", depRes)
	}
	if strings.Contains(depRes.OutputTail, "npm error Usage:") || !strings.Contains(depRes.OutputTail, "Missing: foo") {
		t.Fatalf("unexpected normalized output tail: %q", depRes.OutputTail)
	}

	results := RunGates(ctx, c, []GateSpec{
		{ID: "lint", Command: []string{"sh", "-c", "echo lint-fail >&2; exit 2"}},
		{ID: "unit", Command: []string{"sh", "-c", "echo unit-ok; exit 0"}},
	})
	if len(results) != 2 || results[0].Status != "failed" || results[1].Status != "passed" {
		t.Fatalf("expected independent gate results [failed, passed], got %+v", results)
	}
}

func TestCheckpointSaveAndRollbackDirtyWorkspaceAndBrowserState(t *testing.T) {
	ws := t.TempDir()
	runGit(t, ws, "init", "-q")
	if err := os.WriteFile(filepath.Join(ws, "tracked.txt"), []byte("initial\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, ws, "add", "tracked.txt")
	runGit(t, ws, "commit", "-q", "-m", "init")

	c := &LocalContainer{Root: ws}
	cm := NewCheckpointManager(c)
	ctx := context.Background()

	// Make dirty tracked edit + untracked file BEFORE checkpoint 1.
	if err := os.WriteFile(filepath.Join(ws, "tracked.txt"), []byte("turn-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "untracked1.txt"), []byte("keep-me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cp1, err := cm.Save(ctx, "before-turn-2", BrowserState{
		URL:          "https://preview.example/dashboard",
		StorageState: json.RawMessage(`{"cookies":[{"name":"sid","value":"abc"}]}`),
		StepIndex:    1,
	})
	if err != nil {
		t.Fatalf("Save cp1 failed: %v", err)
	}
	if cp1.Revision == "" || cp1.TreeHash == "" {
		t.Fatalf("expected revision and tree hash captured, got %+v", cp1)
	}

	// Simulate destructive turn 2 edits.
	if err := os.WriteFile(filepath.Join(ws, "tracked.txt"), []byte("broken-turn-2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "junk.txt"), []byte("remove-me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(ws, "untracked1.txt")); err != nil {
		t.Fatal(err)
	}

	restored, err := cm.Rollback(ctx, cp1.ID)
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}
	if restored.State.URL != "https://preview.example/dashboard" || !strings.Contains(string(restored.State.StorageState), `"sid"`) {
		t.Fatalf("expected browser state returned on rollback, got %+v", restored.State)
	}

	b, err := os.ReadFile(filepath.Join(ws, "tracked.txt"))
	if err != nil || string(b) != "turn-1\n" {
		t.Fatalf("expected tracked.txt restored to turn-1, got %q (err=%v)", string(b), err)
	}
	b, err = os.ReadFile(filepath.Join(ws, "untracked1.txt"))
	if err != nil || string(b) != "keep-me\n" {
		t.Fatalf("expected untracked1.txt restored, got %q (err=%v)", string(b), err)
	}
	if _, err := os.Stat(filepath.Join(ws, "junk.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected junk.txt cleaned on rollback, stat err=%v", err)
	}
}
