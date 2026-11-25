package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	DefaultMaxOutputBytes = 4 << 20
	DefaultWorkspaceDir   = "/workspace/repo"
)

type ExecOpts struct {
	Command        []string
	Env            map[string]string
	Dir            string
	Timeout        time.Duration
	MaxOutputBytes int
	Stdin          []byte
}

type ExecResult struct {
	ExitCode        int
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	Duration        time.Duration
}

type Container interface {
	Exec(ctx context.Context, opts ExecOpts) (ExecResult, error)
	WriteFile(ctx context.Context, path string, data []byte, mode os.FileMode, user string) error
	Close(ctx context.Context) error
	WorkspaceDir() string
}

type tailBuffer struct {
	mu        sync.Mutex
	buf       []byte
	limit     int
	truncated bool
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if b.limit <= 0 {
		b.limit = DefaultMaxOutputBytes
	}
	if len(p) >= b.limit {
		b.buf = append(b.buf[:0], p[len(p)-b.limit:]...)
		b.truncated = true
		return n, nil
	}
	if len(b.buf)+len(p) > b.limit {
		drop := len(b.buf) + len(p) - b.limit
		copy(b.buf, b.buf[drop:])
		b.buf = b.buf[:len(b.buf)-drop]
		b.truncated = true
	}
	b.buf = append(b.buf, p...)
	return n, nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := string(b.buf)
	if b.truncated {
		s = "...[output truncated, retaining final bytes]\n" + s
	}
	return s
}

func (b *tailBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

var _ io.Writer = (*tailBuffer)(nil)

// sensitiveEnvFragments lists prefixes/suffixes/substrings that must never leak
// from the host process into sandbox tool executions unless explicitly passed.
var sensitiveEnvSubstrings = []string{
	"API_KEY",
	"SECRET",
	"TOKEN",
	"PASSWORD",
	"PASSWD",
	"PRIVATE_KEY",
	"ACCESS_KEY",
	"CREDENTIAL",
	"DATABASE_URL",
	"OPENAI_",
	"ANTHROPIC_",
	"CLAUDE_",
	"OPENROUTER_",
	"CODEX_",
	"INFISICAL_",
	"HATCHET_",
	"WAPO_LLM_",
	"GITHUB_APP_",
}

// ScrubEnv strips sensitive host environment variables before handing an
// environment slice to a sandbox subprocess.
func ScrubEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		upper := strings.ToUpper(k)
		blocked := false
		for _, frag := range sensitiveEnvSubstrings {
			if strings.Contains(upper, frag) {
				blocked = true
				break
			}
		}
		if !blocked {
			out = append(out, kv)
		}
	}
	return out
}

type LocalContainer struct {
	Root string
}

func (c *LocalContainer) WorkspaceDir() string {
	if c != nil && strings.TrimSpace(c.Root) != "" {
		return filepath.Clean(c.Root)
	}
	return DefaultWorkspaceDir
}

func (c *LocalContainer) Exec(ctx context.Context, o ExecOpts) (ExecResult, error) {
	if o.Dir == "" && c != nil && c.Root != "" {
		if info, err := os.Stat(c.Root); err == nil && info.IsDir() {
			o.Dir = c.Root
		}
	}
	return runCommand(ctx, o)
}

func (c *LocalContainer) WriteFile(ctx context.Context, targetPath string, data []byte, mode os.FileMode, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root := "."
	if c != nil && strings.TrimSpace(c.Root) != "" {
		root = c.Root
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	p := targetPath
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	} else if c != nil && c.Root != "" {
		cleanRoot := filepath.Clean(root)
		if filepath.Clean(p) != cleanRoot && !strings.HasPrefix(filepath.Clean(p), cleanRoot+string(filepath.Separator)) {
			p = filepath.Join(root, strings.TrimLeft(p, string(filepath.Separator)))
		}
	}
	p, err = filepath.Abs(p)
	if err != nil {
		return err
	}
	full := p
	ancestor := filepath.Dir(full)
	for {
		resolved, resolveErr := filepath.EvalSymlinks(ancestor)
		if resolveErr == nil {
			rel, relErr := filepath.Rel(root, resolved)
			if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("write path escapes container root")
			}
			break
		}
		if !os.IsNotExist(resolveErr) {
			return resolveErr
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return resolveErr
		}
		ancestor = parent
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(full))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, parent)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("write path escapes container root")
	}
	p = filepath.Join(parent, filepath.Base(full))
	if info, statErr := os.Lstat(p); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		p, err = filepath.EvalSymlinks(p)
		if err != nil {
			return err
		}
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}
	rel, err = filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("write path escapes container root")
	}
	return os.WriteFile(p, data, mode)
}

func (c *LocalContainer) Close(context.Context) error { return nil }

func runCommand(ctx context.Context, o ExecOpts) (ExecResult, error) {
	started := time.Now()
	if len(o.Command) == 0 {
		return ExecResult{}, errors.New("empty command")
	}
	if o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	cmd := exec.Command(o.Command[0], o.Command[1:]...)
	cmd.Dir = o.Dir
	if len(o.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(o.Stdin)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Always start from scrubbed host environment so LLM/GitHub/Infisical
	// credentials never leak into sandbox commands.
	envMap := make(map[string]string)
	for _, kv := range ScrubEnv(os.Environ()) {
		if k, v, ok := strings.Cut(kv, "="); ok {
			envMap[k] = v
		}
	}
	for k, v := range o.Env {
		envMap[k] = v
	}
	keys := make([]string, 0, len(envMap))
	for k := range envMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	cmd.Env = make([]string, 0, len(keys))
	for _, k := range keys {
		cmd.Env = append(cmd.Env, k+"="+envMap[k])
	}

	out := &tailBuffer{limit: o.MaxOutputBytes}
	errout := &tailBuffer{limit: o.MaxOutputBytes}
	cmd.Stdout = out
	cmd.Stderr = errout
	if err := cmd.Start(); err != nil {
		return ExecResult{}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		waitErr = ctx.Err()
	}

	r := ExecResult{
		ExitCode:        0,
		Stdout:          out.String(),
		Stderr:          errout.String(),
		StdoutTruncated: out.Truncated(),
		StderrTruncated: errout.Truncated(),
		Duration:        time.Since(started),
	}
	if cmd.ProcessState != nil {
		r.ExitCode = cmd.ProcessState.ExitCode()
	}
	if errors.Is(waitErr, context.DeadlineExceeded) {
		r.ExitCode = 124
	} else if errors.Is(waitErr, context.Canceled) {
		r.ExitCode = 130
	} else if waitErr != nil {
		var ee *exec.ExitError
		if !errors.As(waitErr, &ee) {
			return r, waitErr
		}
	}
	return r, nil
}

type PodmanConfig struct {
	Image         string
	Network       string   // defaults to "none"; set "default" or "slirp4netns:allow_host_loopback=false" for isolated rootless networking
	CgroupManager string   // defaults to "cgroupfs" so rootless containers work under system systemd units
	Memory        string   // defaults to "2g"
	CPUs          string   // defaults to "2"
	PidsLimit     int      // defaults to 512
	User          string   // defaults to "root" for container exec
	WorkspaceDir  string   // defaults to "/workspace/repo"
	SleepSeconds  int      // defaults to 4200
	Volumes       []string // optional host:container bind mounts
	Labels        map[string]string
}

func (cfg PodmanConfig) normalized() PodmanConfig {
	if cfg.Network == "" {
		cfg.Network = "none"
	}
	if cfg.CgroupManager == "" {
		cfg.CgroupManager = "cgroupfs"
	}
	if cfg.Memory == "" {
		cfg.Memory = "2g"
	}
	if cfg.CPUs == "" {
		cfg.CPUs = "2"
	}
	if cfg.PidsLimit <= 0 {
		cfg.PidsLimit = 512
	}
	if cfg.User == "" {
		cfg.User = "root"
	}
	if cfg.WorkspaceDir == "" {
		cfg.WorkspaceDir = DefaultWorkspaceDir
	}
	if cfg.SleepSeconds <= 0 {
		cfg.SleepSeconds = 4200
	}
	return cfg
}

// BuildPodmanRunArgs constructs the hardened podman run argument vector.
// Kept pure so security invariants (--cap-drop=ALL, --security-opt=no-new-privileges,
// --network=none default, resource limits, zero host secrets) are unit-testable.
func BuildPodmanRunArgs(name string, cfg PodmanConfig) []string {
	c := cfg.normalized()
	args := []string{
		"podman",
		"--cgroup-manager=" + c.CgroupManager,
		"run", "--rm", "-d",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
	}
	if strings.HasPrefix(c.Image, "localhost/") {
		args = append(args, "--pull=never")
	}
	if c.Network != "default" {
		args = append(args, "--network="+c.Network)
	}
	args = append(args,
		"--memory="+c.Memory,
		"--cpus="+c.CPUs,
		fmt.Sprintf("--pids-limit=%d", c.PidsLimit),
		"--name", name,
	)
	for _, vol := range c.Volumes {
		if strings.TrimSpace(vol) != "" {
			args = append(args, "-v", vol)
		}
	}
	if len(c.Labels) > 0 {
		keys := make([]string, 0, len(c.Labels))
		for k := range c.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			args = append(args, "--label", k+"="+c.Labels[k])
		}
	}
	args = append(args, c.Image, "sleep", fmt.Sprint(c.SleepSeconds))
	return args
}

type PodmanContainer struct {
	Name     string
	Registry *ActiveRegistry
	Config   PodmanConfig
	Image    string
	execFn   func(context.Context, ExecOpts) (ExecResult, error)
}

func NewPodmanContainer(ctx context.Context, image string, registry *ActiveRegistry) (*PodmanContainer, error) {
	return NewPodmanContainerWithConfig(ctx, PodmanConfig{Image: image}, registry)
}

func NewPodmanContainerWithConfig(ctx context.Context, cfg PodmanConfig, registry *ActiveRegistry) (*PodmanContainer, error) {
	if strings.TrimSpace(cfg.Image) == "" {
		return nil, errors.New("empty image")
	}
	cfg = cfg.normalized()
	name := fmt.Sprintf("wapo-sandbox-%d", time.Now().UnixNano())
	p := &PodmanContainer{
		Name:     name,
		Registry: registry,
		Config:   cfg,
		Image:    cfg.Image,
		execFn:   runCommand,
	}
	if registry != nil {
		registry.Add(name)
	}
	args := BuildPodmanRunArgs(name, cfg)
	res, err := p.execFn(ctx, ExecOpts{Command: args, Timeout: 30 * time.Second, MaxOutputBytes: 8192})
	if err != nil || res.ExitCode != 0 {
		// Best-effort cleanup of any partially created container; keep it tracked if removal fails.
		rmCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		rmRes, rmErr := p.execFn(rmCtx, ExecOpts{Command: []string{"podman", "--cgroup-manager=" + p.cgroupManager(), "rm", "--force", name}, Timeout: 10 * time.Second, MaxOutputBytes: 4096})
		cancel()
		if registry != nil && rmErr == nil && rmRes.ExitCode == 0 {
			registry.Remove(name)
		}
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("podman run failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return p, nil
}

func (p *PodmanContainer) WorkspaceDir() string {
	if p != nil && p.Config.WorkspaceDir != "" {
		return p.Config.WorkspaceDir
	}
	return DefaultWorkspaceDir
}

func (p *PodmanContainer) runner() func(context.Context, ExecOpts) (ExecResult, error) {
	if p.execFn != nil {
		return p.execFn
	}
	return runCommand
}

func (p *PodmanContainer) cgroupManager() string {
	if p != nil && p.Config.CgroupManager != "" {
		return p.Config.CgroupManager
	}
	return "cgroupfs"
}

func (p *PodmanContainer) Exec(ctx context.Context, o ExecOpts) (ExecResult, error) {
	user := p.Config.User
	if user == "" {
		user = "root"
	}
	args := []string{"podman", "--cgroup-manager=" + p.cgroupManager(), "exec", "--interactive", "--user", user}
	if o.Dir != "" {
		args = append(args, "--workdir", o.Dir)
	}
	if len(o.Env) > 0 {
		keys := make([]string, 0, len(o.Env))
		for k := range o.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			args = append(args, "--env", k+"="+o.Env[k])
		}
	}
	args = append(args, p.Name)
	args = append(args, o.Command...)
	return p.runner()(ctx, ExecOpts{
		Command:        args,
		Timeout:        o.Timeout,
		MaxOutputBytes: o.MaxOutputBytes,
		Stdin:          o.Stdin,
	})
}

func (p *PodmanContainer) WriteFile(ctx context.Context, targetPath string, data []byte, mode os.FileMode, user string) error {
	if user == "" {
		user = p.Config.User
	}
	if user == "" {
		user = "root"
	}
	args := []string{
		"podman", "--cgroup-manager=" + p.cgroupManager(), "exec", "-i", "--user", user, p.Name,
		"sh", "-c",
		`mkdir -p "$(dirname "$1")" && cat > "$1" && chmod "$2" "$1"`,
		"sh", targetPath, fmt.Sprintf("%o", mode),
	}
	res, err := p.runner()(ctx, ExecOpts{Command: args, Stdin: data, Timeout: 30 * time.Second, MaxOutputBytes: 8192})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("podman write file %s failed (exit %d): %s", targetPath, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

func (p *PodmanContainer) Close(ctx context.Context) error {
	res, err := p.runner()(ctx, ExecOpts{Command: []string{"podman", "--cgroup-manager=" + p.cgroupManager(), "rm", "--force", p.Name}, Timeout: 30 * time.Second, MaxOutputBytes: 8192})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("podman rm %s failed (exit %d): %s", p.Name, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	if p.Registry != nil {
		p.Registry.Remove(p.Name)
	}
	return nil
}

type ActiveRegistry struct {
	mu      sync.Mutex
	names   map[string]struct{}
	cleanup func(context.Context, string) error
}

func NewActiveRegistry() *ActiveRegistry {
	return &ActiveRegistry{names: map[string]struct{}{}}
}

func (r *ActiveRegistry) Add(n string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names == nil {
		r.names = map[string]struct{}{}
	}
	r.names[n] = struct{}{}
}

func (r *ActiveRegistry) Remove(n string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.names, n)
}

func (r *ActiveRegistry) Names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := make([]string, 0, len(r.names))
	for n := range r.names {
		v = append(v, n)
	}
	sort.Strings(v)
	return v
}

func (r *ActiveRegistry) Cleanup(ctx context.Context) error {
	var first error
	for _, n := range r.Names() {
		var err error
		if r.cleanup != nil {
			err = r.cleanup(ctx, n)
		} else {
			res, e := runCommand(ctx, ExecOpts{Command: []string{"podman", "rm", "--force", n}, Timeout: 30 * time.Second, MaxOutputBytes: 4096})
			if e != nil {
				err = e
			} else if res.ExitCode != 0 {
				err = fmt.Errorf("podman rm %s exited %d: %s", n, res.ExitCode, strings.TrimSpace(res.Stderr))
			}
		}
		if err != nil && first == nil {
			first = err
		}
		if err == nil {
			r.Remove(n)
		}
	}
	return first
}
