package sandbox

import (
	"context"
	"encoding/base64"
	"fmt"
	"path"
	"strings"
	"time"
)

func workspaceDir(c Container) string {
	if c != nil && strings.TrimSpace(c.WorkspaceDir()) != "" {
		return c.WorkspaceDir()
	}
	return DefaultWorkspaceDir
}

func validPath(p string) (string, error) {
	if p == "" || strings.Contains(p, "\\") || path.IsAbs(p) || strings.ContainsRune(p, '\x00') {
		return "", fmt.Errorf("invalid repository path: %q", p)
	}
	clean := path.Clean(p)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("path escapes workspace: %q", p)
	}
	return clean, nil
}

// ReadFile reads a bounded line range from a file inside the repository
// workspace, rejecting path traversal and symlink escapes.
func ReadFile(ctx context.Context, c Container, relPath string, startLine, endLine int) (string, error) {
	p, err := validPath(relPath)
	if err != nil {
		return "", err
	}
	if startLine < 1 {
		startLine = 1
	}
	if endLine < 0 {
		endLine = 0
	}
	ws := workspaceDir(c)
	// Pure POSIX sh + awk: verifies canonical path stays inside workspace root,
	// avoiding any Python dependency inside minimal tool containers.
	script := `set -eu
root=$(cd "$1" && pwd -P)
target_dir=$(cd "$(dirname "$1/$2")" && pwd -P)
target="$target_dir/$(basename "$2")"
if command -v readlink >/dev/null 2>&1; then
  resolved=$(readlink -f "$target" 2>/dev/null || printf '%s' "$target")
else
  resolved="$target"
fi
case "$resolved" in
  "$root"/*) ;;
  *) echo "symlink escapes workspace" >&2; exit 2 ;;
esac
[ -f "$resolved" ] || { echo "file not found: $2" >&2; exit 1; }
awk -v a="$3" -v b="$4" 'NR>=a && (b==0 || NR<=b) {printf "%d: %s\n", NR, $0}' "$resolved"
`
	args := []string{"sh", "-c", script, "sh", ws, p, fmt.Sprint(startLine), fmt.Sprint(endLine)}
	r, err := c.Exec(ctx, ExecOpts{Command: args, Timeout: 20 * time.Second, MaxOutputBytes: 1 << 20})
	if err != nil {
		return "", err
	}
	if r.ExitCode != 0 {
		return "", fmt.Errorf("read file %s failed: %s", p, strings.TrimSpace(r.Stderr))
	}
	return r.Stdout, nil
}

func Grep(ctx context.Context, c Container, pattern, glob string, maxMatches int) (ExecResult, error) {
	if strings.TrimSpace(pattern) == "" {
		return ExecResult{}, fmt.Errorf("empty grep pattern")
	}
	if maxMatches < 1 {
		maxMatches = 100
	}
	ws := workspaceDir(c)
	script := `set -u
cd "$1" || exit 1
glob="$2"
pat="$3"
lim="$4"
if command -v rg >/dev/null 2>&1; then
  if [ -n "$glob" ]; then
    rg --line-number --no-heading --glob "$glob" -- "$pat" . 2>/dev/null | head -n "$lim"
  else
    rg --line-number --no-heading -- "$pat" . 2>/dev/null | head -n "$lim"
  fi
else
  if [ -n "$glob" ]; then
    grep -R -n -E --include="$glob" --exclude-dir=.git -- "$pat" . 2>/dev/null | head -n "$lim"
  else
    grep -R -n -E --exclude-dir=.git -- "$pat" . 2>/dev/null | head -n "$lim"
  fi
fi
exit 0
`
	args := []string{"sh", "-c", script, "sh", ws, glob, pattern, fmt.Sprint(maxMatches)}
	return c.Exec(ctx, ExecOpts{Command: args, Timeout: 30 * time.Second, MaxOutputBytes: 1 << 20})
}

func ListFiles(ctx context.Context, c Container, prefix string) (ExecResult, error) {
	ws := workspaceDir(c)
	args := []string{"git", "-C", ws, "ls-files"}
	if prefix != "" {
		p, err := validPath(prefix)
		if err != nil {
			return ExecResult{}, err
		}
		args = append(args, "--", p)
	}
	return c.Exec(ctx, ExecOpts{Command: args, Timeout: 15 * time.Second, MaxOutputBytes: 1 << 20})
}

func GitDiff(ctx context.Context, c Container, diffBase string, paths []string) (ExecResult, error) {
	if strings.TrimSpace(diffBase) == "" {
		return ExecResult{}, fmt.Errorf("empty diff base")
	}
	ws := workspaceDir(c)
	args := []string{"git", "-C", ws, "diff", "--no-ext-diff", diffBase, "--"}
	for _, p := range paths {
		v, err := validPath(p)
		if err != nil {
			return ExecResult{}, err
		}
		args = append(args, v)
	}
	return c.Exec(ctx, ExecOpts{Command: args, Timeout: 30 * time.Second, MaxOutputBytes: 2 << 20})
}

func GitShow(ctx context.Context, c Container, rev, relPath string) (ExecResult, error) {
	if strings.TrimSpace(rev) == "" {
		return ExecResult{}, fmt.Errorf("empty git revision")
	}
	p, err := validPath(relPath)
	if err != nil {
		return ExecResult{}, err
	}
	ws := workspaceDir(c)
	return c.Exec(ctx, ExecOpts{Command: []string{"git", "-C", ws, "show", rev + ":" + p}, Timeout: 15 * time.Second, MaxOutputBytes: 1 << 20})
}

type CheckoutSpec struct {
	Repository string
	RemoteURL  string // optional override (e.g. file:// bare repo in tests)
	BaseRef    string
	BaseSHA    string
	HeadSHA    string
	PRNumber   int
	Merged     bool
	Closed     bool
	Token      string
	Depth      int
}

type CheckoutResult struct {
	HeadSHA            string
	DiffBase           string
	UsedPRHeadFallback bool
	UsedBaseSHA        bool
}

// CheckoutRepo clones/fetches a PR head and diff base into the container
// workspace without persisting credentials into .git/config.
// For merged/closed PRs (or whenever BaseSHA is supplied), DiffBase resolves
// directly to BaseSHA instead of moving origin/<base_ref> so diffs remain exact.
func CheckoutRepo(ctx context.Context, c Container, s CheckoutSpec) (CheckoutResult, error) {
	remote := strings.TrimSpace(s.RemoteURL)
	if remote == "" {
		if strings.Contains(s.Repository, "..") || strings.TrimSpace(s.Repository) == "" || !strings.Contains(s.Repository, "/") {
			return CheckoutResult{}, fmt.Errorf("invalid repository: %q", s.Repository)
		}
		remote = "https://github.com/" + s.Repository + ".git"
	}
	if s.Depth <= 0 {
		s.Depth = 50
	}
	ws := workspaceDir(c)

	env := map[string]string{
		"GIT_TERMINAL_PROMPT": "0",
	}
	if s.Token != "" {
		basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + s.Token))
		env["GIT_CONFIG_COUNT"] = "1"
		env["GIT_CONFIG_KEY_0"] = "http.extraheader"
		env["GIT_CONFIG_VALUE_0"] = "AUTHORIZATION: basic " + basic
	}

	script := `set -eu
ws="$1"
remote="$2"
depth="$3"
base_ref="$4"
base_sha="$5"
head_sha="$6"
pr_num="$7"

mkdir -p "$ws"
cd "$ws"
if [ ! -d .git ]; then
  git init -q .
fi
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$remote"
else
  git remote add origin "$remote"
fi

used_pr_fallback=0
checkout_ref=""

if [ -n "$head_sha" ]; then
  if git -c credential.helper= fetch --depth "$depth" origin "$head_sha" >/dev/null 2>&1; then
    checkout_ref="$head_sha"
  elif [ "$pr_num" != "0" ] && git -c credential.helper= fetch --depth "$depth" origin "refs/pull/$pr_num/head" >/dev/null 2>&1; then
    used_pr_fallback=1
    checkout_ref="FETCH_HEAD"
  else
    echo "failed to fetch head_sha $head_sha" >&2
    exit 1
  fi
elif [ "$pr_num" != "0" ]; then
  git -c credential.helper= fetch --depth "$depth" origin "refs/pull/$pr_num/head"
  used_pr_fallback=1
  checkout_ref="FETCH_HEAD"
elif [ -n "$base_ref" ]; then
  git -c credential.helper= fetch --depth "$depth" origin "$base_ref"
  checkout_ref="FETCH_HEAD"
else
  echo "no head_sha, pr_num, or base_ref supplied" >&2
  exit 1
fi

git checkout -q --detach "$checkout_ref"
resolved_head=$(git rev-parse HEAD)

used_base_sha=0
diff_base=""
if [ -n "$base_sha" ]; then
  if ! git cat-file -e "$base_sha^{commit}" 2>/dev/null; then
    git -c credential.helper= fetch --depth "$depth" origin "$base_sha" >/dev/null 2>&1 || true
  fi
  if git cat-file -e "$base_sha^{commit}" 2>/dev/null; then
    diff_base="$base_sha"
    used_base_sha=1
  fi
fi

if [ -z "$diff_base" ] && [ -n "$base_ref" ]; then
  if git -c credential.helper= fetch --depth "$depth" origin "refs/heads/$base_ref:refs/remotes/origin/$base_ref" >/dev/null 2>&1; then
    diff_base="origin/$base_ref"
  elif git -c credential.helper= fetch --depth "$depth" origin "$base_ref" >/dev/null 2>&1; then
    diff_base=$(git rev-parse FETCH_HEAD)
  fi
fi

if [ -z "$diff_base" ]; then
  diff_base="$resolved_head"
fi

printf 'HEAD_SHA=%s\nDIFF_BASE=%s\nUSED_PR_FALLBACK=%s\nUSED_BASE_SHA=%s\n' "$resolved_head" "$diff_base" "$used_pr_fallback" "$used_base_sha"
`
	args := []string{
		"sh", "-c", script, "sh",
		ws, remote, fmt.Sprint(s.Depth),
		s.BaseRef, s.BaseSHA, s.HeadSHA, fmt.Sprint(s.PRNumber),
	}
	r, err := c.Exec(ctx, ExecOpts{Command: args, Env: env, Timeout: 2 * time.Minute, MaxOutputBytes: 1 << 16})
	if err != nil {
		return CheckoutResult{}, err
	}
	if r.ExitCode != 0 {
		return CheckoutResult{}, fmt.Errorf("checkout failed (exit %d): %s", r.ExitCode, strings.TrimSpace(r.Stderr))
	}

	var res CheckoutResult
	for _, line := range strings.Split(strings.TrimSpace(r.Stdout), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "HEAD_SHA":
			res.HeadSHA = v
		case "DIFF_BASE":
			res.DiffBase = v
		case "USED_PR_FALLBACK":
			res.UsedPRHeadFallback = v == "1"
		case "USED_BASE_SHA":
			res.UsedBaseSHA = v == "1"
		}
	}
	return res, nil
}
