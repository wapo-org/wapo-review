package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type BrowserState struct {
	StorageState json.RawMessage `json:"storageState,omitempty"`
	URL          string          `json:"url,omitempty"`
	StepIndex    int             `json:"stepIndex,omitempty"`
}

type Checkpoint struct {
	ID       string       `json:"id"`
	Label    string       `json:"label"`
	State    BrowserState `json:"state"`
	Created  time.Time    `json:"created"`
	Revision string       `json:"revision,omitempty"`
	TreeHash string       `json:"treeHash,omitempty"`
}

type CheckpointManager struct {
	mu      sync.RWMutex
	seq     atomic.Int64
	c       Container
	history []Checkpoint
}

func NewCheckpointManager(c Container) *CheckpointManager {
	return &CheckpointManager{c: c}
}

// Save captures both the exact workspace tree (tracked + untracked files via
// an ephemeral GIT_INDEX_FILE without touching HEAD or the user's real index)
// and the paired BrowserState for coordinated turn rollback.
func (m *CheckpointManager) Save(ctx context.Context, label string, state BrowserState) (Checkpoint, error) {
	now := time.Now().UTC()
	id := fmt.Sprintf("cp-%d-%d", now.UnixNano(), m.seq.Add(1))
	cp := Checkpoint{
		ID:      id,
		Label:   label,
		State:   state,
		Created: now,
	}

	if m.c != nil {
		ws := workspaceDir(m.c)
		script := `set -eu
cd "$1"
head_rev=$(git rev-parse HEAD)
tmp_idx=$(mktemp)
trap 'rm -f "$tmp_idx"' EXIT
cp .git/index "$tmp_idx" 2>/dev/null || true
GIT_INDEX_FILE="$tmp_idx" git add -A
tree_hash=$(GIT_INDEX_FILE="$tmp_idx" git write-tree)
printf '%s %s\n' "$head_rev" "$tree_hash"
`
		r, err := m.c.Exec(ctx, ExecOpts{
			Command:        []string{"sh", "-c", script, "sh", ws},
			Timeout:        15 * time.Second,
			MaxOutputBytes: 4096,
		})
		if err != nil {
			return Checkpoint{}, err
		}
		if r.ExitCode != 0 {
			return Checkpoint{}, fmt.Errorf("checkpoint snapshot failed (exit %d): %s", r.ExitCode, strings.TrimSpace(r.Stderr))
		}
		{
			fields := strings.Fields(strings.TrimSpace(r.Stdout))
			if len(fields) >= 1 {
				cp.Revision = fields[0]
			}
			if len(fields) >= 2 {
				cp.TreeHash = fields[1]
			}
		}
	}

	m.mu.Lock()
	m.history = append(m.history, cp)
	m.mu.Unlock()
	return cp, nil
}

// Rollback restores the workspace to the exact tree captured by checkpoint id
// and returns the restored Checkpoint (including its BrowserState).
func (m *CheckpointManager) Rollback(ctx context.Context, id string) (Checkpoint, error) {
	m.mu.RLock()
	idx := -1
	for i, cp := range m.history {
		if cp.ID == id {
			idx = i
			break
		}
	}
	var cp Checkpoint
	if idx >= 0 {
		cp = m.history[idx]
	}
	m.mu.RUnlock()

	if idx < 0 {
		return Checkpoint{}, fmt.Errorf("checkpoint not found: %s", id)
	}
	if m.c == nil || (cp.Revision == "" && cp.TreeHash == "") {
		return cp, nil
	}

	ws := workspaceDir(m.c)
	script := `set -eu
cd "$1"
rev="$2"
tree="$3"
if [ -n "$rev" ]; then
  git reset -q --hard "$rev"
fi
git clean -q -fd
if [ -n "$tree" ]; then
  git read-tree --reset -u "$tree"
  if [ -n "$rev" ]; then
    git reset -q --mixed "$rev"
  fi
fi
`
	r, err := m.c.Exec(ctx, ExecOpts{
		Command:        []string{"sh", "-c", script, "sh", ws, cp.Revision, cp.TreeHash},
		Timeout:        30 * time.Second,
		MaxOutputBytes: 8192,
	})
	if err != nil {
		return Checkpoint{}, err
	}
	if r.ExitCode != 0 {
		return Checkpoint{}, fmt.Errorf("rollback failed (exit %d): %s", r.ExitCode, strings.TrimSpace(r.Stderr))
	}
	return cp, nil
}

func (m *CheckpointManager) Latest() (Checkpoint, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.history) == 0 {
		return Checkpoint{}, false
	}
	return m.history[len(m.history)-1], true
}

func (m *CheckpointManager) History() []Checkpoint {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Checkpoint(nil), m.history...)
}
