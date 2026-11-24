package orchestrator

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	_ "modernc.org/sqlite"
)

type runEntry struct {
	gen    uint64
	cancel context.CancelFunc
	done   chan struct{}
	result *ReviewResult
	err    error
}

type LocalRunner struct {
	Stages      ReviewStages
	MaxShards   int
	TenantLimit int
	DB          *sql.DB

	mu          sync.Mutex
	genSeq      atomic.Uint64
	runs        map[string]*runEntry
	tenantSlots map[string]chan struct{}
}

func NewLocalRunner(stages ReviewStages, maxShards, tenantLimit int, db *sql.DB) *LocalRunner {
	if maxShards < 1 {
		maxShards = 4
	}
	if tenantLimit < 1 {
		tenantLimit = 2
	}
	r := &LocalRunner{
		Stages:      stages,
		MaxShards:   maxShards,
		TenantLimit: tenantLimit,
		DB:          db,
		runs:        map[string]*runEntry{},
		tenantSlots: map[string]chan struct{}{},
	}
	if db != nil {
		_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS deliveries (
			run_id TEXT PRIMARY KEY,
			repo TEXT NOT NULL DEFAULT '',
			pr_number INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT '',
			result BLOB,
			error TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL DEFAULT ''
		)`)
	}
	return r
}

var _ WorkflowRunner = (*LocalRunner)(nil)

func (l *LocalRunner) persistDelivery(in ReviewInput, gen uint64, status string, out *ReviewOutput, runErr error) {
	if l.DB == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if current := l.runs[in.RunID]; current == nil || current.gen != gen {
		return
	}
	var blob []byte
	if out != nil {
		blob, _ = json.Marshal(out)
	}
	errStr := ""
	if runErr != nil {
		errStr = runErr.Error()
	}
	_, _ = l.DB.Exec(
		`INSERT OR REPLACE INTO deliveries(run_id, repo, pr_number, status, result, error, updated_at) VALUES(?,?,?,?,?,?,?)`,
		in.RunID, in.Repo, in.PRNumber, status, blob, errStr, time.Now().UTC().Format(time.RFC3339Nano),
	)
}

// Start begins (or coalesces/supersedes) a PR review run keyed by RunID (or repo:pr).
func (l *LocalRunner) Start(ctx context.Context, in ReviewInput) (RunRef, error) {
	if l.Stages == nil {
		return RunRef{}, errors.New("review stages are required")
	}
	id := in.RunID
	if id == "" {
		id = fmt.Sprintf("%s:%d", in.Repo, in.PRNumber)
	}
	in.RunID = id

	runCtx, cancel := context.WithCancel(ctx)
	entry := &runEntry{
		gen:    l.genSeq.Add(1),
		cancel: cancel,
		done:   make(chan struct{}),
	}

	l.mu.Lock()
	if prev := l.runs[id]; prev != nil && prev.cancel != nil {
		prev.cancel()
	}
	l.runs[id] = entry
	slot := l.tenantSlots[in.TenantID]
	if slot == nil {
		slot = make(chan struct{}, l.TenantLimit)
		l.tenantSlots[in.TenantID] = slot
	}
	l.mu.Unlock()

	l.persistDelivery(in, entry.gen, "queued", nil, nil)

	go func() {
		defer close(entry.done)
		select {
		case slot <- struct{}{}:
		case <-runCtx.Done():
			l.mu.Lock()
			entry.err = runCtx.Err()
			entry.cancel = nil
			l.mu.Unlock()
			l.persistDelivery(in, entry.gen, "canceled", nil, runCtx.Err())
			return
		}
		defer func() { <-slot }()

		l.persistDelivery(in, entry.gen, "running", nil, nil)
		out, err := l.execute(runCtx, in)

		l.mu.Lock()
		current := l.runs[id] == entry && runCtx.Err() == nil
		if err == nil && current {
			res := ReviewResult{Ref: RunRef{ID: id}, Output: out}
			entry.result = &res
		} else {
			entry.err = err
		}
		entry.cancel = nil
		l.mu.Unlock()

		if err == nil {
			l.persistDelivery(in, entry.gen, "completed", &out, nil)
		} else if errors.Is(err, context.Canceled) {
			l.persistDelivery(in, entry.gen, "canceled", nil, err)
		} else {
			l.persistDelivery(in, entry.gen, "failed", nil, err)
		}
	}()

	return RunRef{ID: id}, nil
}

func (l *LocalRunner) execute(ctx context.Context, in ReviewInput) (ReviewOutput, error) {
	var o ReviewOutput
	var err error
	o.Prepare, err = l.Stages.PreparePR(ctx, in)
	if err != nil {
		return o, err
	}
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		res, e := l.Stages.SandboxGates(gctx, in, o.Prepare)
		if e != nil {
			return e
		}
		o.Gates = res
		return nil
	})
	g.Go(func() error {
		res, e := l.Stages.GraphAndStatic(gctx, in, o.Prepare)
		if e != nil {
			return e
		}
		o.Graph = res
		return nil
	})
	if err = g.Wait(); err != nil {
		return o, err
	}
	o.Shards, err = l.Stages.ReviewShards(ctx, in, o.Prepare)
	if err != nil {
		return o, err
	}
	o.Consolidated, err = l.Stages.Consolidate(ctx, in, o.Gates, o.Graph, o.Shards)
	if err != nil {
		return o, err
	}
	if in.UIChecks {
		o.Browser, err = l.Stages.BrowserAndVisualQA(ctx, in, o.Consolidated)
		if err != nil {
			return o, err
		}
	}
	o.Published, err = l.Stages.PublishReview(ctx, in, o.Consolidated, o.Browser)
	return o, err
}

func (l *LocalRunner) Wait(ctx context.Context, ref RunRef) (ReviewResult, error) {
	l.mu.Lock()
	entry := l.runs[ref.ID]
	l.mu.Unlock()
	if entry == nil {
		if l.DB != nil {
			var blob []byte
			var status, errStr string
			err := l.DB.QueryRow(`SELECT status, result, error FROM deliveries WHERE run_id = ?`, ref.ID).Scan(&status, &blob, &errStr)
			if err == nil && status == "completed" && len(blob) > 0 {
				var out ReviewOutput
				if json.Unmarshal(blob, &out) == nil {
					return ReviewResult{Ref: ref, Output: out}, nil
				}
			}
			if err == nil && errStr != "" {
				return ReviewResult{}, errors.New(errStr)
			}
		}
		return ReviewResult{}, errors.New("run is not available")
	}

	select {
	case <-ctx.Done():
		return ReviewResult{}, ctx.Err()
	case <-entry.done:
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if entry.result != nil {
		return *entry.result, nil
	}
	if entry.err != nil {
		return ReviewResult{}, entry.err
	}
	return ReviewResult{}, errors.New("run finished without result")
}

func (l *LocalRunner) Replay(context.Context, RunRef, ...string) error {
	return errors.New("replay is not supported by local runner")
}

func (l *LocalRunner) Cancel(_ context.Context, ref RunRef) error {
	l.mu.Lock()
	entry := l.runs[ref.ID]
	var cancel context.CancelFunc
	if entry != nil {
		cancel = entry.cancel
	}
	l.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}
