package orchestrator

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type stubStages struct {
	mu           sync.Mutex
	order        []string
	browserRan   atomic.Bool
	prepareBlock chan struct{}
	prepareHit   chan struct{}
	startedCount atomic.Int32
}

func (s *stubStages) record(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.order = append(s.order, name)
}

func (s *stubStages) PreparePR(ctx context.Context, in ReviewInput) (StageResult, error) {
	n := s.startedCount.Add(1)
	s.record("prepare:" + in.Trigger)
	if s.prepareHit != nil && n == 1 {
		close(s.prepareHit)
	}
	if s.prepareBlock != nil && n == 1 {
		select {
		case <-ctx.Done():
			return StageResult{}, ctx.Err()
		case <-s.prepareBlock:
		}
	}
	return StageResult{Version: 1, Status: "ok", Data: map[string]any{"trigger": in.Trigger}}, nil
}

func (s *stubStages) SandboxGates(context.Context, ReviewInput, StageResult) (StageResult, error) {
	s.record("gates")
	return StageResult{Version: 1, Status: "passed"}, nil
}

func (s *stubStages) GraphAndStatic(context.Context, ReviewInput, StageResult) (StageResult, error) {
	s.record("graph")
	return StageResult{Version: 1, Status: "ok"}, nil
}

func (s *stubStages) ReviewShards(context.Context, ReviewInput, StageResult) ([]StageResult, error) {
	s.record("shards")
	return []StageResult{{Version: 1, Status: "ok"}}, nil
}

func (s *stubStages) Consolidate(context.Context, ReviewInput, StageResult, StageResult, []StageResult) (StageResult, error) {
	s.record("consolidate")
	return StageResult{Version: 1, Status: "ok"}, nil
}

func (s *stubStages) BrowserAndVisualQA(context.Context, ReviewInput, StageResult) (StageResult, error) {
	s.browserRan.Store(true)
	s.record("browser")
	return StageResult{Version: 1, Status: "ok"}, nil
}

func (s *stubStages) PublishReview(context.Context, ReviewInput, StageResult, StageResult) (StageResult, error) {
	s.record("publish")
	return StageResult{Version: 1, Status: "published"}, nil
}

func TestLocalRunnerFullDAGAndSQLitePersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "queue.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	st := &stubStages{}
	r := NewLocalRunner(st, 4, 2, db)

	ref, err := r.Start(context.Background(), ReviewInput{
		Version:  1,
		RunID:    "run-1",
		TenantID: "t1",
		Repo:     "org/repo",
		PRNumber: 42,
		Trigger:  "opened",
		UIChecks: true,
	})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	res, err := r.Wait(context.Background(), ref)
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
	if !st.browserRan.Load() || res.Output.Published.Status != "published" {
		t.Fatalf("expected browser & publish completed, got %+v", res.Output)
	}

	// Verify fresh LocalRunner against same SQLite DB can read persisted result.
	r2 := NewLocalRunner(st, 4, 2, db)
	persisted, err := r2.Wait(context.Background(), ref)
	if err != nil || persisted.Output.Published.Status != "published" {
		t.Fatalf("expected persisted delivery loaded from SQLite, got %+v err=%v", persisted, err)
	}
}

func TestLocalRunnerCoalescingCancelsSupersededRun(t *testing.T) {
	st := &stubStages{
		prepareBlock: make(chan struct{}),
		prepareHit:   make(chan struct{}),
	}
	r := NewLocalRunner(st, 4, 2, nil)

	ref1, err := r.Start(context.Background(), ReviewInput{
		TenantID: "t1", Repo: "org/repo", PRNumber: 7, Trigger: "old",
	})
	if err != nil {
		t.Fatal(err)
	}
	<-st.prepareHit

	// Start superseding run for the same PR -> cancels old run, completes new run cleanly.
	ref2, err := r.Start(context.Background(), ReviewInput{
		TenantID: "t1", Repo: "org/repo", PRNumber: 7, Trigger: "new",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref1.ID != ref2.ID {
		t.Fatalf("expected same coalesced RunID, got %s vs %s", ref1.ID, ref2.ID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := r.Wait(ctx, ref2)
	if err != nil {
		t.Fatalf("expected superseding run to succeed, got err=%v", err)
	}
	if res.Output.Prepare.Data["trigger"] != "new" {
		t.Fatalf("expected trigger=new, got %+v", res.Output.Prepare.Data)
	}
}

func TestLocalRunnerCancelAndSkipUIChecks(t *testing.T) {
	st := &stubStages{
		prepareBlock: make(chan struct{}),
		prepareHit:   make(chan struct{}),
	}
	r := NewLocalRunner(st, 4, 1, nil)
	ref, err := r.Start(context.Background(), ReviewInput{
		RunID: "cancel-me", TenantID: "t1", Repo: "org/repo", PRNumber: 9,
	})
	if err != nil {
		t.Fatal(err)
	}
	<-st.prepareHit
	if err := r.Cancel(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	_, err = r.Wait(context.Background(), ref)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled after Cancel, got %v", err)
	}

	st2 := &stubStages{}
	r2 := NewLocalRunner(st2, 4, 1, nil)
	ref2, err := r2.Start(context.Background(), ReviewInput{
		RunID: "no-ui", TenantID: "t1", Repo: "org/repo", PRNumber: 10, UIChecks: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Wait(context.Background(), ref2); err != nil {
		t.Fatal(err)
	}
	if st2.browserRan.Load() {
		t.Fatal("browser QA should not run when UIChecks=false")
	}
}

func TestRegisterHatchetValidation(t *testing.T) {
	if _, err := RegisterHatchet(nil, &stubStages{}, 2); err == nil {
		t.Fatal("expected error when Hatchet client is nil")
	}
}
