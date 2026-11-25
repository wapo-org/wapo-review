package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/wapo-org/wapo-review/internal/githubapp"
	"github.com/wapo-org/wapo-review/internal/memory"
	"github.com/wapo-org/wapo-review/internal/orchestrator"
)

type recordingRunner struct {
	mu      sync.Mutex
	started []orchestrator.ReviewInput
}

func (r *recordingRunner) Start(_ context.Context, in orchestrator.ReviewInput) (orchestrator.RunRef, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started = append(r.started, in)
	return orchestrator.RunRef{ID: in.RunID}, nil
}
func (r *recordingRunner) Wait(context.Context, orchestrator.RunRef) (orchestrator.ReviewResult, error) {
	return orchestrator.ReviewResult{}, nil
}
func (r *recordingRunner) Replay(context.Context, orchestrator.RunRef, ...string) error { return nil }
func (r *recordingRunner) Cancel(context.Context, orchestrator.RunRef) error            { return nil }

func signBody(body []byte, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	healthHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if payload["status"] != "ok" || payload["version"] != version {
		t.Fatalf("unexpected health payload: %+v", payload)
	}
}

func TestServerWebhookSignatureDispatchAndReplyMemory(t *testing.T) {
	var replyPosted bool
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/org/repo/pulls/comments/10":
			_, _ = w.Write([]byte(`{"id":10,"user":{"login":"wapo-review[bot]"},"body":"<!-- wapo-review-finding:1 -->"}`))
		case r.Method == "POST" && r.URL.Path == "/repos/org/repo/pulls/5/comments/11/replies":
			replyPosted = true
			_, _ = w.Write([]byte(`{"id":12}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer gh.Close()

	runner := &recordingRunner{}
	memStore := memory.NewStore(t.TempDir())
	srv := NewServer(ServerConfig{
		WebhookSecret: "whsec",
		BotLogin:      "wapo-review[bot]",
		Runner:        runner,
		Client:        &githubapp.Client{BaseURL: gh.URL},
		LegacyToken:   "tok",
		Memory:        memStore,
	})

	// 1. Invalid signature -> 401
	badReq := httptest.NewRequest("POST", "/webhook", strings.NewReader(`{}`))
	badReq.Header.Set("X-GitHub-Event", "pull_request")
	badReq.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	badRec := httptest.NewRecorder()
	srv.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on invalid signature, got %d", badRec.Code)
	}

	// 2. Signed PR webhook -> dispatches coalesced repo:pr run
	prPayload := []byte(`{"action":"synchronize","repository":{"full_name":"org/repo"},"pull_request":{"number":5,"draft":false,"head":{"sha":"abc","repo":{"full_name":"org/repo"}}}}`)
	prReq := httptest.NewRequest("POST", "/webhooks/github", strings.NewReader(string(prPayload)))
	prReq.Header.Set("X-GitHub-Event", "pull_request")
	prReq.Header.Set("X-Hub-Signature-256", signBody(prPayload, "whsec"))
	prRec := httptest.NewRecorder()
	srv.ServeHTTP(prRec, prReq)
	if prRec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for PR webhook, got %d", prRec.Code)
	}
	if len(runner.started) != 1 || runner.started[0].RunID != "org/repo:5" || runner.started[0].PRNumber != 5 {
		t.Fatalf("unexpected dispatched run: %+v", runner.started)
	}

	// 3. Signed review comment reply -> stores memory note + posts reply
	replyPayload := []byte(`{"action":"created","repository":{"full_name":"org/repo"},"pull_request":{"number":5},"comment":{"id":11,"in_reply_to_id":10,"author_association":"MEMBER","user":{"login":"alice"},"body":"/remember Keep SQL queries parameterized"}}`)
	repReq := httptest.NewRequest("POST", "/webhook", strings.NewReader(string(replyPayload)))
	repReq.Header.Set("X-GitHub-Event", "pull_request_review_comment")
	repReq.Header.Set("X-Hub-Signature-256", signBody(replyPayload, "whsec"))
	repRec := httptest.NewRecorder()
	srv.ServeHTTP(repRec, repReq)
	if repRec.Code != http.StatusAccepted || !replyPosted {
		t.Fatalf("expected 202 and reply posted, code=%d posted=%v", repRec.Code, replyPosted)
	}
	notes, err := memStore.Load("org/repo")
	if err != nil || len(notes) != 1 || !strings.Contains(notes[0].Text, "parameterized") {
		t.Fatalf("expected memory saved from webhook reply, got %+v err=%v", notes, err)
	}
}
