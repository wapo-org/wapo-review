package review

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"github.com/wapo-org/wapo-review/internal/githubapp"
	"github.com/wapo-org/wapo-review/internal/graph"
	"github.com/wapo-org/wapo-review/internal/memory"
	"github.com/wapo-org/wapo-review/internal/orchestrator"
	"github.com/wapo-org/wapo-review/internal/sandbox"
)

type scriptedModel struct {
	mu        sync.Mutex
	responses []*schema.Message
	idx       int
}

func (m *scriptedModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}
func (m *scriptedModel) Generate(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx >= len(m.responses) {
		return &schema.Message{Role: schema.Assistant, Content: "done"}, nil
	}
	r := m.responses[m.idx]
	m.idx++
	return r, nil
}
func (m *scriptedModel) Stream(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return nil, errors.New("not implemented")
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func TestEndToEndReviewPipelineWithLocalRunnerAndMockGitHub(t *testing.T) {
	bare := filepath.Join(t.TempDir(), "origin.git")
	seed := filepath.Join(t.TempDir(), "seed")
	_ = os.MkdirAll(bare, 0o755)
	_ = os.MkdirAll(seed, 0o755)

	runGit(t, bare, "init", "--bare", "-q")
	runGit(t, seed, "init", "-q", "-b", "main")
	runGit(t, seed, "remote", "add", "origin", bare)

	// Base commit: trusted .wapo-review.yml with max_critical=0
	_ = os.WriteFile(filepath.Join(seed, ".wapo-review.yml"), []byte("quality_gate:\n  max_critical: 0\n  max_high: 0\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(seed, "src"), 0o755)
	_ = os.WriteFile(filepath.Join(seed, "src", "auth.ts"), []byte("export function check(t: string) {\n  return t.length > 0;\n}\n"), 0o644)
	runGit(t, seed, "add", ".")
	runGit(t, seed, "commit", "-q", "-m", "base")
	baseSHA := runGit(t, seed, "rev-parse", "HEAD")
	runGit(t, seed, "push", "-q", "origin", "main")

	// PR branch introduces bug AND attempts to weaken .wapo-review.yml (must be ignored!).
	runGit(t, seed, "checkout", "-q", "-b", "feat")
	_ = os.WriteFile(filepath.Join(seed, ".wapo-review.yml"), []byte("quality_gate:\n  max_critical: 999\n"), 0o644)
	_ = os.WriteFile(filepath.Join(seed, "src", "auth.ts"), []byte("export function check(t: string) {\n  if (t === \"\") return true;\n  return t.length > 0;\n}\n"), 0o644)
	runGit(t, seed, "commit", "-q", "-am", "pr change")
	headSHA := runGit(t, seed, "rev-parse", "HEAD")
	runGit(t, seed, "push", "-q", "origin", "HEAD:refs/pull/12/head")

	var mu sync.Mutex
	var checkRunPayload map[string]any
	var reviewPayload map[string]any

	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/org/app/pulls/12":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"number": 12,
				"state":  "open",
				"merged": false,
				"head":   map[string]any{"sha": headSHA},
				"base":   map[string]any{"ref": "main", "sha": baseSHA},
			})
		case r.Method == "GET" && r.URL.Path == "/repos/org/app/pulls/12/files":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"filename": "src/auth.ts",
					"status":   "modified",
					"patch":    "@@ -1,3 +1,4 @@\n export function check(t: string) {\n+  if (t === \"\") return true;\n   return t.length > 0;\n }",
				},
			})
		case r.Method == "POST" && r.URL.Path == "/repos/org/app/check-runs":
			_ = json.NewDecoder(r.Body).Decode(&checkRunPayload)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":501}`))
		case r.Method == "POST" && r.URL.Path == "/repos/org/app/pulls/12/reviews":
			_ = json.NewDecoder(r.Body).Decode(&reviewPayload)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":901}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer gh.Close()

	// Scripted shard model submits verified finding on line 2, posts lead, marks file reviewed.
	shardModel := &scriptedModel{
		responses: []*schema.Message{
			{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
				{ID: "c1", Function: schema.FunctionCall{
					Name:      "submit_finding",
					Arguments: `{"file":"src/auth.ts","start_line":2,"end_line":2,"severity":"high","category":"security","title":"Auth bypass on empty token","body":"Empty string returns true instead of rejecting.","evidence_quote":"if (t === \"\") return true;","confidence":"high"}`,
				}},
				{ID: "c2", Function: schema.FunctionCall{
					Name:      "mark_file_reviewed",
					Arguments: `{"file":"src/auth.ts"}`,
				}},
			}},
			{Role: schema.Assistant, Content: "Shard 1 finished reviewing src/auth.ts"},
		},
	}

	pipe := &Pipeline{
		Client:            &githubapp.Client{BaseURL: gh.URL},
		LegacyToken:       "test-token",
		RemoteURLOverride: "file://" + bare,
		ProfilerCache:     graph.NewProfilerCache(t.TempDir()),
		Memory:            memory.NewStore(t.TempDir()),
		SkipDepInstall:    true,
		GateSpecs:         []sandbox.GateSpec{{ID: "smoke", Command: []string{"sh", "-c", "exit 0"}}},
		ModelFactory: func(context.Context) (model.ToolCallingChatModel, error) {
			return shardModel, nil
		},
	}

	runner := orchestrator.NewLocalRunner(pipe, 4, 2, nil)
	ref, err := runner.Start(context.Background(), orchestrator.ReviewInput{
		Version:  1,
		RunID:    "org/app:12",
		TenantID: "org",
		Repo:     "org/app",
		PRNumber: 12,
		Trigger:  "pull_request",
		UIChecks: false,
	})
	if err != nil {
		t.Fatalf("runner.Start failed: %v", err)
	}
	res, err := runner.Wait(context.Background(), ref)
	if err != nil {
		t.Fatalf("runner.Wait failed: %v", err)
	}
	if res.Output.Published.Status != "published" {
		t.Fatalf("expected published status, got %+v", res.Output.Published)
	}

	mu.Lock()
	defer mu.Unlock()
	if checkRunPayload == nil || checkRunPayload["status"] != "completed" {
		t.Fatalf("expected atomic completed check run, got %+v", checkRunPayload)
	}
	if reviewPayload == nil || reviewPayload["event"] != "REQUEST_CHANGES" {
		t.Fatalf("expected REQUEST_CHANGES review for high finding, got %+v", reviewPayload)
	}
	comments, _ := reviewPayload["comments"].([]any)
	if len(comments) != 1 {
		t.Fatalf("expected 1 inline comment, got %+v", reviewPayload["comments"])
	}
	c0, _ := comments[0].(map[string]any)
	if c0["path"] != "src/auth.ts" || !strings.Contains(c0["body"].(string), "<!-- wapo-review-finding:") {
		t.Fatalf("expected inline comment with bot marker on src/auth.ts, got %+v", c0)
	}
}

func TestHandleReviewCommentReplyStoresMemoryAndReplies(t *testing.T) {
	var replyBody string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/org/app/pulls/comments/10":
			_, _ = w.Write([]byte(`{"id":10,"user":{"login":"wapo-review[bot]"},"body":"Finding <!-- wapo-review-finding:abc -->"}`))
		case r.Method == "POST" && r.URL.Path == "/repos/org/app/pulls/12/comments/11/replies":
			var p map[string]string
			_ = json.NewDecoder(r.Body).Decode(&p)
			replyBody = p["body"]
			_, _ = w.Write([]byte(`{"id":12}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer gh.Close()

	store := memory.NewStore(t.TempDir())
	ev := githubapp.WebhookEvent{Name: "pull_request_review_comment", Action: "created"}
	ev.Repository.FullName = "org/app"
	ev.PullRequest.Number = 12
	ev.Comment.ID = 11
	ev.Comment.InReplyTo = 10
	ev.Comment.Body = "/remember Always use test-model-alpha for streaming checks"

	err := HandleReviewCommentReply(context.Background(), &githubapp.Client{BaseURL: gh.URL, Token: "tok"}, store, ev)
	if err != nil {
		t.Fatalf("HandleReviewCommentReply failed: %v", err)
	}
	notes, err := store.Load("org/app")
	if err != nil || len(notes) != 1 || !strings.Contains(notes[0].Text, "test-model-alpha") {
		t.Fatalf("expected stored memory note, got %+v err=%v", notes, err)
	}
	if !strings.Contains(replyBody, "Noted for future reviews") {
		t.Fatalf("expected confirmation reply posted, got %q", replyBody)
	}
}
