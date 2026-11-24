package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"github.com/wapo-org/wapo-review/internal/redact"
)

type fakeTool struct {
	name string
	fn   func(ctx context.Context, args string) (string, error)
}

func (f *fakeTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: f.name, Desc: "test tool"}, nil
}

func (f *fakeTool) InvokableRun(ctx context.Context, args string, _ ...tool.Option) (string, error) {
	return f.fn(ctx, args)
}

type scriptedModel struct {
	responses []*schema.Message
	idx       int
	seenMsgs  [][]*schema.Message
}

func (m *scriptedModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func (m *scriptedModel) Generate(_ context.Context, msgs []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	copied := append([]*schema.Message(nil), msgs...)
	m.seenMsgs = append(m.seenMsgs, copied)
	if m.idx >= len(m.responses) {
		return nil, errors.New("no more scripted responses")
	}
	r := m.responses[m.idx]
	m.idx++
	return r, nil
}

func (m *scriptedModel) Stream(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return nil, errors.New("not implemented")
}

func TestOpenAICompatibleCustomBaseURLHeadersAndRetry(t *testing.T) {
	var attempts atomic.Int32
	var gotHeader string
	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		gotHeader = r.Header.Get("X-Custom-Router")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotModel, _ = body["model"].(string)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"message":"rate limit 429"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl-1",
			"object":"chat.completion",
			"created":1700000000,
			"model":"custom-model",
			"choices":[{"index":0,"message":{"role":"assistant","content":"ok-openai"},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}
		}`))
	}))
	defer srv.Close()

	m, err := NewModel(context.Background(), ProviderConfig{
		Protocol:        "openai",
		BaseURL:         srv.URL + "/v1",
		APIKey:          "sk-test",
		Model:           "custom-model",
		ReasoningEffort: "high",
		ExtraHeaders:    map[string]string{"X-Custom-Router": "wapo-test"},
		Retry:           RetryPolicy{MaxAttempts: 3, InitialBackoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("NewModel openai failed: %v", err)
	}
	msg, err := m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if msg.Content != "ok-openai" || attempts.Load() != 2 || gotHeader != "wapo-test" || gotModel != "custom-model" {
		t.Fatalf("unexpected result content=%q attempts=%d header=%q model=%q", msg.Content, attempts.Load(), gotHeader, gotModel)
	}
}

func TestOpenAIResponsesProxyWithToolCalls(t *testing.T) {
	var gotPath string
	var gotEffort string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if re, ok := body["reasoning"].(map[string]any); ok {
			gotEffort, _ = re["effort"].(string)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"output":[
				{"type":"function_call","call_id":"fc_1","name":"read_file","arguments":"{\"path\":\"a.go\"}"}
			],
			"usage":{"input_tokens":20,"output_tokens":7,"total_tokens":27,"input_tokens_details":{"cached_tokens":10}}
		}`))
	}))
	defer srv.Close()

	m, err := NewModel(context.Background(), ProviderConfig{
		Protocol:        "openai-responses",
		BaseURL:         srv.URL + "/v1",
		APIKey:          "sk-proxy",
		Model:           "gpt-6.2-sol",
		ReasoningEffort: "high",
	})
	if err != nil {
		t.Fatalf("NewModel openai-responses failed: %v", err)
	}
	bound, err := m.WithTools([]*schema.ToolInfo{{Name: "read_file", Desc: "read"}})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := bound.Generate(context.Background(), []*schema.Message{
		schema.SystemMessage("Be thorough."),
		schema.UserMessage("Check a.go"),
	})
	if err != nil {
		t.Fatalf("responses Generate failed: %v", err)
	}
	if gotPath != "/v1/responses" || gotEffort != "high" || len(msg.ToolCalls) != 1 || msg.ToolCalls[0].Function.Name != "read_file" {
		t.Fatalf("unexpected responses result path=%q effort=%q msg=%+v", gotPath, gotEffort, msg)
	}
	if msg.ResponseMeta.Usage.PromptTokenDetails.CachedTokens != 10 {
		t.Fatalf("expected cached tokens=10, got %+v", msg.ResponseMeta.Usage)
	}
}

func TestFlattenToolSchemaDereferencesRootRef(t *testing.T) {
	raw := []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"#/$defs/FindingDraft","$defs":{"FindingDraft":{"type":"object","properties":{"file":{"type":"string"},"start_line":{"type":"integer"}},"required":["file","start_line"]}}}`)
	flat := flattenToolSchema(raw)
	if _, hasRef := flat["$ref"]; hasRef {
		t.Fatalf("expected root $ref removed, got %+v", flat)
	}
	props, ok := flat["properties"].(map[string]any)
	if !ok || len(props) != 2 || props["file"] == nil || props["start_line"] == nil {
		t.Fatalf("expected flattened top-level properties, got %+v", flat)
	}
}

func TestAnthropicCompatibleCustomBaseURLCacheAndThinking(t *testing.T) {
	var attempts atomic.Int32
	var gotHeader string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		gotHeader = r.Header.Get("X-Anthropic-Proxy")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		if n == 1 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":{"type":"overloaded_error","message":"502"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"msg_1",
			"type":"message",
			"role":"assistant",
			"model":"claude-custom",
			"content":[{"type":"text","text":"ok-anthropic"}],
			"stop_reason":"end_turn",
			"usage":{"input_tokens":12,"output_tokens":6}
		}`))
	}))
	defer srv.Close()

	m, err := NewModel(context.Background(), ProviderConfig{
		Protocol:        "anthropic",
		BaseURL:         srv.URL,
		APIKey:          "ant-test",
		Model:           "claude-custom",
		ReasoningEffort: "medium",
		PromptCache:     true,
		ExtraHeaders:    map[string]string{"X-Anthropic-Proxy": "yes"},
		Retry:           RetryPolicy{MaxAttempts: 3, InitialBackoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("NewModel anthropic failed: %v", err)
	}
	msg, err := m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hello")})
	if err != nil {
		t.Fatalf("Generate anthropic failed: %v", err)
	}
	if msg.Content != "ok-anthropic" || attempts.Load() != 2 || gotHeader != "yes" {
		t.Fatalf("unexpected anthropic result content=%q attempts=%d header=%q", msg.Content, attempts.Load(), gotHeader)
	}
	if _, ok := gotBody["thinking"]; !ok {
		t.Fatalf("expected thinking config in anthropic request body, got %+v", gotBody)
	}
}

func TestReviewLoopGuardsNudgesRedactionAndToolRecovery(t *testing.T) {
	red := redact.New()
	red.Register("super-secret-val")

	sm := &scriptedModel{
		responses: []*schema.Message{
			// Turn 1: tries to finish early without calling required tool -> nudged.
			{Role: schema.Assistant, Content: "done early", ResponseMeta: &schema.ResponseMeta{Usage: &schema.TokenUsage{PromptTokens: 10, CompletionTokens: 3, TotalTokens: 13}}},
			// Turn 2: calls tool with bad args -> tool returns error, loop feeds error back instead of aborting.
			{Role: schema.Assistant, ToolCalls: []schema.ToolCall{{ID: "c1", Function: schema.FunctionCall{Name: "run_check", Arguments: `{"bad":true,"secret":"super-secret-val"}`}}}},
			// Turn 3: calls tool cleanly -> succeeds and marks item done.
			{Role: schema.Assistant, ToolCalls: []schema.ToolCall{{ID: "c2", Function: schema.FunctionCall{Name: "run_check", Arguments: `{"item":"a.go"}`}}}},
			// Turn 4: finishes cleanly with fenced JSON.
			{Role: schema.Assistant, Content: "```json\n{\"ok\":true}\n```", ResponseMeta: &schema.ResponseMeta{Usage: &schema.TokenUsage{PromptTokens: 20, CompletionTokens: 8, TotalTokens: 28}}},
		},
	}

	loop := &ReviewLoop{
		Model:        sm,
		SystemPrompt: "You are a reviewer.",
		Tools: []tool.InvokableTool{
			&fakeTool{
				name: "run_check",
				fn: func(_ context.Context, args string) (string, error) {
					if strings.Contains(args, `"bad":true`) {
						return "", errors.New("invalid argument: super-secret-val")
					}
					return `{"status":"ok","leak":"super-secret-val"}`, nil
				},
			},
		},
		Guards:    []CompletionGuard{RequireToolCalled("run_check"), RequireAllItemsCompleted([]string{"a.go"})},
		MaxTurns:  6,
		MaxNudges: 2,
		Redactor:  red,
		OnToolResult: func(rec ToolRecord, ev *ReviewEvidence) {
			if rec.Error == "" && strings.Contains(rec.Arguments, "a.go") {
				ev.CompletedItems["a.go"] = true
			}
		},
	}

	res, err := loop.Run(context.Background(), "review a.go")
	if err != nil {
		t.Fatalf("ReviewLoop.Run failed: %v", err)
	}
	if res.Nudges != 1 || res.Usage.TurnCount != 4 || res.Usage.TotalTokens != 41 {
		t.Fatalf("unexpected loop stats: nudges=%d usage=%+v", res.Nudges, res.Usage)
	}
	// Verify redaction on recorded tool args, results, and errors.
	for _, turn := range res.Turns {
		for _, rec := range turn.ToolRecords {
			if strings.Contains(rec.Arguments+rec.Result+rec.Error, "super-secret-val") {
				t.Fatalf("secret leaked in ToolRecord: %+v", rec)
			}
		}
	}
	var parsed struct {
		OK bool `json:"ok"`
	}
	parsed, err = DecodeOutput[struct {
		OK bool `json:"ok"`
	}](res.Output)
	if err != nil || !parsed.OK {
		t.Fatalf("DecodeOutput failed: %v parsed=%+v", err, parsed)
	}
}

func TestSkillLoaderAndCappedTool(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "SKILL.md")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "go-review"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go-review", "SKILL.md"), []byte("# Go Review\nCheck errors."), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "escape"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape", "SKILL.md")); err != nil {
		t.Fatal(err)
	}

	loader := SkillLoader{Directory: dir}
	skills, err := loader.Load("go-review")
	if err != nil || len(skills) != 1 || !strings.Contains(FormatSkills(skills), `<skill name="go-review">`) {
		t.Fatalf("Load/FormatSkills failed: err=%v skills=%+v", err, skills)
	}
	if _, err := loader.Load("escape"); err == nil {
		t.Fatal("expected symlink escape skill to be rejected")
	}
	if _, err := loader.Load("../escape"); err == nil {
		t.Fatal("expected traversal skill name to be rejected")
	}

	ct := &cappedTool{
		InvokableTool: &fakeTool{
			name: "big",
			fn:   func(context.Context, string) (string, error) { return strings.Repeat("a", 100), nil },
		},
		limit: 20,
	}
	out, err := ct.InvokableRun(context.Background(), `{}`)
	if err != nil || !strings.Contains(out, "[output truncated at 20 bytes]") {
		t.Fatalf("expected cappedTool truncation, got %q err=%v", out, err)
	}
}
