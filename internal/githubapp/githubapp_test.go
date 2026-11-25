package githubapp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func jwtParse(token string, key *rsa.PublicKey) (string, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) { return key, nil }, jwt.WithTimeFunc(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		return "", err
	}
	claims := parsed.Claims.(jwt.MapClaims)
	v, _ := claims["iss"].(string)
	return v, nil
}
func webhookMAC(body []byte, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func TestMintAppJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token, err := MintAppJWT("123", key, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwtParse(token, &key.PublicKey)
	if err != nil || parsed != "123" {
		t.Fatalf("issuer=%q err=%v", parsed, err)
	}
}

func TestWebhookSignatureAndAppInstallationFilter(t *testing.T) {
	body := []byte(`{"installation":{"id":1}}`)
	sig := webhookMAC(body, "secret")
	if !VerifyWebhookSignature(body, sig, "secret") || VerifyWebhookSignature(body, sig, "wrong") {
		t.Fatal("signature verification failed")
	}
	called := false
	h := WebhookHandler{Secret: "secret", AppMode: true, Handle: func(WebhookEvent) { called = true }}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"action":"created"}`))
	r.Header.Set("X-Hub-Signature-256", webhookMAC([]byte(`{"action":"created"}`), "secret"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted || called {
		t.Fatalf("status=%d called=%v", w.Code, called)
	}
}

func TestMergedPullRequestUsesBaseSHA(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"state":"closed","merged":true,"base":{"ref":"main","sha":"base-sha"}}`))
	}))
	defer s.Close()
	_, base, err := (&Client{BaseURL: s.URL}).GetPullRequest(context.Background(), "a/b", 7)
	if err != nil || base != "base-sha" {
		t.Fatalf("base=%q err=%v", base, err)
	}
}

func TestSubmitReviewPreservesRequestChangesOn422(t *testing.T) {
	var events []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body strings.Builder
		buf := make([]byte, 1024)
		for {
			n, _ := r.Body.Read(buf)
			if n > 0 {
				body.Write(buf[:n])
			} else {
				break
			}
		}
		if strings.Contains(body.String(), `"REQUEST_CHANGES"`) {
			events = append(events, "REQUEST_CHANGES")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":1}`))
			return
		}
		events = append(events, "COMMENT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer s.Close()
	c := &Client{BaseURL: s.URL, Token: "tok"}
	if err := c.SubmitReview(context.Background(), "a/b", 7, "headsha", "REQUEST_CHANGES", "body", nil); err != nil {
		t.Fatalf("SubmitReview failed: %v", err)
	}
	if len(events) != 1 || events[0] != "REQUEST_CHANGES" {
		t.Fatalf("expected REQUEST_CHANGES to be preserved, got %v", events)
	}
}

func TestCreateCompletedCheckRunFallbackAndChunkedPatchRetry(t *testing.T) {
	// 1. 422 fallback without annotations.
	postCalls := 0
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postCalls++
		if postCalls == 1 {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message":"Invalid annotation line"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":99}`))
	}))
	defer s1.Close()
	id, err := (&Client{BaseURL: s1.URL}).CreateCompletedCheckRun(context.Background(), "a/b", "Wapo Gate", "head", "failure", "Gate", "sum", []Annotation{
		{Path: "./a.go", StartLine: 0, EndLine: 0, Level: "failure", Message: "bad"},
	})
	if err != nil || id != 99 || postCalls != 3 {
		t.Fatalf("422 fallback failed: id=%d posts=%d err=%v", id, postCalls, err)
	}

	// 2. >50 annotations chunked PATCH with 404 retry.
	patchCalls := 0
	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":101}`))
			return
		}
		patchCalls++
		if patchCalls == 1 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":101}`))
	}))
	defer s2.Close()
	anns := make([]Annotation, 55)
	for i := range anns {
		anns[i] = Annotation{Path: "a.go", StartLine: i + 1, EndLine: i + 1, Level: "warning", Message: "m"}
	}
	id2, err := (&Client{BaseURL: s2.URL}).CreateCompletedCheckRun(context.Background(), "a/b", "Wapo Gate", "head", "success", "Gate", "sum", anns)
	if err != nil || id2 != 101 || patchCalls != 2 {
		t.Fatalf("chunked patch retry failed: id=%d patches=%d err=%v", id2, patchCalls, err)
	}
}

func TestCreateCompletedCheckRunReplaysFirstAnnotationChunkAfter422(t *testing.T) {
	var postAnnotations bool
	var replayed int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var payload struct {
				Output struct {
					Annotations []Annotation `json:"annotations"`
				} `json:"output"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if len(payload.Output.Annotations) > 0 && !postAnnotations {
				postAnnotations = true
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":9}`))
			return
		}
		var payload struct {
			Output struct {
				Annotations []Annotation `json:"annotations"`
			} `json:"output"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		replayed += len(payload.Output.Annotations)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":9}`))
	}))
	defer s.Close()
	_, err := (&Client{BaseURL: s.URL}).CreateCompletedCheckRun(context.Background(), "a/b", "check", "head", "success", "title", "summary", []Annotation{{Path: "a.go", StartLine: 1, EndLine: 1, Message: "first"}})
	if err != nil || replayed != 1 {
		t.Fatalf("first annotation chunk lost: replayed=%d err=%v", replayed, err)
	}
}

func TestWebhookRoutingFiltersDraftForkAndAllowsCommandsAndReplies(t *testing.T) {
	var seen []string
	h := WebhookHandler{
		Secret:   "sec",
		BotLogin: "wapo-review[bot]",
		Handle:   func(e WebhookEvent) { seen = append(seen, e.Name+":"+e.Action) },
	}
	send := func(ev, payload string) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(payload))
		req.Header.Set("X-GitHub-Event", ev)
		req.Header.Set("X-Hub-Signature-256", webhookMAC([]byte(payload), "sec"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusAccepted {
			t.Fatalf("event %s got status %d", ev, w.Code)
		}
	}
	// Draft PR ignored
	send("pull_request", `{"action":"opened","repository":{"full_name":"a/b"},"pull_request":{"number":1,"draft":true,"head":{"repo":{"full_name":"a/b"}}}}`)
	// Fork PR ignored
	send("pull_request", `{"action":"opened","repository":{"full_name":"a/b"},"pull_request":{"number":2,"draft":false,"head":{"repo":{"full_name":"fork/b"}}}}`)
	// Same-repo non-draft PR accepted
	send("pull_request", `{"action":"synchronize","repository":{"full_name":"a/b"},"pull_request":{"number":3,"draft":false,"head":{"repo":{"full_name":"a/b"}}}}`)
	// /wapo-review comment on PR accepted
	send("issue_comment", `{"action":"created","repository":{"full_name":"a/b"},"issue":{"number":3,"pull_request":{}},"comment":{"body":"/wapo-review focus on auth"}}`)
	// Human reply to bot review comment accepted
	send("pull_request_review_comment", `{"action":"created","repository":{"full_name":"a/b"},"comment":{"id":5,"in_reply_to_id":4,"user":{"login":"alice"},"body":"always use Muse Ember"}}`)

	got := strings.Join(seen, ",")
	want := "pull_request:synchronize,issue_comment:created,pull_request_review_comment:created"
	if got != want {
		t.Fatalf("webhook routing got %q, want %q", got, want)
	}
}
