package githubapp

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type WebhookEvent struct {
	Name         string `json:"-"`
	Action       string `json:"action"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Issue struct {
		Number      int              `json:"number"`
		PullRequest *json.RawMessage `json:"pull_request"`
		User        struct {
			Login string `json:"login"`
		} `json:"user"`
		Body string `json:"body"`
	} `json:"issue"`
	Comment struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
		User struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"user"`
		InReplyTo int64 `json:"in_reply_to_id"`
	} `json:"comment"`
	PullRequest struct {
		Number int  `json:"number"`
		Draft  bool `json:"draft"`
		Head   struct {
			SHA  string `json:"sha"`
			Repo *struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
}

func VerifyWebhookSignature(body []byte, signature, secret string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)
	return len(got) == len(expected) && subtle.ConstantTimeCompare(got, expected) == 1
}

type WebhookHandler struct {
	Secret      string
	Secrets     []string
	AppMode     bool
	BotLogin    string
	Handle      func(WebhookEvent)
	HandleError func(WebhookEvent) error
}

func (h WebhookHandler) verifyAny(body []byte, sig string) bool {
	if h.Secret != "" && VerifyWebhookSignature(body, sig, h.Secret) {
		return true
	}
	for _, s := range h.Secrets {
		if s != "" && VerifyWebhookSignature(body, sig, s) {
			return true
		}
	}
	return false
}

func (h WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const maxBody = 10 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if len(body) > maxBody {
		http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil || !h.verifyAny(body, r.Header.Get("X-Hub-Signature-256")) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}
	var e WebhookEvent
	if json.Unmarshal(body, &e) != nil {
		http.Error(w, "Invalid payload", 400)
		return
	}
	e.Name = r.Header.Get("X-GitHub-Event")
	if h.AppMode && e.Installation.ID == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if e.Name == "pull_request" && (e.PullRequest.Draft || e.PullRequest.Head.Repo == nil || e.PullRequest.Head.Repo.FullName != e.Repository.FullName) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if e.Name == "issue_comment" && (e.Issue.PullRequest == nil || isBot(e.Comment.User.Login, e.Comment.User.Type) || !hasSlashCommand(e.Comment.Body)) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if e.Name == "pull_request_review_comment" && (h.BotLogin == "" || e.Comment.User.Login == h.BotLogin || isBot(e.Comment.User.Login, e.Comment.User.Type) || e.Comment.InReplyTo == 0) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if h.HandleError != nil {
		if err := h.HandleError(e); err != nil {
			http.Error(w, "Failed to start review", http.StatusInternalServerError)
			return
		}
	} else if h.Handle != nil {
		h.Handle(e)
	}
	w.WriteHeader(http.StatusAccepted)
}

func isBot(login, userType string) bool {
	return strings.EqualFold(userType, "Bot") || strings.HasSuffix(strings.ToLower(login), "[bot]")
}

func hasSlashCommand(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "/wapo-review" || strings.HasPrefix(line, "/wapo-review ") || strings.HasPrefix(line, "/wapo-review\t") {
			return true
		}
	}
	return false
}
