package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AppConfig struct {
	AppID, PrivateKeyPEM, ClientID, ClientSecret, WebhookSecret, CallbackURL, SessionSecret string
	APIURL, OAuthURL                                                                        string
	HTTPClient                                                                              *http.Client
	LegacyToken                                                                             string
}

func MintAppJWT(appID string, key *rsa.PrivateKey, now time.Time) (string, error) {
	claims := jwt.RegisteredClaims{Issuer: appID, IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)), ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute))}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
}

type TokenResolver interface {
	Resolve(context.Context, int64, []string) (string, error)
}

type InstallationTokenCache struct {
	AppID        string
	Key          *rsa.PrivateKey
	APIURL       string
	Client       *http.Client
	SafetyMargin time.Duration
	mu           sync.Mutex
	cache        map[int64]cachedToken
}
type cachedToken struct {
	token  string
	expiry time.Time
	repos  map[string]bool
}

func NewInstallationTokenCache(appID string, key *rsa.PrivateKey, apiURL string, client *http.Client) *InstallationTokenCache {
	if client == nil {
		client = http.DefaultClient
	}
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	return &InstallationTokenCache{AppID: appID, Key: key, APIURL: strings.TrimRight(apiURL, "/"), Client: client, SafetyMargin: 2 * time.Minute, cache: map[int64]cachedToken{}}
}
func (c *InstallationTokenCache) Resolve(ctx context.Context, id int64, repos []string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	old, ok := c.cache[id]
	covered := ok && old.expiry.After(now.Add(c.SafetyMargin))
	for _, r := range repos {
		covered = covered && old.repos[r]
	}
	if covered {
		return old.token, nil
	}
	jwtToken, err := MintAppJWT(c.AppID, c.Key, now)
	if err != nil {
		return "", err
	}
	repoNames := make([]string, 0, len(repos))
	for _, r := range repos {
		name := r
		if _, after, ok := strings.Cut(r, "/"); ok && after != "" {
			name = after
		}
		if name != "" {
			repoNames = append(repoNames, name)
		}
	}
	payload := map[string]any{"permissions": map[string]string{"contents": "read", "pull_requests": "write", "checks": "write", "issues": "write"}}
	if len(repoNames) > 0 {
		payload["repositories"] = repoNames
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/app/installations/%d/access_tokens", c.APIURL, id), strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("installation token request: %s", resp.Status)
	}
	var data struct {
		Token   string    `json:"token"`
		Expires time.Time `json:"expires_at"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	if data.Token == "" {
		return "", errors.New("empty installation token")
	}
	set := map[string]bool{}
	for _, r := range repos {
		set[r] = true
	}
	c.cache[id] = cachedToken{data.Token, data.Expires, set}
	return data.Token, nil
}
func (c *InstallationTokenCache) Evict(id int64) { c.mu.Lock(); delete(c.cache, id); c.mu.Unlock() }

// ResolveToken fails closed in App mode. Legacy credentials are considered only when AppID is empty.
func ResolveToken(ctx context.Context, appMode bool, installationID int64, repos []string, resolver TokenResolver, legacy string) (string, error) {
	if appMode {
		if resolver == nil || installationID == 0 {
			return "", errors.New("GitHub App installation is required")
		}
		return resolver.Resolve(ctx, installationID, repos)
	}
	if legacy == "" {
		return "", errors.New("GitHub token is not configured")
	}
	return legacy, nil
}

type OAuthHandler struct {
	Config AppConfig
	Client *http.Client
}

func (h *OAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	switch r.URL.Path {
	case "/auth/github/login":
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			http.Error(w, "OAuth unavailable", 500)
			return
		}
		state := base64.RawURLEncoding.EncodeToString(b)
		http.SetCookie(w, &http.Cookie{Name: "github_oauth_state", Value: state, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
		base := h.Config.OAuthURL
		if base == "" {
			base = "https://github.com"
		}
		target := strings.TrimRight(base, "/") + "/login/oauth/authorize?" + url.Values{"client_id": {h.Config.ClientID}, "redirect_uri": {h.Config.CallbackURL}, "state": {state}}.Encode()
		http.Redirect(w, r, target, http.StatusFound)
	case "/auth/github/callback":
		cookie, err := r.Cookie("github_oauth_state")
		if err != nil || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(r.URL.Query().Get("state"))) != 1 {
			http.Error(w, "Invalid OAuth state", 400)
			return
		}
		values := url.Values{"client_id": {h.Config.ClientID}, "client_secret": {h.Config.ClientSecret}, "code": {r.URL.Query().Get("code")}}
		req, _ := http.NewRequestWithContext(r.Context(), "POST", strings.TrimRight(h.Config.OAuthURL, "/")+"/login/oauth/access_token", strings.NewReader(values.Encode()))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "OAuth exchange failed", 502)
			return
		}
		defer resp.Body.Close()
		var tok struct {
			AccessToken string `json:"access_token"`
		}
		if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&tok) != nil || tok.AccessToken == "" {
			http.Error(w, "OAuth exchange failed", 502)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "github_oauth_state", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: "github_session", Value: tok.AccessToken, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 86400})
		http.Redirect(w, r, "/", http.StatusFound)
	case "/auth/me":
		cookie, err := r.Cookie("github_session")
		if err != nil {
			http.Error(w, "Not signed in", 401)
			return
		}
		apiURL := strings.TrimRight(h.Config.APIURL, "/")
		if apiURL == "" {
			apiURL = "https://api.github.com"
		}
		req, _ := http.NewRequestWithContext(r.Context(), "GET", apiURL+"/user", nil)
		req.Header.Set("Authorization", "Bearer "+cookie.Value)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "GitHub unavailable", 502)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	case "/auth/github/logout":
		http.SetCookie(w, &http.Cookie{Name: "github_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}
