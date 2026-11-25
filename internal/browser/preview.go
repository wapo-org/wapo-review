package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/wapo-org/wapo-review/internal/redact"
	"github.com/wapo-org/wapo-review/internal/secrets"
)

func isDisallowedHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return true
		}
	}
	return false
}

func isDisallowedResolvedHost(host string) bool {
	if isDisallowedHost(host) {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return true
	}
	for _, addr := range ips {
		ip := addr.IP
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return true
		}
	}
	return false
}

func PreviewProviderMatches(rawURL string, providerHosts ...string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, candidate := range providerHosts {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if host == candidate || strings.HasSuffix(host, "."+candidate) {
			return true
		}
	}
	return false
}

func ResolvePreviewURL(statuses, deployments, comments []string, baseURL string) (string, error) {
	u, _, err := ResolvePreviewTarget(statuses, deployments, comments, baseURL)
	return u, err
}

// ResolvePreviewTarget validates a preview URL and pins its hostname to one of
// the public addresses returned during validation.
func ResolvePreviewTarget(statuses, deployments, comments []string, baseURL string) (string, string, error) {
	all := make([]string, 0, len(statuses)+len(deployments)+len(comments)+1)
	all = append(all, statuses...)
	all = append(all, deployments...)
	all = append(all, comments...)
	all = append(all, baseURL)

	for _, candidate := range all {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		u, err := url.Parse(candidate)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			continue
		}
		if isDisallowedHost(u.Hostname()) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, u.Hostname())
		cancel()
		if lookupErr != nil || len(ips) == 0 {
			continue
		}
		valid := true
		for _, item := range ips {
			ip := item.IP
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
				valid = false
				break
			}
		}
		if valid {
			return u.String(), ips[0].IP.String(), nil
		}
	}
	return "", "", errors.New("no safe HTTPS preview URL found")
}

// ResolveVercelPreview queries the Vercel Deployments API for a READY preview
// matching headSHA using QAProfile.Vercel credentials (token + web_project_id).
func ResolveVercelPreview(ctx context.Context, profile *secrets.QAProfile, headSHA string) (string, map[string]string, error) {
	if profile == nil || headSHA == "" {
		return "", nil, errors.New("vercel preview lookup requires QA profile and head SHA")
	}
	token := strings.TrimSpace(profile.Vercel["token"])
	projectID := strings.TrimSpace(profile.Vercel["web_project_id"])
	if token == "" || projectID == "" {
		return "", nil, errors.New("vercel token or web_project_id not configured")
	}
	q := url.Values{
		"projectId": {projectID},
		"target":    {"preview"},
		"sha":       {headSHA},
		"state":     {"READY"},
	}
	if team := strings.TrimSpace(profile.Vercel["team_id"]); team != "" {
		q.Set("teamId", team)
	}
	endpoint := "https://api.vercel.com/v7/deployments?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("vercel deployments API returned HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Deployments []struct {
			UID        string `json:"uid"`
			URL        string `json:"url"`
			ProjectID  string `json:"projectId"`
			ReadyState string `json:"readyState"`
			State      string `json:"state"`
		} `json:"deployments"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", nil, err
	}
	for _, d := range payload.Deployments {
		state := d.ReadyState
		if state == "" {
			state = d.State
		}
		if d.ProjectID != projectID || state != "READY" || strings.TrimSpace(d.URL) == "" {
			continue
		}
		candidate := "https://" + strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(d.URL), "https://"), "http://")
		resolved, err := ResolvePreviewURL([]string{candidate}, nil, nil, "")
		if err != nil {
			continue
		}
		headers := map[string]string{}
		if bypass := strings.TrimSpace(profile.Vercel["web_bypass_secret"]); bypass != "" {
			headers["x-vercel-protection-bypass"] = bypass
		}
		return resolved, headers, nil
	}
	return "", nil, errors.New("no ready Vercel preview matched PR head SHA")
}

type SignInSpec struct {
	Persona  string
	Email    string
	Password string
	Secrets  map[string]string
}

func BuildAuthHeaders(ctx context.Context, profile *secrets.QAProfile, adapter secrets.Adapter, persona string, r *redact.Redactor) (map[string]string, error) {
	if profile == nil {
		return nil, errors.New("QA profile is required")
	}
	if r != nil {
		r.Register(profile.KnownValues()...)
	}
	vault := secrets.CollectSandboxVaultSecrets(ctx, profile, adapter)
	if r != nil {
		for _, v := range vault {
			r.Register(v)
		}
	}
	p, ok := profile.Personas[persona]
	if !ok {
		return nil, errors.New("QA persona not found")
	}
	return map[string]string{"X-QA-Email": p.Email, "X-QA-Password": p.Password}, nil
}

func StorageStatePath(runDir string) string { return filepath.Join(runDir, "storage-state.json") }
