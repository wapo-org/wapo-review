package githubapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL, Token string
	HTTP           *http.Client
}
type PullRequest struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	State  string `json:"state"`
	Merged bool   `json:"merged"`
	Head   struct {
		SHA string `json:"sha"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	} `json:"base"`
}
type File struct {
	Filename string `json:"filename"`
	Status   string `json:"status"`
	Patch    string `json:"patch"`
}
type Annotation struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Level     string `json:"annotation_level"`
	Message   string `json:"message"`
	Title     string `json:"title,omitempty"`
	Details   string `json:"raw_details,omitempty"`
}

func (c *Client) request(ctx context.Context, method, path string, payload any) (*http.Response, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	var body io.Reader
	if payload != nil {
		b, e := json.Marshal(payload)
		if e != nil {
			return nil, e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, base+path, body)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	cl := c.HTTP
	if cl == nil {
		cl = &http.Client{CheckRedirect: refuseCrossOriginRedirect}
	} else if cl.CheckRedirect == nil {
		copy := *cl
		copy.CheckRedirect = refuseCrossOriginRedirect
		cl = &copy
	}
	return cl.Do(req)
}
func refuseCrossOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 0 && !strings.EqualFold(req.URL.Scheme, via[0].URL.Scheme) || len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		return http.ErrUseLastResponse
	}
	if len(via) >= 10 {
		return fmt.Errorf("too many redirects")
	}
	return nil
}
func decodeResponse(resp *http.Response, dst any) error {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("GitHub API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	if dst == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}
func (c *Client) GetPullRequest(ctx context.Context, repo string, n int) (PullRequest, string, error) {
	var p PullRequest
	r, e := c.request(ctx, "GET", fmt.Sprintf("/repos/%s/pulls/%d", repo, n), nil)
	if e != nil {
		return p, "", e
	}
	e = decodeResponse(r, &p)
	base := "origin/" + p.Base.Ref
	if p.Merged || p.State != "open" {
		base = p.Base.SHA
	}
	return p, base, e
}
func (c *Client) ListPullRequestFiles(ctx context.Context, repo string, n int) ([]File, error) {
	var all []File
	for page := 1; ; page++ {
		q := url.Values{"per_page": {"100"}, "page": {fmt.Sprint(page)}}
		r, e := c.request(ctx, "GET", fmt.Sprintf("/repos/%s/pulls/%d/files?%s", repo, n, q.Encode()), nil)
		if e != nil {
			return nil, e
		}
		var batch []File
		if e = decodeResponse(r, &batch); e != nil {
			return nil, e
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			return all, nil
		}
	}
}
func (c *Client) CompareFiles(ctx context.Context, repo, base, head string) ([]File, error) {
	r, e := c.request(ctx, "GET", fmt.Sprintf("/repos/%s/compare/%s...%s", repo, base, head), nil)
	if e != nil {
		return nil, e
	}
	var out struct {
		Files []File `json:"files"`
	}
	if e = decodeResponse(r, &out); e != nil {
		return nil, e
	}
	return out.Files, nil
}
func (c *Client) SubmitReview(ctx context.Context, repo string, n int, head, event, body string, comments []map[string]any) error {
	payload := map[string]any{"commit_id": head, "event": event, "body": body}
	if len(comments) > 0 {
		payload["comments"] = comments
	}
	r, e := c.request(ctx, "POST", fmt.Sprintf("/repos/%s/pulls/%d/reviews", repo, n), payload)
	if e != nil {
		return e
	}
	if r.StatusCode == 422 && event == "REQUEST_CHANGES" {
		r.Body.Close()
	}
	if r.StatusCode == 422 && len(comments) > 0 {
		r.Body.Close()
		// Preserve every finding in the top-level review body if GitHub rejects
		// an inline comment line anchor so zero findings are silently dropped.
		var fallback strings.Builder
		if strings.TrimSpace(body) != "" {
			fallback.WriteString(strings.TrimSpace(body))
			fallback.WriteString("\n\n")
		}
		fmt.Fprintf(&fallback, "<details><summary>Findings moved from inline comments (%d)</summary>\n\n", len(comments))
		for _, cm := range comments {
			p, _ := cm["path"].(string)
			ln := cm["line"]
			cb, _ := cm["body"].(string)
			fmt.Fprintf(&fallback, "- **%s:%v**\n\n%s\n\n", p, ln, strings.TrimSpace(cb))
		}
		fallback.WriteString("</details>\n")
		payload["body"] = fallback.String()
		delete(payload, "comments")
		r, e = c.request(ctx, "POST", fmt.Sprintf("/repos/%s/pulls/%d/reviews", repo, n), payload)
		if e != nil {
			return e
		}
	}
	return decodeResponse(r, nil)
}
func (c *Client) CreateCompletedCheckRun(ctx context.Context, repo, name, head, conclusion, title, summary string, annotations []Annotation) (int64, error) {
	clean := make([]Annotation, 0, len(annotations))
	for _, a := range annotations {
		a.Path = strings.TrimPrefix(strings.TrimPrefix(a.Path, "/"), "./")
		if a.Path == "" {
			continue
		}
		if a.StartLine < 1 {
			a.StartLine = 1
		}
		if a.EndLine < a.StartLine {
			a.EndLine = a.StartLine
		}
		if len(a.Message) > 4000 {
			a.Message = truncateUTF8(a.Message, 4000)
		}
		if len(a.Title) > 255 {
			a.Title = truncateUTF8(a.Title, 255)
		}
		clean = append(clean, a)
	}
	chunks := [][]Annotation{clean}
	if len(clean) > 50 {
		chunks = [][]Annotation{clean[:50]}
		for i := 50; i < len(clean); i += 50 {
			end := i + 50
			if end > len(clean) {
				end = len(clean)
			}
			chunks = append(chunks, clean[i:end])
		}
	}
	output := map[string]any{"title": title, "summary": summary}
	if len(chunks[0]) > 0 {
		output["annotations"] = chunks[0]
	}
	payload := map[string]any{"name": name, "head_sha": head, "status": "completed", "conclusion": conclusion, "output": output}
	r, e := c.request(ctx, "POST", fmt.Sprintf("/repos/%s/check-runs", repo), payload)
	if e != nil {
		return 0, e
	}
	fallback := r.StatusCode == 422 && len(chunks[0]) > 0
	if fallback {
		r.Body.Close()
		delete(output, "annotations")
		r, e = c.request(ctx, "POST", fmt.Sprintf("/repos/%s/check-runs", repo), payload)
		if e != nil {
			return 0, e
		}
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if e = decodeResponse(r, &created); e != nil {
		return 0, e
	}
	remainingChunks := chunks[1:]
	if fallback {
		remainingChunks = append([][]Annotation{chunks[0]}, remainingChunks...)
	}
	for _, chunk := range remainingChunks {
		for attempt := 0; ; attempt++ {
			resp, err := c.request(ctx, "PATCH", fmt.Sprintf("/repos/%s/check-runs/%d", repo, created.ID), map[string]any{"output": map[string]any{"title": title, "summary": summary, "annotations": chunk}})
			if err != nil {
				return 0, err
			}
			if resp.StatusCode == 404 {
				resp.Body.Close()
				if attempt < 2 {
					select {
					case <-ctx.Done():
						return 0, ctx.Err()
					case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
					}
					continue
				}
			}
			if err = decodeResponse(resp, nil); err != nil {
				return 0, err
			}
			break
		}
	}
	return created.ID, nil
}

func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !isUTF8Boundary(value, limit) {
		limit--
	}
	return value[:limit]
}

func isUTF8Boundary(value string, index int) bool {
	return index == len(value) || value[index]&0xc0 != 0x80
}
func (c *Client) GetPullReviewComment(ctx context.Context, repo string, id int64) (map[string]any, error) {
	var out map[string]any
	r, e := c.request(ctx, "GET", fmt.Sprintf("/repos/%s/pulls/comments/%d", repo, id), nil)
	if e != nil {
		return nil, e
	}
	e = decodeResponse(r, &out)
	return out, e
}
func (c *Client) ReplyToPullReviewComment(ctx context.Context, repo string, n int, id int64, body string) error {
	r, e := c.request(ctx, "POST", fmt.Sprintf("/repos/%s/pulls/%d/comments/%d/replies", repo, n, id), map[string]string{"body": body})
	if e != nil {
		return e
	}
	return decodeResponse(r, nil)
}
func (c *Client) PostIssueComment(ctx context.Context, repo string, n int, body string) (map[string]any, error) {
	var out map[string]any
	r, e := c.request(ctx, "POST", fmt.Sprintf("/repos/%s/issues/%d/comments", repo, n), map[string]string{"body": body})
	if e != nil {
		return nil, e
	}
	e = decodeResponse(r, &out)
	return out, e
}
func (c *Client) UpdateIssueComment(ctx context.Context, repo string, id int64, body string) error {
	r, e := c.request(ctx, "PATCH", fmt.Sprintf("/repos/%s/issues/comments/%d", repo, id), map[string]string{"body": body})
	if e != nil {
		return e
	}
	return decodeResponse(r, nil)
}
func IsBotCommentAuthor(comment map[string]any, bot string) bool {
	user, _ := comment["user"].(map[string]any)
	login, _ := user["login"].(string)
	body, _ := comment["body"].(string)
	return login == bot || login == bot+"[bot]" || strings.Contains(body, "<!-- wapo-review-finding:")
}

func isPreviewDashboardHost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	h := strings.ToLower(u.Hostname())
	return h == "vercel.com" || h == "www.vercel.com" || h == "github.com" || h == "app.netlify.com"
}

// ListPreviewCandidateURLs extracts candidate preview deployment URLs from
// successful commit statuses, GitHub deployments, and PR issue comments (e.g. Vercel bot).
func (c *Client) ListPreviewCandidateURLs(ctx context.Context, repo, headSHA string, prNum int) (statuses, deployments, comments []string) {
	if headSHA != "" {
		if r, err := c.request(ctx, "GET", fmt.Sprintf("/repos/%s/commits/%s/status", repo, headSHA), nil); err == nil {
			var combined struct {
				Statuses []struct {
					State     string `json:"state"`
					TargetURL string `json:"target_url"`
				} `json:"statuses"`
			}
			if decodeResponse(r, &combined) == nil {
				for _, s := range combined.Statuses {
					if s.State == "success" && s.TargetURL != "" && !isPreviewDashboardHost(s.TargetURL) {
						statuses = append(statuses, s.TargetURL)
					}
				}
			}
		}
		if r, err := c.request(ctx, "GET", fmt.Sprintf("/repos/%s/deployments?sha=%s&per_page=10", repo, url.QueryEscape(headSHA)), nil); err == nil {
			var deps []struct {
				ID int64 `json:"id"`
			}
			if decodeResponse(r, &deps) == nil {
				for _, dep := range deps {
					if r2, err := c.request(ctx, "GET", fmt.Sprintf("/repos/%s/deployments/%d/statuses?per_page=5", repo, dep.ID), nil); err == nil {
						var dsts []struct {
							State          string `json:"state"`
							EnvironmentURL string `json:"environment_url"`
							TargetURL      string `json:"target_url"`
						}
						if decodeResponse(r2, &dsts) == nil {
							for _, ds := range dsts {
								if ds.State != "success" {
									continue
								}
								if ds.EnvironmentURL != "" && !isPreviewDashboardHost(ds.EnvironmentURL) {
									deployments = append(deployments, ds.EnvironmentURL)
								} else if ds.TargetURL != "" && !isPreviewDashboardHost(ds.TargetURL) {
									deployments = append(deployments, ds.TargetURL)
								}
							}
						}
					}
				}
			}
		}
	}
	if prNum > 0 {
		if r, err := c.request(ctx, "GET", fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=30", repo, prNum), nil); err == nil {
			var ic []struct {
				Body string `json:"body"`
			}
			if decodeResponse(r, &ic) == nil {
				for _, m := range ic {
					for _, tok := range strings.FieldsFunc(m.Body, func(r rune) bool {
						return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '(' || r == ')' || r == '[' || r == ']' || r == '<' || r == '>' || r == '"' || r == '\''
					}) {
						u := strings.TrimRight(tok, ".,;")
						if strings.HasPrefix(u, "https://") && (strings.Contains(u, ".vercel.app") || strings.Contains(u, ".netlify.app") || strings.Contains(u, ".pages.dev")) {
							comments = append(comments, u)
						}
					}
				}
			}
		}
	}
	return statuses, deployments, comments
}
