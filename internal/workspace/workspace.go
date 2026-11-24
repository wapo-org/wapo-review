package workspace

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"github.com/eino-contrib/jsonschema"
)

type VerifiedFinding struct {
	ID            string    `json:"id"`
	File          string    `json:"file"`
	StartLine     int       `json:"start_line"`
	EndLine       int       `json:"end_line"`
	Severity      string    `json:"severity"`
	Category      string    `json:"category"`
	Title         string    `json:"title"`
	Body          string    `json:"body"`
	EvidenceQuote string    `json:"evidence_quote"`
	SuggestedFix  string    `json:"suggested_fix,omitempty"`
	Confidence    string    `json:"confidence"`
	OnDiffLine    bool      `json:"on_diff_line"`
	Fingerprint   string    `json:"fingerprint"`
	CreatedAt     time.Time `json:"created_at"`
}
type Lead struct {
	ID            string    `json:"id"`
	FromShard     string    `json:"from_shard"`
	TargetFile    string    `json:"target_file"`
	TargetSymbol  string    `json:"target_symbol"`
	Question      string    `json:"question"`
	SeverityHint  string    `json:"severity_hint"`
	InvariantType string    `json:"invariant_type,omitempty"`
	Evidence      string    `json:"evidence,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}
type SharedWorkspace struct {
	Root string
	mu   sync.Mutex
}

func New(root string) (*SharedWorkspace, error) {
	if err := os.MkdirAll(filepath.Join(root, "findings"), 0700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, "notes"), 0700); err != nil {
		return nil, err
	}
	return &SharedWorkspace{Root: root}, nil
}
func (w *SharedWorkspace) append(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = f.Write(append(b, '\n'))
	return e
}
func (w *SharedWorkspace) AppendFinding(id string, f VerifiedFinding) error {
	return w.append(filepath.Join(w.Root, "findings", clean(id)+".jsonl"), f)
}
func (w *SharedWorkspace) AppendLead(l Lead) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if l.ID == "" {
		l.ID = randomID()
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}
	b, e := json.Marshal(l)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(filepath.Join(w.Root, "leads.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = f.Write(append(b, '\n'))
	return e
}
func (w *SharedWorkspace) ReadAllFindings() ([]VerifiedFinding, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	paths, _ := filepath.Glob(filepath.Join(w.Root, "findings", "*.jsonl"))
	out := []VerifiedFinding{}
	for _, p := range paths {
		if e := scan(p, &out); e != nil {
			return nil, e
		}
	}
	return out, nil
}
func (w *SharedWorkspace) ReadAllLeads() ([]Lead, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := []Lead{}
	e := scan(filepath.Join(w.Root, "leads.jsonl"), &out)
	if os.IsNotExist(e) {
		return out, nil
	}
	return out, e
}
func (w *SharedWorkspace) WriteNote(id, content string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return os.WriteFile(filepath.Join(w.Root, "notes", clean(id)+".md"), []byte(content), 0600)
}
func (w *SharedWorkspace) ReadAllNotes() (map[string]string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	m := map[string]string{}
	ps, e := filepath.Glob(filepath.Join(w.Root, "notes", "*.md"))
	if e != nil {
		return nil, e
	}
	for _, p := range ps {
		b, e := os.ReadFile(p)
		if e != nil {
			return nil, e
		}
		m[strings.TrimSuffix(filepath.Base(p), ".md")] = string(b)
	}
	return m, nil
}
func scan[T any](p string, out *[]T) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 4<<20)
	for s.Scan() {
		var v T
		if e := json.Unmarshal(s.Bytes(), &v); e != nil {
			return e
		}
		*out = append(*out, v)
	}
	return s.Err()
}
func clean(s string) string {
	s = filepath.Base(s)
	if s == "." || s == "/" || s == "" {
		return "unknown"
	}
	return s
}
func randomID() string { b := make([]byte, 12); _, _ = rand.Read(b); return hex.EncodeToString(b) }

type invTool struct {
	name   string
	desc   string
	schema any
	run    func(string) (string, error)
}

func (t invTool) Info(context.Context) (*schema.ToolInfo, error) {
	info := &schema.ToolInfo{Name: t.name, Desc: t.desc}
	if t.schema != nil {
		info.ParamsOneOf = schema.NewParamsOneOfByJSONSchema(jsonschema.Reflect(t.schema))
	}
	return info, nil
}
func (t invTool) InvokableRun(_ context.Context, s string, _ ...tool.Option) (string, error) {
	return t.run(s)
}

type postLeadArgs struct {
	TargetFile    string `json:"target_file"`
	TargetSymbol  string `json:"target_symbol,omitempty"`
	Question      string `json:"question"`
	SeverityHint  string `json:"severity_hint,omitempty"`
	InvariantType string `json:"invariant_type,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
}

func NewPostLeadTool(w *SharedWorkspace, shard string) tool.InvokableTool {
	return invTool{
		name:   "post_lead",
		desc:   "Post a cross-file investigation lead for another shard or the Consolidator Agent. Include invariant_type and brief evidence when known.",
		schema: postLeadArgs{},
		run: func(raw string) (string, error) {
			var l Lead
			if e := json.Unmarshal([]byte(raw), &l); e != nil {
				return "", e
			}
			l.FromShard = shard
			if e := w.AppendLead(l); e != nil {
				return "", e
			}
			b, _ := json.Marshal(l)
			return string(b), nil
		},
	}
}
func NewReadLeadsTool(w *SharedWorkspace) tool.InvokableTool {
	return invTool{
		name: "read_leads",
		desc: "Read all cross-shard investigation leads in this run",
		run:  func(string) (string, error) { v, e := w.ReadAllLeads(); b, _ := json.Marshal(v); return string(b), e },
	}
}
func NewReadSharedFindingsTool(w *SharedWorkspace) tool.InvokableTool {
	return invTool{
		name: "read_shared_findings",
		desc: "Read all verified findings submitted so far across all shards",
		run: func(string) (string, error) {
			v, e := w.ReadAllFindings()
			b, _ := json.Marshal(v)
			return string(b), e
		},
	}
}
