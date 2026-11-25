package memory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/wapo-org/wapo-review/internal/branding"
	"github.com/wapo-org/wapo-review/internal/redact"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const MaxNotesPerRepo = 50
const MaxNoteChars = 500

var ValidScopes = []string{"all", "code_review", "hands_on", "visual_review"}
var slug = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type Note struct {
	ID        string `json:"id"`
	Text      string `json:"text"`
	Scope     string `json:"scope"`
	Source    string `json:"source"`
	CreatedAt string `json:"created_at"`
}
type Store struct {
	Dir      string
	Redactor *redact.Redactor
	mu       sync.Mutex
}

func NewStore(dir string, secrets ...string) *Store {
	return &Store{Dir: dir, Redactor: redact.New(secrets...)}
}
func repoFile(repo string) (string, error) {
	p := strings.Split(repo, "/")
	if len(p) != 2 || !slug.MatchString(p[0]) || !slug.MatchString(p[1]) || strings.Contains(repo, "..") || strings.Contains(repo, "\\") {
		return "", errors.New("invalid repository name")
	}
	h := sha256.Sum256([]byte(repo))
	return p[0] + "_" + p[1] + "_" + hex.EncodeToString(h[:6]) + ".json", nil
}
func (s *Store) path(repo string) (string, error) {
	n, e := repoFile(repo)
	if e != nil {
		return "", e
	}
	d := s.Dir
	if d == "" {
		d = filepath.Join(branding.StateDir(), "memory")
	}
	return filepath.Join(d, n), nil
}
func (s *Store) Load(repo string) ([]Note, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load(repo)
}

func (s *Store) lockRepo(repo string) (func(), error) {
	p, err := s.path(repo)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

func (s *Store) SetRedactor(redactor *redact.Redactor) { s.Redactor = redactor }

func (s *Store) load(repo string) ([]Note, error) {
	p, e := s.path(repo)
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(p)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var n []Note
	e = json.Unmarshal(b, &n)
	return n, e
}
func (s *Store) Add(repo, text, scope, source string) (Note, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, e := s.lockRepo(repo)
	if e != nil {
		return Note{}, e
	}
	defer unlock()
	if scope == "" {
		scope = "all"
	}
	valid := false
	for _, v := range ValidScopes {
		valid = valid || scope == v
	}
	if !valid {
		return Note{}, errors.New("invalid scope")
	}
	norm := strings.Join(strings.Fields(text), " ")
	redactor := s.Redactor
	if redactor == nil {
		redactor = redact.New()
	}
	norm = redactor.RedactString(norm)
	if len(norm) > MaxNoteChars {
		norm = truncateRunes(norm, MaxNoteChars)
	}
	if norm == "" {
		return Note{}, errors.New("empty note")
	}
	notes, e := s.load(repo)
	if e != nil && !os.IsNotExist(e) {
		return Note{}, e
	}
	for _, n := range notes {
		if n.Scope == scope && strings.EqualFold(strings.Join(strings.Fields(n.Text), " "), norm) {
			return n, nil
		}
	}
	note := Note{ID: time.Now().UTC().Format("20060102150405.000000000"), Text: norm, Scope: scope, Source: source, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	notes = append(notes, note)
	if len(notes) > MaxNotesPerRepo {
		notes = notes[len(notes)-MaxNotesPerRepo:]
	}
	p, e := s.path(repo)
	if e != nil {
		return Note{}, e
	}
	if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return Note{}, e
	}
	_ = os.Chmod(filepath.Dir(p), 0700)
	b, e := json.MarshalIndent(notes, "", "  ")
	if e != nil {
		return Note{}, e
	}
	tmp := p + ".tmp"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return Note{}, e
	}
	if e = os.Rename(tmp, p); e != nil {
		_ = os.Remove(tmp)
		return Note{}, e
	}
	return note, nil
}
func (s *Store) Remove(repo, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, e := s.lockRepo(repo)
	if e != nil {
		return false, e
	}
	defer unlock()
	n, e := s.load(repo)
	if e != nil {
		return false, e
	}
	out := n[:0]
	found := false
	for _, v := range n {
		if v.ID == id {
			found = true
		} else {
			out = append(out, v)
		}
	}
	if !found {
		return false, nil
	}
	p, e := s.path(repo)
	if e != nil {
		return false, e
	}
	b, e := json.MarshalIndent(out, "", "  ")
	if e != nil {
		return false, e
	}
	tmp, e := os.CreateTemp(filepath.Dir(p), ".memory-*")
	if e != nil {
		return false, e
	}
	tmpName := tmp.Name()
	if _, e = tmp.Write(b); e == nil {
		e = tmp.Chmod(0600)
	}
	if closeErr := tmp.Close(); e == nil {
		e = closeErr
	}
	if e == nil {
		e = os.Rename(tmpName, p)
	}
	if e != nil {
		_ = os.Remove(tmpName)
	}
	return e == nil, e
}

func truncateRunes(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	for maxBytes > 0 && !utf8.RuneStart(value[maxBytes]) {
		maxBytes--
	}
	return value[:maxBytes]
}
