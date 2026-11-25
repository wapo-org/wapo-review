package memory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestStoreSecurityDedupRedactionAndCap(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "memory"), "secret123456")
	if _, e := s.Add("../escape/repo", "unsafe", "all", "test"); e == nil {
		t.Fatal("accepted traversal")
	}
	n, e := s.Add("owner/repo", "always use secret123456", "all", "test")
	if e != nil || strings.Contains(n.Text, "secret123456") {
		t.Fatalf("redaction: %#v %v", n, e)
	}
	dup, e := s.Add("owner/repo", "always use [REDACTED]", "all", "test")
	if e != nil || dup.ID != n.ID {
		t.Fatal("dedup failed")
	}
	for i := 0; i < 55; i++ {
		if _, e = s.Add("owner/repo", strings.Repeat("x", i+1), "all", "test"); e != nil {
			t.Fatal(e)
		}
	}
	notes, e := s.Load("owner/repo")
	if e != nil || len(notes) != MaxNotesPerRepo {
		t.Fatalf("notes %d err %v", len(notes), e)
	}
	name, _ := repoFile("owner/repo")
	fi, _ := os.Stat(filepath.Join(s.Dir, name))
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	di, _ := os.Stat(s.Dir)
	if di.Mode().Perm() != 0700 {
		t.Fatalf("dir mode %o", di.Mode().Perm())
	}
}

func TestStoreDefaultRedactionAndCrossInstanceWrites(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "memory")
	first, second := NewStore(dir), NewStore(dir)
	if _, err := first.Add("owner/repo", "token ghp_abcdefghijklmnopqrstuvwxyz1234567890", "all", "test"); err != nil {
		t.Fatal(err)
	}
	notes, err := first.Load("owner/repo")
	if err != nil || len(notes) != 1 || strings.Contains(notes[0].Text, "ghp_") {
		t.Fatalf("default redaction failed: %#v %v", notes, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := first
			if i%2 != 0 {
				store = second
			}
			if _, err := store.Add("owner/repo", fmt.Sprintf("note %d", i), "all", "test"); err != nil {
				t.Errorf("Add: %v", err)
			}
		}(i)
	}
	wg.Wait()
	notes, err = second.Load("owner/repo")
	if err != nil || len(notes) != 21 {
		t.Fatalf("cross-instance writes lost: notes=%d err=%v", len(notes), err)
	}
}
func TestReplyExtractionAndRanking(t *testing.T) {
	if _, _, ok := ParseRememberCommand("remember(code_review): prefer table tests"); !ok {
		t.Fatal("remember parse failed")
	}
	if scope, text, ok := ParseRememberCommand("/remember: always check migrations"); !ok || scope != "all" || text != "always check migrations" {
		t.Fatalf("slash remember parse: %q %q %v", scope, text, ok)
	}
	for _, body := range []string{"Fixed.", "Thanks!", "> Always preserve quoted text\n?", "Is this intentional?"} {
		if _, _, ok := ExtractMemoryFromReply(body, true); ok {
			t.Errorf("accepted %q", body)
		}
	}
	scope, text, ok := ExtractMemoryFromReply("From now on, always use screenshots for visual review.", false)
	if !ok || scope != "visual_review" || text == "" {
		t.Fatalf("extraction %q %q %v", scope, text, ok)
	}
	notes := []Note{{Text: "always use table tests", Scope: "code_review"}, {Text: "preview requires login", Scope: "hands_on"}, {Text: "prefer table tests for handlers", Scope: "all"}}
	got := FormatContext(notes, "code_review", "handlers table tests", 80)
	if !strings.HasPrefix(got, "- prefer table tests for handlers") {
		t.Fatalf("ranking %q", got)
	}
}
