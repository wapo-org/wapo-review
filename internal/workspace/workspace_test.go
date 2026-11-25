package workspace

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentAppendAndModes(t *testing.T) {
	root := t.TempDir()
	w, e := New(root)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if e := w.AppendFinding("shard", VerifiedFinding{ID: string(rune('a' + i))}); e != nil {
				t.Error(e)
			}
			if e := w.AppendLead(Lead{FromShard: "shard"}); e != nil {
				t.Error(e)
			}
		}(i)
	}
	wg.Wait()
	fs, e := w.ReadAllFindings()
	if e != nil || len(fs) != 12 {
		t.Fatalf("findings=%d err=%v", len(fs), e)
	}
	ls, e := w.ReadAllLeads()
	if e != nil || len(ls) != 12 {
		t.Fatalf("leads=%d err=%v", len(ls), e)
	}
	for _, p := range []string{filepath.Join(root, "findings"), filepath.Join(root, "notes")} {
		st, e := os.Stat(p)
		if e != nil {
			t.Fatal(e)
		}
		if st.Mode().Perm() != 0700 {
			t.Fatalf("%s mode %o", p, st.Mode().Perm())
		}
	}
	st, e := os.Stat(filepath.Join(root, "leads.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("file mode %o", st.Mode().Perm())
	}
}

func TestLeadEnrichmentRoundTrip(t *testing.T) {
	w, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AppendLead(Lead{FromShard: "a", TargetFile: "b.go", InvariantType: "state_machine", Evidence: "transition at b.go:42"}); err != nil {
		t.Fatal(err)
	}
	leads, err := w.ReadAllLeads()
	if err != nil || len(leads) != 1 {
		t.Fatalf("leads=%+v err=%v", leads, err)
	}
	if leads[0].InvariantType != "state_machine" || leads[0].Evidence != "transition at b.go:42" {
		t.Fatalf("enrichment lost: %+v", leads[0])
	}
}

func TestPostLeadResponseIncludesGeneratedIdentity(t *testing.T) {
	w, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	response, err := NewPostLeadTool(w, "shard-a").InvokableRun(context.Background(), `{"target_file":"a.go","question":"check invariant"}`)
	if err != nil {
		t.Fatal(err)
	}
	var lead Lead
	if err := json.Unmarshal([]byte(response), &lead); err != nil {
		t.Fatal(err)
	}
	if lead.ID == "" || lead.CreatedAt.IsZero() || lead.FromShard != "shard-a" {
		t.Fatalf("lead identity missing: %+v", lead)
	}
}
