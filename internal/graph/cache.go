package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ProfilerCache struct{ Root string }

func NewProfilerCache(root string) *ProfilerCache { return &ProfilerCache{Root: root} }

func (c *ProfilerCache) directory(tenant, repo string) string {
	return filepath.Join(c.Root, cacheKey(tenant), cacheKey(repo))
}

func cacheKey(value string) string {
	h := sha256.Sum256([]byte(value))
	return clean(value) + "-" + hex.EncodeToString(h[:6])
}

func clean(s string) string {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\") {
		return "_"
	}
	return s
}

func atomicWriteFile(dst string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func (c *ProfilerCache) Save(x *CodebaseIndex, baseSHA string) error {
	d := c.directory(x.TenantID, x.RepoID)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	sources := make(map[string][]byte, len(x.Files))
	for p, f := range x.Files {
		sources[p] = f.Parsed.Source
	}
	b, err := json.Marshal(sources)
	if err != nil {
		return err
	}
	if err := atomicWriteFile(filepath.Join(d, cacheKey(x.CommitSHA)+".json"), b, 0o600); err != nil {
		return err
	}
	meta, err := json.Marshal(map[string]string{"commit_sha": x.CommitSHA, "base_sha": baseSHA})
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(d, "latest.json"), meta, 0o600)
}

func (c *ProfilerCache) Load(tenant, repo, sha string) (*CodebaseIndex, error) {
	b, err := os.ReadFile(filepath.Join(c.directory(tenant, repo), cacheKey(sha)+".json"))
	if err != nil {
		return nil, err
	}
	var sources map[string][]byte
	if err := json.Unmarshal(b, &sources); err != nil {
		return nil, err
	}
	return NewCodebaseIndex(sources, tenant, repo, sha), nil
}

func (c *ProfilerCache) SeedBase(tenant, repo, _ string) (string, *CodebaseIndex, error) {
	b, err := os.ReadFile(filepath.Join(c.directory(tenant, repo), "latest.json"))
	if err != nil {
		return "", nil, err
	}
	var m struct {
		BaseSHA string `json:"base_sha"`
	}
	if err := json.Unmarshal(b, &m); err != nil || m.BaseSHA == "" {
		return "", nil, err
	}
	x, err := c.Load(tenant, repo, m.BaseSHA)
	if err == nil && x.CommitSHA != m.BaseSHA {
		return "", nil, os.ErrNotExist
	}
	return m.BaseSHA, x, err
}

func (c *ProfilerCache) Prune(tenant, repo string, max int, protected ...string) (int, error) {
	d := c.directory(tenant, repo)
	entries, err := filepath.Glob(filepath.Join(d, "*.json"))
	if err != nil {
		return 0, err
	}
	protect := map[string]bool{"latest.json": true}
	for _, p := range protected {
		if p != "" {
			protect[cacheKey(p)+".json"] = true
		}
	}
	type item struct {
		path    string
		modTime int64
	}
	var candidates []item
	protectedCount := 0
	for _, p := range entries {
		base := filepath.Base(p)
		if base == "latest.json" {
			continue
		}
		if protect[base] {
			protectedCount++
			continue
		}
		info, err := os.Stat(p)
		var mt int64
		if err == nil {
			mt = info.ModTime().UnixNano()
		}
		candidates = append(candidates, item{path: p, modTime: mt})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].modTime != candidates[j].modTime {
			return candidates[i].modTime < candidates[j].modTime
		}
		return candidates[i].path < candidates[j].path
	})
	allowedUnprotected := max - protectedCount
	if allowedUnprotected < 0 {
		allowedUnprotected = 0
	}
	removed := 0
	for len(candidates) > allowedUnprotected {
		if os.Remove(candidates[0].path) == nil {
			removed++
		}
		candidates = candidates[1:]
	}
	return removed, nil
}
