package sharder

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/wapo-org/wapo-review/internal/graph"
)

type PRFile struct {
	Path      string
	Status    string
	Patch     string
	Additions int
	Deletions int
	IsTest    bool
}

type Shard struct {
	ID               string
	Name             string
	Subsystem        string
	Files            []PRFile
	Checklist        []string
	LineNumberedDiff string
	EstTokens        int
	Hunks            int
	CrossShardLinks  []CrossShardLink
}

type CrossShardLink struct {
	FromFile string
	ToFile   string
	Reason   string
}

// FormatLineNumberedDiff formats either a bare GitHub per-file patch (starting
// with `@@`) or a full multi-file unified diff with exact new-side line numbers.
func FormatLineNumberedDiff(path, patch string) string {
	var b strings.Builder
	hasFileHeaders := strings.Contains(patch, "+++ b/")
	inFile := !hasFileHeaders
	line := 0
	for _, raw := range strings.Split(patch, "\n") {
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "+++ b/") {
			inFile = strings.TrimPrefix(raw, "+++ b/") == path
			continue
		}
		if strings.HasPrefix(raw, "diff ") || strings.HasPrefix(raw, "index ") || strings.HasPrefix(raw, "--- ") {
			continue
		}
		if strings.HasPrefix(raw, "@@") {
			if inFile {
				if i := strings.Index(raw, "+"); i >= 0 {
					f := strings.Fields(raw[i+1:])
					if len(f) > 0 {
						line = atoi(strings.SplitN(f[0], ",", 2)[0])
					}
				}
			}
			continue
		}
		if !inFile || strings.HasPrefix(raw, "\\") {
			continue
		}
		if strings.HasPrefix(raw, "+") {
			fmt.Fprintf(&b, "%4d | %s\n", line, raw)
			line++
		} else if strings.HasPrefix(raw, "-") {
			fmt.Fprintf(&b, "     | %s\n", raw)
		} else {
			fmt.Fprintf(&b, "%4d | %s\n", line, raw)
			line++
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func estFileTokens(f PRFile) int {
	t := (len(f.Patch) + 3) / 4
	if t < 1 {
		t = 1
	}
	return t
}

func EstFileTokens(f PRFile) int { return estFileTokens(f) }

const maxProdFilesPerShard = 3
const maxHunksPerShard = 14

// ShardFiles partitions PR files into subsystem-affinity shards targeting 4-6
// production files per shard (with a single-shard fast path for <=6 prod files).
// Strong call/import/co-change chains are kept together; oversized components
// are split along subdirectory and token-budget boundaries.
func ShardFiles(files []PRFile, idx *graph.CodebaseIndex, tokenBudget int) []Shard {
	if tokenBudget <= 0 {
		tokenBudget = 12000
	}
	var production []PRFile
	var tests []PRFile
	for _, f := range files {
		if f.IsTest {
			tests = append(tests, f)
		} else {
			production = append(production, f)
		}
	}
	sort.Slice(production, func(i, j int) bool { return production[i].Path < production[j].Path })
	sort.Slice(tests, func(i, j int) bool { return tests[i].Path < tests[j].Path })

	totalTokens, totalHunks := 0, 0
	for _, f := range production {
		totalTokens += estFileTokens(f)
		totalHunks += countHunks(f.Patch)
	}
	testTokens, testHunks := 0, 0
	for _, f := range tests {
		testTokens += estFileTokens(f)
		testHunks += countHunks(f.Patch)
	}
	if len(production) <= maxProdFilesPerShard && len(production)+len(tests) <= maxProdFilesPerShard && totalTokens+testTokens <= tokenBudget && totalHunks+testHunks <= maxHunksPerShard {
		all := append(append([]PRFile(nil), production...), tests...)
		if len(all) == 0 {
			return nil
		}
		return []Shard{makeShard(1, all)}
	}

	// Build affinity graph: strong edges (imports, calls, co-changes) first.
	byPath := make(map[string]PRFile, len(production))
	adj := make(map[string]map[string]bool, len(production))
	reasons := map[string]map[string]string{}
	for _, f := range production {
		byPath[f.Path] = f
		adj[f.Path] = map[string]bool{}
		reasons[f.Path] = map[string]string{}
	}
	connect := func(a, b, reason string) {
		if a == b || adj[a] == nil || adj[b] == nil {
			return
		}
		adj[a][b] = true
		adj[b][a] = true
		if reasons[a][b] == "" || reason < reasons[a][b] {
			reasons[a][b] = reason
			reasons[b][a] = reason
		}
	}

	for _, f := range production {
		if idx != nil {
			for _, p := range idx.ImportsOf(f.Path) {
				connect(f.Path, p, "import")
			}
			for _, p := range idx.ImportersOf(f.Path) {
				connect(f.Path, p, "import")
			}
			for _, p := range idx.CalleesOf(f.Path) {
				connect(f.Path, p, "call")
			}
			for _, p := range idx.CallersOf(f.Path) {
				connect(f.Path, p, "call")
			}
			for p := range idx.CoChanges[f.Path] {
				connect(f.Path, p, "co_change")
			}
			for _, p := range idx.SharedTablePeers(f.Path) {
				connect(f.Path, p, "shared_table")
			}
			for _, p := range idx.SharedStatusPeers(f.Path) {
				connect(f.Path, p, "shared_status")
			}
			for _, p := range idx.PairedModules(f.Path) {
				connect(f.Path, p, "paired_module")
			}
		}
	}

	// Extract graph-connected affinity components.
	seen := map[string]bool{}
	var components [][]PRFile
	for _, f := range production {
		if seen[f.Path] {
			continue
		}
		queue := []string{f.Path}
		seen[f.Path] = true
		var comp []PRFile
		for len(queue) > 0 {
			p := queue[0]
			queue = queue[1:]
			comp = append(comp, byPath[p])
			var neighbors []string
			for n := range adj[p] {
				if !seen[n] {
					neighbors = append(neighbors, n)
				}
			}
			sort.Strings(neighbors)
			for _, n := range neighbors {
				seen[n] = true
				queue = append(queue, n)
			}
		}
		sort.Slice(comp, func(i, j int) bool { return comp[i].Path < comp[j].Path })
		components = append(components, comp)
	}

	// Group singletons by directory so same-subsystem files stay together.
	dirSingletons := map[string][]PRFile{}
	var units [][]PRFile
	for _, comp := range components {
		if len(comp) == 1 {
			d := filepath.Dir(comp[0].Path)
			dirSingletons[d] = append(dirSingletons[d], comp[0])
		} else {
			units = append(units, comp)
		}
	}
	dirKeys := make([]string, 0, len(dirSingletons))
	for d := range dirSingletons {
		dirKeys = append(dirKeys, d)
	}
	sort.Strings(dirKeys)
	for _, d := range dirKeys {
		units = append(units, dirSingletons[d])
	}

	// Split any oversized unit (> maxProdFilesPerShard or > tokenBudget) along
	// subdirectory and size boundaries so no shard causes reviewer skimming.
	var boundedUnits [][]PRFile
	for _, u := range units {
		boundedUnits = append(boundedUnits, splitUnit(u, maxProdFilesPerShard, maxHunksPerShard, tokenBudget)...)
	}

	// Pack units into shards respecting both maxProdFilesPerShard and tokenBudget.
	var buckets [][]PRFile
	var cur []PRFile
	curTokens := 0
	curHunks := 0
	for _, u := range boundedUnits {
		uTokens := 0
		uHunks := 0
		for _, f := range u {
			uTokens += estFileTokens(f)
			uHunks += countHunks(f.Patch)
		}
		if len(cur) > 0 && (len(cur)+len(u) > maxProdFilesPerShard || curTokens+uTokens > tokenBudget || curHunks+uHunks > maxHunksPerShard) {
			buckets = append(buckets, cur)
			cur = nil
			curTokens = 0
			curHunks = 0
		}
		cur = append(cur, u...)
		curTokens += uTokens
		curHunks += uHunks
	}
	if len(cur) > 0 {
		buckets = append(buckets, cur)
	}

	// Attach paired test files (up to 2 per shard) to the shard containing their
	// tested production file. Standalone/remaining tests are chunked cleanly rather
	// than flooding shard-1.
	assignedTest := make(map[string]bool, len(tests))
	testsPerBucket := make([]int, len(buckets))
	for _, tf := range tests {
		targetIdx := -1
		for bi, b := range buckets {
			prodFiles := 0
			for _, existing := range b {
				if !existing.IsTest {
					prodFiles++
				}
			}
			if testsPerBucket[bi] >= 2 || prodFiles > maxProdFilesPerShard {
				continue
			}
			testTokens, testHunks := estFileTokens(tf), countHunks(tf.Patch)
			bucketTokens, bucketHunks := 0, 0
			for _, existing := range b {
				bucketTokens += estFileTokens(existing)
				bucketHunks += countHunks(existing.Patch)
			}
			if bucketTokens+testTokens > tokenBudget || bucketHunks+testHunks > maxHunksPerShard {
				continue
			}
			for _, pf := range b {
				if !pf.IsTest && testMatchesProd(tf.Path, pf.Path, idx) {
					targetIdx = bi
					break
				}
			}
			if targetIdx >= 0 {
				break
			}
		}
		if targetIdx >= 0 {
			buckets[targetIdx] = append(buckets[targetIdx], tf)
			testsPerBucket[targetIdx]++
			assignedTest[tf.Path] = true
		}
	}
	var orphanTests []PRFile
	for _, tf := range tests {
		if !assignedTest[tf.Path] {
			orphanTests = append(orphanTests, tf)
		}
	}
	if len(orphanTests) > 0 {
		buckets = append(buckets, splitUnit(orphanTests, maxProdFilesPerShard, maxHunksPerShard, tokenBudget)...)
	}

	shards := make([]Shard, 0, len(buckets))
	for i, b := range buckets {
		shards = append(shards, makeShard(i+1, b))
	}
	shardFor := map[string]int{}
	for si, bucket := range buckets {
		for _, f := range bucket {
			shardFor[f.Path] = si
		}
	}
	for a, neighbors := range adj {
		for b := range neighbors {
			if a < b && shardFor[a] != shardFor[b] {
				for _, source := range []string{a, b} {
					target := b
					if source == b {
						target = a
					}
					shards[shardFor[source]].CrossShardLinks = append(shards[shardFor[source]].CrossShardLinks, CrossShardLink{source, target, reasons[a][b]})
				}
			}
		}
	}
	for i := range shards {
		links := shards[i].CrossShardLinks
		sort.Slice(links, func(a, b int) bool {
			if links[a].FromFile != links[b].FromFile {
				return links[a].FromFile < links[b].FromFile
			}
			if links[a].ToFile != links[b].ToFile {
				return links[a].ToFile < links[b].ToFile
			}
			return links[a].Reason < links[b].Reason
		})
		if len(links) > 6 {
			links = links[:6]
		}
		shards[i].CrossShardLinks = links
	}
	return shards
}

func countHunks(patch string) int {
	count := 0
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "@@") {
			count++
		}
	}
	if count == 0 && patch != "" {
		return 1
	}
	return count
}

func CountHunks(patch string) int { return countHunks(patch) }

type ClusterOptions struct {
	MaxFiles    int
	MaxHunks    int
	TokenBudget int
	PreferGraph bool
}

func ClusterFilesByGraph(files []PRFile, idx *graph.CodebaseIndex, opts ClusterOptions) [][]PRFile {
	maxFiles, maxHunks, tokenBudget := opts.MaxFiles, opts.MaxHunks, opts.TokenBudget
	if maxFiles <= 0 {
		maxFiles = 3
	}
	if maxHunks <= 0 {
		maxHunks = 14
	}
	if tokenBudget <= 0 {
		tokenBudget = 12000
	}
	ordered := append([]PRFile(nil), files...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	byPath := make(map[string]PRFile, len(ordered))
	adj := make(map[string]map[string]bool, len(ordered))
	for _, f := range ordered {
		byPath[f.Path] = f
		adj[f.Path] = map[string]bool{}
	}
	connect := func(a, b string) {
		if a != b && adj[a] != nil && adj[b] != nil {
			adj[a][b] = true
			adj[b][a] = true
		}
	}
	if opts.PreferGraph && idx != nil {
		for _, f := range ordered {
			neighbors := append(idx.ImportsOf(f.Path), idx.ImportersOf(f.Path)...)
			neighbors = append(neighbors, idx.CalleesOf(f.Path)...)
			neighbors = append(neighbors, idx.CallersOf(f.Path)...)
			for p := range idx.CoChanges[f.Path] {
				neighbors = append(neighbors, p)
			}
			neighbors = append(neighbors, idx.SharedTablePeers(f.Path)...)
			neighbors = append(neighbors, idx.SharedStatusPeers(f.Path)...)
			neighbors = append(neighbors, idx.PairedModules(f.Path)...)
			neighbors = append(neighbors, idx.ContractPeers(f.Path)...)
			for _, p := range neighbors {
				connect(f.Path, p)
			}
		}
	}
	seen := map[string]bool{}
	var components [][]PRFile
	for _, f := range ordered {
		if seen[f.Path] {
			continue
		}
		queue := []string{f.Path}
		seen[f.Path] = true
		var component []PRFile
		for len(queue) > 0 {
			p := queue[0]
			queue = queue[1:]
			component = append(component, byPath[p])
			var neighbors []string
			for n := range adj[p] {
				if !seen[n] {
					neighbors = append(neighbors, n)
				}
			}
			sort.Strings(neighbors)
			for _, n := range neighbors {
				seen[n] = true
				queue = append(queue, n)
			}
		}
		components = append(components, component)
	}
	var out [][]PRFile
	var singleton []PRFile
	flush := func() {
		if len(singleton) > 0 {
			out = append(out, splitUnit(singleton, maxFiles, maxHunks, tokenBudget)...)
			singleton = nil
		}
	}
	for _, component := range components {
		if len(component) == 1 {
			singleton = append(singleton, component[0])
			continue
		}
		flush()
		out = append(out, splitOrdered(component, maxFiles, maxHunks, tokenBudget)...)
	}
	flush()
	return out
}

func splitOrdered(files []PRFile, maxFiles, maxHunks, tokenBudget int) [][]PRFile {
	var buckets [][]PRFile
	var current []PRFile
	tokens, hunks := 0, 0
	for _, file := range files {
		ft, fh := estFileTokens(file), countHunks(file.Patch)
		if len(current) > 0 && (len(current) >= maxFiles || tokens+ft > tokenBudget || hunks+fh > maxHunks) {
			buckets = append(buckets, current)
			current = nil
			tokens = 0
			hunks = 0
		}
		current = append(current, file)
		tokens += ft
		hunks += fh
	}
	if len(current) > 0 {
		buckets = append(buckets, current)
	}
	return buckets
}

func splitUnit(u []PRFile, maxFiles, maxHunks, tokenBudget int) [][]PRFile {
	totalTok, totalHunks := 0, 0
	for _, f := range u {
		totalTok += estFileTokens(f)
		totalHunks += countHunks(f.Patch)
	}
	if len(u) <= maxFiles && totalTok <= tokenBudget && totalHunks <= maxHunks {
		return [][]PRFile{u}
	}
	// Group by directory first, then slice cleanly.
	byDir := map[string][]PRFile{}
	for _, f := range u {
		d := filepath.Dir(f.Path)
		byDir[d] = append(byDir[d], f)
	}
	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	var out [][]PRFile
	for _, d := range dirs {
		var cur []PRFile
		curTok := 0
		curHunks := 0
		for _, f := range byDir[d] {
			ft := estFileTokens(f)
			fh := countHunks(f.Patch)
			if len(cur) > 0 && (len(cur) >= maxFiles || curTok+ft > tokenBudget || curHunks+fh > maxHunks) {
				out = append(out, cur)
				cur = nil
				curTok = 0
				curHunks = 0
			}
			cur = append(cur, f)
			curTok += ft
			curHunks += fh
		}
		if len(cur) > 0 {
			out = append(out, cur)
		}
	}
	return out
}

var genericTestStems = map[string]bool{
	"index": true, "main": true, "app": true, "client": true,
	"tools": true, "harness": true, "fixture": true, "types": true,
	"utils": true, "helpers": true, "config": true, "server": true,
}

func testMatchesProd(testPath, prodPath string, idx *graph.CodebaseIndex) bool {
	stem := strings.ToLower(strings.TrimSuffix(filepath.Base(prodPath), filepath.Ext(prodPath)))
	if len(stem) < 3 || genericTestStems[stem] {
		return false
	}
	if idx != nil {
		for _, t := range idx.TestsFor(prodPath) {
			if t == testPath {
				return true
			}
		}
	}
	testBase := strings.ToLower(filepath.Base(testPath))
	return strings.HasPrefix(testBase, stem+".") || strings.HasPrefix(testBase, stem+"_") || strings.HasPrefix(testBase, "test_"+stem)
}

func makeShard(id int, files []PRFile) Shard {
	s := Shard{
		ID:   fmt.Sprintf("shard-%d", id),
		Name: fmt.Sprintf("shard-%d", id),
	}
	hasProd := false
	for _, f := range files {
		if !f.IsTest {
			hasProd = true
			break
		}
	}
	var diffBuf strings.Builder
	for _, f := range files {
		s.Files = append(s.Files, f)
		// Keep checklist focused on production files (unless shard is test-only)
		// so agents never burn turns marking paired tests.
		if !hasProd || !f.IsTest {
			s.Checklist = append(s.Checklist, f.Path)
		}
		formatted := FormatLineNumberedDiff(f.Path, f.Patch)
		if formatted != "" {
			fmt.Fprintf(&diffBuf, "=== %s ===\n%s\n", f.Path, formatted)
		}
		s.EstTokens += estFileTokens(f)
		s.Hunks += countHunks(f.Patch)
	}
	s.LineNumberedDiff = strings.TrimRight(diffBuf.String(), "\n")
	if len(files) > 0 {
		s.Subsystem = filepath.Dir(files[0].Path)
	}
	return s
}
