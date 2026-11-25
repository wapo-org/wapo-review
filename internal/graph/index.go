package graph

import (
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"

	"github.com/wapo-org/wapo-review/internal/ast"
)

type Symbol = ast.Symbol

type CodebaseIndex struct {
	TenantID         string
	RepoID           string
	CommitSHA        string
	Files            map[string]*ast.FileFacts
	Symbols          []Symbol
	Imports          map[string][]string
	Importers        map[string][]string
	Calls            map[string][]string
	Callers          map[string][]string
	CoChanges        map[string]map[string]int
	ParsedFilesCount int
	stems            map[string][]string
}

func NewCodebaseIndex(files map[string][]byte, tenantID, repoID, sha string) *CodebaseIndex {
	x := &CodebaseIndex{
		TenantID:  tenantID,
		RepoID:    repoID,
		CommitSHA: sha,
		Files:     map[string]*ast.FileFacts{},
		Imports:   map[string][]string{},
		Importers: map[string][]string{},
		Calls:     map[string][]string{},
		Callers:   map[string][]string{},
		CoChanges: map[string]map[string]int{},
		stems:     map[string][]string{},
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		f, err := ast.ExtractFileFacts(p, files[p])
		if err == nil {
			x.Files[p] = f
			x.ParsedFilesCount++
		}
	}
	x.finalize()
	return x
}

func (x *CodebaseIndex) finalize() {
	x.Symbols = nil
	x.stems = map[string][]string{}
	x.Imports = map[string][]string{}
	x.Importers = map[string][]string{}
	x.Calls = map[string][]string{}
	x.Callers = map[string][]string{}

	byName := map[string][]string{}
	paths := make([]string, 0, len(x.Files))
	for p := range x.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		f := x.Files[p]
		stem := strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
		x.stems[stem] = append(x.stems[stem], p)
		for _, s := range f.Symbols {
			x.Symbols = append(x.Symbols, s)
			byName[s.Name] = append(byName[s.Name], p)
		}
	}

	for _, p := range paths {
		f := x.Files[p]
		for _, im := range f.Imports {
			raw := im.Path
			target := strings.Trim(raw, "\"'` ;")
			base := filepath.Base(target)
			stem := strings.TrimSuffix(base, filepath.Ext(base))
			for _, candidate := range x.stems[stem] {
				if candidate == p {
					continue
				}
				x.Imports[p] = appendUnique(x.Imports[p], candidate)
				x.Importers[candidate] = appendUnique(x.Importers[candidate], p)
			}
		}
		for _, c := range f.Calls {
			for _, candidate := range byName[c.Name] {
				if candidate != p {
					x.Calls[p] = appendUnique(x.Calls[p], candidate)
					x.Callers[candidate] = appendUnique(x.Callers[candidate], p)
				}
			}
		}
	}
}

func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

// IncrementalCopy creates a new CodebaseIndex by cloning unchanged FileFacts,
// removing deleted files, and reparsing ONLY the provided changed file sources.
func (x *CodebaseIndex) IncrementalCopy(tenantID, repoID, sha string, changed map[string][]byte, deleted []string) *CodebaseIndex {
	y := &CodebaseIndex{
		TenantID:  tenantID,
		RepoID:    repoID,
		CommitSHA: sha,
		Files:     make(map[string]*ast.FileFacts, len(x.Files)+len(changed)),
		CoChanges: make(map[string]map[string]int, len(x.CoChanges)),
	}
	for p, f := range x.Files {
		y.Files[p] = f
	}
	for k, m := range x.CoChanges {
		cp := make(map[string]int, len(m))
		for k2, v2 := range m {
			cp[k2] = v2
		}
		y.CoChanges[k] = cp
	}
	for _, p := range deleted {
		delete(y.Files, p)
	}
	changedPaths := make([]string, 0, len(changed))
	for p := range changed {
		changedPaths = append(changedPaths, p)
	}
	sort.Strings(changedPaths)
	for _, p := range changedPaths {
		f, err := ast.ExtractFileFacts(p, changed[p])
		if err == nil {
			y.Files[p] = f
			y.ParsedFilesCount++
		} else {
			delete(y.Files, p)
		}
	}
	y.finalize()
	return y
}

func (x *CodebaseIndex) SymbolsNamed(n string) []Symbol {
	var out []Symbol
	for _, s := range x.Symbols {
		if s.Name == n || s.QualifiedName == n {
			out = append(out, s)
		}
	}
	return out
}

func (x *CodebaseIndex) CallersOf(p string) []string { return append([]string(nil), x.Callers[p]...) }
func (x *CodebaseIndex) CalleesOf(p string) []string { return append([]string(nil), x.Calls[p]...) }
func (x *CodebaseIndex) ImportsOf(p string) []string { return append([]string(nil), x.Imports[p]...) }
func (x *CodebaseIndex) ImportersOf(p string) []string {
	return append([]string(nil), x.Importers[p]...)
}

func (x *CodebaseIndex) ExportedSymbols(path string) []string {
	seen := map[string]bool{}
	if facts := x.Files[path]; facts != nil {
		for _, symbol := range facts.Symbols {
			if symbol.Exported || (symbol.Name != "" && !strings.HasPrefix(symbol.Name, "_")) {
				seen[symbol.Name] = true
			}
		}
	}
	return sortedKeys(seen)
}

func (x *CodebaseIndex) ContractPeers(path string) []string {
	peers := map[string]bool{}
	for _, peer := range append(x.ImportsOf(path), x.ImportersOf(path)...) {
		if peer != path && !isTestFile(peer) && filepath.Dir(peer) != filepath.Dir(path) {
			peers[peer] = true
		}
	}
	return sortedKeys(peers)
}

func isTestFile(p string) bool {
	lower := strings.ToLower(filepath.Base(p))
	return strings.Contains(lower, ".test.") ||
		strings.Contains(lower, ".spec.") ||
		strings.HasSuffix(lower, "_test.go") ||
		strings.HasPrefix(lower, "test_") ||
		strings.HasSuffix(lower, "_test.py") ||
		strings.HasSuffix(lower, "test.java") ||
		strings.Contains(strings.ToLower(p), "/__tests__/") ||
		strings.Contains(strings.ToLower(p), "/tests/")
}

// TestsFor returns test files closely associated with p (by direct import/call
// edge or matching filename stem), rather than all tests in the repository.
func (x *CodebaseIndex) TestsFor(p string) []string {
	targetStem := strings.ToLower(strings.TrimSuffix(filepath.Base(p), filepath.Ext(p)))
	matched := map[string]bool{}
	for _, imp := range x.Importers[p] {
		if isTestFile(imp) {
			matched[imp] = true
		}
	}
	for _, caller := range x.Callers[p] {
		if isTestFile(caller) {
			matched[caller] = true
		}
	}
	if targetStem != "" && targetStem != "index" && targetStem != "main" {
		for candidate := range x.Files {
			if !isTestFile(candidate) {
				continue
			}
			base := strings.ToLower(filepath.Base(candidate))
			if strings.Contains(base, targetStem) {
				matched[candidate] = true
			}
		}
	}
	out := make([]string, 0, len(matched))
	for m := range matched {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func (x *CodebaseIndex) TestsForFile(p string) []string { return x.TestsFor(p) }

// FindCycles detects strongly connected components (import cycles) of size >= 2
// using Tarjan's algorithm in O(V + E).
func (x *CodebaseIndex) FindCycles() [][]string {
	nodes := make([]string, 0, len(x.Files))
	for p := range x.Files {
		nodes = append(nodes, p)
	}
	sort.Strings(nodes)

	index := 0
	indices := make(map[string]int, len(nodes))
	lowlink := make(map[string]int, len(nodes))
	onStack := make(map[string]bool, len(nodes))
	var stack []string
	var cycles [][]string

	var strongConnect func(v string)
	strongConnect = func(v string) {
		index++
		indices[v] = index
		lowlink[v] = index
		stack = append(stack, v)
		onStack[v] = true

		for _, w := range x.Imports[v] {
			if indices[w] == 0 {
				strongConnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] {
				if indices[w] < lowlink[v] {
					lowlink[v] = indices[w]
				}
			}
		}

		if lowlink[v] == indices[v] {
			var comp []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				comp = append(comp, w)
				if w == v {
					break
				}
			}
			if len(comp) >= 2 {
				sort.Strings(comp)
				cycles = append(cycles, comp)
			}
		}
	}

	for _, n := range nodes {
		if indices[n] == 0 {
			strongConnect(n)
		}
	}
	return cycles
}

func (x *CodebaseIndex) CoChangedWith(p string) map[string]int { return x.CoChanges[p] }

func (x *CodebaseIndex) IngestGitLog(raw string, depth int, _ bool) {
	x.CoChanges = map[string]map[string]int{}
	sets := strings.Split(raw, "\x00\x00")
	for i := 0; i < len(sets) && (depth <= 0 || i < depth); i++ {
		ps := strings.Fields(sets[i])
		for _, a := range ps {
			if x.CoChanges[a] == nil {
				x.CoChanges[a] = map[string]int{}
			}
			for _, b := range ps {
				if a != b {
					x.CoChanges[a][b]++
				}
			}
		}
	}
}

// PageRank computes personalized PageRank scores over the combined import+call
// graph, seeded toward changed files when provided.
func (x *CodebaseIndex) PageRank(changed []string) map[string]float64 {
	n := len(x.Files)
	if n == 0 {
		return map[string]float64{}
	}
	nodes := make([]string, 0, n)
	for p := range x.Files {
		nodes = append(nodes, p)
	}
	sort.Strings(nodes)

	seedSet := make(map[string]bool, len(changed))
	for _, c := range changed {
		if _, ok := x.Files[c]; ok {
			seedSet[c] = true
		}
	}

	const damping = 0.85
	rank := make(map[string]float64, n)
	base := 1.0 / float64(n)
	for _, p := range nodes {
		rank[p] = base
	}

	outEdges := make(map[string][]string, n)
	for _, p := range nodes {
		var edges []string
		edges = append(edges, x.Imports[p]...)
		for _, c := range x.Calls[p] {
			edges = appendUnique(edges, c)
		}
		outEdges[p] = edges
	}

	for iter := 0; iter < 15; iter++ {
		next := make(map[string]float64, n)
		var sinkSum float64
		for _, p := range nodes {
			if len(outEdges[p]) == 0 {
				sinkSum += rank[p]
			}
		}
		for _, p := range nodes {
			teleport := (1.0 - damping) / float64(n)
			if len(seedSet) > 0 {
				if seedSet[p] {
					teleport = (1.0 - damping) * 0.8 / float64(len(seedSet))
				} else {
					teleport = (1.0 - damping) * 0.2 / float64(n)
				}
			}
			next[p] = teleport + damping*sinkSum/float64(n)
		}
		for _, p := range nodes {
			edges := outEdges[p]
			if len(edges) == 0 {
				continue
			}
			share := damping * rank[p] / float64(len(edges))
			for _, dst := range edges {
				next[dst] += share
			}
		}
		diff := 0.0
		for _, p := range nodes {
			diff += math.Abs(next[p] - rank[p])
		}
		rank = next
		if diff < 1e-6 {
			break
		}
	}
	return rank
}

func (x *CodebaseIndex) RenderRepoMap(changed []string) string {
	scores := x.PageRank(changed)
	paths := make([]string, 0, len(x.Files))
	for p := range x.Files {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		if scores[paths[i]] != scores[paths[j]] {
			return scores[paths[i]] > scores[paths[j]]
		}
		return paths[i] < paths[j]
	})
	var b strings.Builder
	for _, p := range paths {
		f := x.Files[p]
		var syms []string
		for _, s := range f.Symbols {
			if len(syms) >= 6 {
				break
			}
			syms = append(syms, s.Name)
		}
		if len(syms) > 0 {
			fmt.Fprintf(&b, "%s [%s]\n", p, strings.Join(syms, ", "))
		} else {
			fmt.Fprintf(&b, "%s\n", p)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func (x *CodebaseIndex) FormatGraphContext(changed []string, max int) string {
	s := x.RenderRepoMap(changed)
	var invariant strings.Builder
	for _, p := range changed {
		tables := x.SharedTablePeers(p)
		statuses := x.SharedStatusPeers(p)
		paired := x.PairedModules(p)
		if len(tables)+len(statuses)+len(paired) == 0 {
			continue
		}
		fmt.Fprintf(&invariant, "\nInvariant neighbors %s", p)
		if len(tables) > 0 {
			fmt.Fprintf(&invariant, "\n  shared_table: %s", strings.Join(tables, ", "))
		}
		if len(statuses) > 0 {
			fmt.Fprintf(&invariant, "\n  shared_status: %s", strings.Join(statuses, ", "))
		}
		if len(paired) > 0 {
			fmt.Fprintf(&invariant, "\n  paired_module: %s", strings.Join(paired, ", "))
		}
	}
	if invariant.Len() > 0 && (max <= 0 || len(s)+invariant.Len() <= max) {
		s += invariant.String()
	}
	if max > 0 && len(s) > max {
		return s[:max]
	}
	return s
}

var genericModuleStems = map[string]bool{"index": true, "main": true, "types": true, "utils": true, "helpers": true, "config": true, "constants": true, "schema": true, "client": true, "server": true, "app": true, "tools": true, "routes": true, "mod": true, "lib": true}
var genericSymbolNames = map[string]bool{"handler": true, "default": true, "run": true, "init": true, "main": true, "get": true, "set": true, "list": true, "create": true, "delete": true, "update": true, "read": true, "write": true, "start": true, "stop": true, "close": true, "new": true, "load": true, "save": true, "parse": true, "format": true, "validate": true, "check": true, "test": true, "index": true, "config": true, "client": true, "server": true, "types": true}

func (x *CodebaseIndex) SharedTablePeers(path string) []string {
	tableFiles := map[string]map[string]bool{}
	for p, facts := range x.Files {
		for _, table := range facts.Tables {
			if tableFiles[table] == nil {
				tableFiles[table] = map[string]bool{}
			}
			tableFiles[table][p] = true
		}
	}
	peers := map[string]bool{}
	if facts := x.Files[path]; facts != nil {
		for _, table := range facts.Tables {
			files := tableFiles[table]
			if len(files) > 8 {
				continue
			}
			for p := range files {
				if p != path {
					peers[p] = true
				}
			}
		}
	}
	return sortedKeys(peers)
}

func (x *CodebaseIndex) SharedStatusPeers(path string) []string {
	statusFiles := map[string]map[string]bool{}
	for p, facts := range x.Files {
		if isTestFile(p) {
			continue
		}
		for _, status := range facts.Statuses {
			if statusFiles[status] == nil {
				statusFiles[status] = map[string]bool{}
			}
			statusFiles[status][p] = true
		}
	}
	counts := map[string]int{}
	if facts := x.Files[path]; facts != nil && !isTestFile(path) {
		for _, status := range facts.Statuses {
			files := statusFiles[status]
			if len(files) > 12 {
				continue
			}
			for p := range files {
				if p != path {
					counts[p]++
				}
			}
		}
	}
	peers := map[string]bool{}
	for p, count := range counts {
		if count >= 2 {
			peers[p] = true
		}
	}
	return sortedKeys(peers)
}

func (x *CodebaseIndex) PairedModules(path string) []string {
	stem := strings.ToLower(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
	if stem == "" || genericModuleStems[stem] {
		return nil
	}
	peers := map[string]bool{}
	shared := map[string]map[string]bool{}
	for p, facts := range x.Files {
		if isTestFile(p) {
			continue
		}
		exported := map[string]bool{}
		for _, name := range x.ExportedSymbols(p) {
			exported[strings.ToLower(name)] = true
		}
		for _, symbol := range facts.Symbols {
			name := strings.ToLower(symbol.Name)
			if exported[name] && !genericSymbolNames[name] {
				if shared[name] == nil {
					shared[name] = map[string]bool{}
				}
				shared[name][p] = true
			}
		}
	}
	counts := map[string]int{}
	if facts := x.Files[path]; facts != nil && !isTestFile(path) {
		exported := map[string]bool{}
		for _, name := range x.ExportedSymbols(path) {
			exported[strings.ToLower(name)] = true
		}
		for _, symbol := range facts.Symbols {
			name := strings.ToLower(symbol.Name)
			files := shared[name]
			if exported[name] && !genericSymbolNames[name] && len(files) <= 6 {
				for p := range files {
					if p != path && filepath.Dir(p) != filepath.Dir(path) {
						counts[p]++
					}
				}
			}
		}
	}
	for p := range x.Files {
		if p == path || isTestFile(p) {
			continue
		}
		other := strings.ToLower(strings.TrimSuffix(filepath.Base(p), filepath.Ext(p)))
		if other == stem && filepath.Dir(p) != filepath.Dir(path) {
			peers[p] = true
		}
	}
	for p, count := range counts {
		if count >= 2 {
			peers[p] = true
		}
	}
	return sortedKeys(peers)
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func (x *CodebaseIndex) Resolve() { x.finalize() }
