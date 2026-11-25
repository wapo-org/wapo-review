package ast

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	gts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

type ParsedFile struct {
	Filename string
	Source   []byte
	Language *gts.Language
	Tree     *gts.Tree
}
type Symbol struct {
	File, Name, QualifiedName, Kind, Signature string
	StartLine, EndLine                         int
	Exported                                   bool
	StartByte, EndByte                         int
}
type Import struct {
	File, Path string
	StartLine  int
}
type Call struct {
	File, Name string
	StartLine  int
}
type CodeChunk struct {
	File, Symbol, Kind, Text string
	StartLine, EndLine       int
}
type FileFacts struct {
	Parsed   *ParsedFile
	Symbols  []Symbol
	Imports  []Import
	Calls    []Call
	Chunks   []CodeChunk
	Tables   []string
	Statuses []string
}

var tablePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\.(?:query|insert|replace|delete|update|normalizeId)\s*\(\s*["'\x60]([a-z_][a-z0-9_]*)["'\x60]`),
	regexp.MustCompile(`(?i)\b(?:FROM|INTO|UPDATE|DELETE\s+FROM)\s+["'\x60]?([a-z_][a-z0-9_]*)`),
	regexp.MustCompile(`(?i)\bdefineTable\s*\(\s*\{\s*["'\x60]?([a-z_][a-z0-9_]*)["'\x60]?\s*:`),
	regexp.MustCompile(`(?i)\b(?:pgTable|mysqlTable|sqliteTable)\s*\(\s*["'\x60]([a-z_][a-z0-9_]*)["'\x60]`),
	regexp.MustCompile(`(?i)\bmodel\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`),
}

var statusTokens = map[string]bool{"pending": true, "running": true, "paused": true, "cancelling": true, "cancelled": true, "canceled": true, "approved": true, "rejected": true, "ready": true, "leased": true, "busy": true, "expired": true, "compacted": true, "failed": true, "completed": true, "committing": true}
var tableNoise = map[string]bool{"the": true, "and": true, "from": true, "into": true, "where": true, "user": true, "users": true, "data": true, "table": true, "this": true, "that": true, "new": true, "old": true, "set": true, "key": true, "value": true}

func extractInvariants(src []byte) (tables, statuses []string) {
	text := string(src)
	seenTables, seenStatuses := map[string]bool{}, map[string]bool{}
	for _, pattern := range tablePatterns {
		for _, match := range pattern.FindAllStringSubmatch(text, -1) {
			if len(match) < 2 {
				continue
			}
			name := strings.ToLower(match[1])
			if len(name) >= 3 && !tableNoise[name] && !seenTables[name] {
				seenTables[name] = true
				tables = append(tables, name)
			}
		}
	}
	word := regexp.MustCompile(`[A-Za-z]+`)
	for _, token := range word.FindAllString(text, -1) {
		status := strings.ToLower(token)
		if statusTokens[status] && !seenStatuses[status] {
			seenStatuses[status] = true
			statuses = append(statuses, status)
		}
	}
	sort.Strings(tables)
	sort.Strings(statuses)
	return tables, statuses
}

func LanguageForFile(path string) *gts.Language {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ts", ".mts", ".cts":
		return grammars.TypescriptLanguage()
	case ".tsx":
		return grammars.TsxLanguage()
	case ".js", ".jsx", ".mjs", ".cjs":
		return grammars.JavascriptLanguage()
	case ".py":
		return grammars.PythonLanguage()
	case ".go":
		return grammars.GoLanguage()
	case ".rs":
		return grammars.RustLanguage()
	case ".java":
		return grammars.JavaLanguage()
	default:
		return nil
	}
}

func Parse(filename string, src []byte) (*ParsedFile, error) {
	lang := LanguageForFile(filename)
	if lang == nil {
		return nil, fmt.Errorf("unsupported source extension: %s", filepath.Ext(filename))
	}
	tree, err := gts.NewParser(lang).Parse(src)
	if err != nil {
		return nil, err
	}
	return &ParsedFile{Filename: filename, Source: append([]byte(nil), src...), Language: lang, Tree: tree}, nil
}

type ExclusionDecision struct {
	Excluded bool
	Reason   string
}
type GitAttributeRule struct {
	Pattern                            string
	Generated, Vendored, Documentation bool
}

var vendored = map[string]bool{"node_modules": true, "vendor": true, "third_party": true, ".venv": true, "dist": true, "build": true, "target": true, "Pods": true, "__pycache__": true, ".next": true, ".nuxt": true}
var generated = map[string]bool{"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "uv.lock": true, "Cargo.lock": true, "go.sum": true, "poetry.lock": true}

func IsExcluded(path string, headerLines []string, rules []GitAttributeRule, extraGlobs []string) ExclusionDecision {
	p := strings.TrimPrefix(filepath.ToSlash(path), "./")
	name := filepath.Base(p)
	for _, part := range strings.Split(p, "/") {
		if vendored[part] {
			return ExclusionDecision{true, "vendored path"}
		}
	}
	if generated[name] || strings.HasSuffix(name, ".min.js") || strings.HasSuffix(name, ".min.css") || strings.HasSuffix(name, ".pb.go") || strings.HasSuffix(name, "_pb2.py") || strings.HasSuffix(name, ".snap") || strings.Contains(name, ".generated.") || strings.Contains("/"+p+"/", "/_generated/") {
		return ExclusionDecision{true, "generated artifact"}
	}
	for i, line := range headerLines {
		if i == 5 {
			break
		}
		low := strings.ToLower(line)
		for _, marker := range []string{"code generated by", "do not edit", "@generated", "auto-generated"} {
			if strings.Contains(low, marker) {
				return ExclusionDecision{true, "generated file header"}
			}
		}
	}
	for _, r := range rules {
		if (r.Generated || r.Vendored || r.Documentation) && globMatch(r.Pattern, p) {
			return ExclusionDecision{true, "gitattributes: " + r.Pattern}
		}
	}
	for _, pattern := range extraGlobs {
		if globMatch(pattern, p) {
			return ExclusionDecision{true, "extra exclusion glob"}
		}
	}
	return ExclusionDecision{}
}
func globMatch(pattern, path string) bool {
	if ok, _ := filepath.Match(pattern, path); ok {
		return true
	}
	if strings.Contains(pattern, "/") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if ok, _ := filepath.Match(pattern, part); ok {
			return true
		}
	}
	return false
}

func ExtractFileFacts(path string, src []byte) (*FileFacts, error) {
	p, err := Parse(path, src)
	if err != nil {
		return nil, err
	}
	facts := &FileFacts{Parsed: p}
	facts.Tables, facts.Statuses = extractInvariants(src)
	definitions := map[string]string{"function_definition": "function", "function_declaration": "function", "method_definition": "method", "method_declaration": "method", "function_item": "function", "class_definition": "class", "class_declaration": "class", "interface_declaration": "interface", "struct_item": "struct", "type_declaration": "struct"}
	var walk func(*gts.Node, []string)
	walk = func(n *gts.Node, parents []string) {
		if n == nil {
			return
		}
		typ := n.Type(p.Language)
		kind := definitions[typ]
		nameNode := n.ChildByFieldName("name", p.Language)
		if kind != "" && nameNode != nil {
			name := nameNode.Text(src)
			start, end := int(n.StartPoint().Row)+1, int(n.EndPoint().Row)+1
			sig := strings.TrimSpace(strings.SplitN(n.Text(src), "\n", 2)[0])
			sym := Symbol{File: path, Name: name, QualifiedName: strings.Join(append(append([]string{}, parents...), name), "."), Kind: kind, Signature: sig, StartLine: start, EndLine: end, Exported: strings.HasPrefix(sig, "export ") || strings.HasPrefix(sig, "pub ") || strings.HasPrefix(sig, "public ") || (strings.HasSuffix(path, ".py") && !strings.HasPrefix(name, "_")), StartByte: int(n.StartByte()), EndByte: int(n.EndByte())}
			facts.Symbols = append(facts.Symbols, sym)
			body := n.Text(src)
			if len(body) > 1200 {
				body = body[:1200]
			}
			facts.Chunks = append(facts.Chunks, CodeChunk{path, sym.QualifiedName, kind, body, start, end})
			parents = append(append([]string{}, parents...), name)
		}
		if strings.Contains(typ, "import") || typ == "use_declaration" {
			facts.Imports = append(facts.Imports, Import{path, strings.TrimSpace(n.Text(src)), int(n.StartPoint().Row) + 1})
		}
		if typ == "call" || typ == "call_expression" || typ == "method_invocation" {
			fn := n.ChildByFieldName("function", p.Language)
			if fn == nil {
				fn = n.ChildByFieldName("name", p.Language)
			}
			if fn != nil {
				raw := fn.Text(src)
				raw = strings.TrimSpace(raw[strings.LastIndex(raw, ".")+1:])
				facts.Calls = append(facts.Calls, Call{path, raw, int(n.StartPoint().Row) + 1})
			}
		}
		for _, c := range n.Children() {
			walk(c, parents)
		}
	}
	walk(p.Tree.RootNode(), nil)
	return facts, nil
}
