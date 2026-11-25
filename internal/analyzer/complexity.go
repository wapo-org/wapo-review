package analyzer

import (
	"fmt"
	"path"
	"strings"

	gts "github.com/odvcencio/gotreesitter"
	"github.com/wapo-org/wapo-review/internal/ast"
)

type FunctionComplexity struct {
	File      string
	Name      string
	StartLine int
	EndLine   int
	Score     int
	Delta     int
}

var topLevelFunctionTypes = map[string]bool{
	"function_declaration":           true,
	"generator_function_declaration": true,
	"function_definition":            true,
	"function_item":                  true,
	"method_definition":              true,
	"method_declaration":             true,
	"constructor_declaration":        true,
}

var functionNodesByLang = map[string]map[string]bool{
	"python": {"function_definition": true},
	"javascript": {
		"function_declaration": true, "function_expression": true,
		"method_definition": true, "arrow_function": true,
		"generator_function_declaration": true,
	},
	"typescript": {
		"function_declaration": true, "function_expression": true,
		"method_definition": true, "arrow_function": true,
		"generator_function_declaration": true,
	},
	"tsx": {
		"function_declaration": true, "function_expression": true,
		"method_definition": true, "arrow_function": true,
		"generator_function_declaration": true,
	},
	"go":   {"function_declaration": true, "method_declaration": true},
	"rust": {"function_item": true},
	"java": {"method_declaration": true, "constructor_declaration": true},
}

var nestedLambdaTypes = map[string]bool{
	"function_definition":            true,
	"function_declaration":           true,
	"function_expression":            true,
	"generator_function_declaration": true,
	"method_definition":              true,
	"arrow_function":                 true,
	"function":                       true,
	"func_literal":                   true,
	"lambda":                         true,
	"lambda_expression":              true,
	"closure_expression":             true,
	"function_item":                  true,
	"method_declaration":             true,
	"constructor_declaration":        true,
}

var loopAndSwitchTypes = map[string]bool{
	"for_statement":               true,
	"for_in_statement":            true,
	"for_of_statement":            true,
	"for_expression":              true,
	"enhanced_for_statement":      true,
	"while_statement":             true,
	"while_expression":            true,
	"do_statement":                true,
	"loop_expression":             true,
	"switch_statement":            true,
	"switch_expression":           true,
	"expression_switch_statement": true,
	"type_switch_statement":       true,
	"select_statement":            true,
	"match_expression":            true,
	"match_statement":             true,
}

var ternaryTypes = map[string]bool{
	"ternary_expression":     true,
	"conditional_expression": true,
}

var catchTypes = map[string]bool{
	"catch_clause":        true,
	"except_clause":       true,
	"except_group_clause": true,
}

var classTypes = map[string]bool{
	"class_definition":  true,
	"class_declaration": true,
	"class_expression":  true,
	"impl_item":         true,
}

func CognitiveComplexities(file string, src []byte) ([]FunctionComplexity, error) {
	if excludedComplexityPath(file) {
		return nil, nil
	}
	p, err := ast.Parse(file, src)
	if err != nil {
		return nil, err
	}
	lang := p.Language
	langName := fileLang(file)
	fnTypes := functionNodesByLang[langName]
	if len(fnTypes) == 0 {
		fnTypes = topLevelFunctionTypes
	}

	root := p.Tree.RootNode()
	var out []FunctionComplexity

	var collect func(n, parent *gts.Node)
	collect = func(n, parent *gts.Node) {
		if n == nil {
			return
		}
		typ := n.Type(lang)
		if classTypes[typ] {
			for i := 0; i < n.NamedChildCount(); i++ {
				collect(n.NamedChild(i), n)
			}
			return
		}
		if fnTypes[typ] {
			name := extractFuncNameWithParent(n, parent, lang, src)
			body := bodyNodeOf(n, lang)
			isJS := langName == "javascript" || langName == "typescript" || langName == "tsx"
			jsWrapper := isJS && !hasDirectControlFlow(body, lang)
			sc := &complexityScorer{
				lang:      lang,
				langName:  langName,
				src:       src,
				funcName:  name,
				jsWrapper: jsWrapper,
				seenBool:  map[*gts.Node]bool{},
			}
			score := sc.visit(body, 0, true)
			out = append(out, FunctionComplexity{
				File:      file,
				Name:      name,
				StartLine: int(n.StartPoint().Row) + 1,
				EndLine:   int(n.EndPoint().Row) + 1,
				Score:     score,
			})
			return
		}
		if parent == root && (typ == "if_statement" || typ == "if_expression" || loopAndSwitchTypes[typ] || typ == "try_statement") {
			sc := &complexityScorer{
				lang:     lang,
				langName: langName,
				src:      src,
				seenBool: map[*gts.Node]bool{},
			}
			score := sc.visit(n, 0, true)
			if score > 0 {
				out = append(out, FunctionComplexity{
					File:      file,
					Name:      "<top-level>",
					StartLine: int(n.StartPoint().Row) + 1,
					EndLine:   int(n.EndPoint().Row) + 1,
					Score:     score,
				})
			}
			return
		}
		for i := 0; i < n.NamedChildCount(); i++ {
			collect(n.NamedChild(i), n)
		}
	}
	collect(root, nil)
	return out, nil
}

func excludedComplexityPath(file string) bool {
	clean := strings.ToLower(strings.Trim(path.Clean(strings.ReplaceAll(file, "\\", "/")), "/"))
	base := path.Base(clean)
	if strings.HasSuffix(base, "_test.go") || strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") ||
		strings.HasSuffix(base, ".pb.go") || strings.HasSuffix(base, "_gen.go") {
		return true
	}
	for _, segment := range strings.Split(clean, "/") {
		switch segment {
		case "tests", "__tests__", "testdata", "fixtures", "golden", "mocks", "vendor", "node_modules":
			return true
		}
	}
	return strings.Contains(clean, "evals/cases/") || strings.HasPrefix(clean, "evals/cases/")
}

func extractFuncNameWithParent(n, parent *gts.Node, lang *gts.Language, src []byte) string {
	if id := n.ChildByFieldName("name", lang); id != nil {
		return strings.TrimSpace(id.Text(src))
	}
	if parent != nil {
		pt := parent.Type(lang)
		if pt == "variable_declarator" || pt == "pair" || pt == "assignment" || pt == "public_field_definition" || pt == "field_definition" {
			for _, field := range []string{"name", "key", "left"} {
				if id := parent.ChildByFieldName(field, lang); id != nil {
					return strings.TrimSpace(id.Text(src))
				}
			}
		}
	}
	for i := 0; i < n.NamedChildCount(); i++ {
		ch := n.NamedChild(i)
		t := ch.Type(lang)
		if t == "identifier" || t == "property_identifier" || t == "field_identifier" {
			return strings.TrimSpace(ch.Text(src))
		}
	}
	return "<anonymous>"
}

func bodyNodeOf(n *gts.Node, lang *gts.Language) *gts.Node {
	if b := n.ChildByFieldName("body", lang); b != nil {
		return b
	}
	for i := n.NamedChildCount() - 1; i >= 0; i-- {
		ch := n.NamedChild(i)
		t := ch.Type(lang)
		if t == "block" || t == "statement_block" || t == "function_body" || t == "expression_body" || t == "compound_statement" {
			return ch
		}
	}
	return n
}

func hasDirectControlFlow(body *gts.Node, lang *gts.Language) bool {
	if body == nil {
		return false
	}
	var check func(*gts.Node) bool
	check = func(n *gts.Node) bool {
		if n == nil {
			return false
		}
		t := n.Type(lang)
		if nestedLambdaTypes[t] {
			return false
		}
		if t == "if_statement" || t == "if_expression" || loopAndSwitchTypes[t] || ternaryTypes[t] || catchTypes[t] {
			return true
		}
		if boolOpOf(n, lang) != "" {
			return true
		}
		for i := 0; i < n.NamedChildCount(); i++ {
			if check(n.NamedChild(i)) {
				return true
			}
		}
		return false
	}
	for i := 0; i < body.NamedChildCount(); i++ {
		if check(body.NamedChild(i)) {
			return true
		}
	}
	return false
}

type complexityScorer struct {
	lang      *gts.Language
	langName  string
	src       []byte
	funcName  string
	jsWrapper bool
	seenBool  map[*gts.Node]bool
}

func (s *complexityScorer) isNegation(n *gts.Node) bool {
	t := n.Type(s.lang)
	if t == "not_operator" {
		return true
	}
	if t == "unary_expression" {
		if op := n.ChildByFieldName("operator", s.lang); op != nil && strings.TrimSpace(op.Text(s.src)) == "!" {
			return true
		}
		for _, ch := range n.Children() {
			if !ch.IsNamed() && strings.TrimSpace(ch.Text(s.src)) == "!" {
				return true
			}
		}
	}
	return false
}

func (s *complexityScorer) scoreLogicalRoot(n *gts.Node, nesting int) int {
	var tokens []string // "" represents negation sequence break
	var sideNodes []*gts.Node

	var collect func(*gts.Node)
	collect = func(cur *gts.Node) {
		if cur == nil {
			return
		}
		ct := cur.Type(s.lang)
		if ct == "parenthesized_expression" || ct == "parenthesized_condition" {
			for i := 0; i < cur.NamedChildCount(); i++ {
				collect(cur.NamedChild(i))
			}
			return
		}
		if op := boolOpOf(cur, s.lang); op != "" {
			s.seenBool[cur] = true
			left := cur.ChildByFieldName("left", s.lang)
			right := cur.ChildByFieldName("right", s.lang)
			if left == nil || right == nil {
				if cur.NamedChildCount() >= 1 {
					left = cur.NamedChild(0)
				}
				if cur.NamedChildCount() >= 2 {
					right = cur.NamedChild(1)
				}
			}
			if left != nil {
				collect(left)
			}
			tokens = append(tokens, op)
			if right != nil {
				collect(right)
			}
			return
		}
		if s.isNegation(cur) {
			tokens = append(tokens, "")
			for i := 0; i < cur.NamedChildCount(); i++ {
				collect(cur.NamedChild(i))
			}
			return
		}
		sideNodes = append(sideNodes, cur)
	}

	collect(n)
	total := 0
	prev := ""
	for _, op := range tokens {
		if op == "" {
			prev = ""
		} else if op != prev {
			total++
			prev = op
		}
	}
	for _, side := range sideNodes {
		total += s.visit(side, nesting, false)
	}
	return total
}

func (s *complexityScorer) visitIf(n *gts.Node, nesting int, isElseIf bool) int {
	total := 1
	if !isElseIf {
		total += nesting
	}
	cond := n.ChildByFieldName("condition", s.lang)
	conseq := n.ChildByFieldName("consequence", s.lang)
	alt := n.ChildByFieldName("alternative", s.lang)

	if cond != nil {
		total += s.visit(cond, nesting, false)
	}
	if conseq != nil {
		total += s.visit(conseq, nesting+1, false)
	}
	for i := 0; i < n.NamedChildCount(); i++ {
		ch := n.NamedChild(i)
		if ch == cond || ch == conseq || ch == alt {
			continue
		}
		ct := ch.Type(s.lang)
		switch ct {
		case "elif_clause", "else_if_clause":
			total += s.visitElif(ch, nesting)
		case "else_clause":
			total += s.visitElse(ch, nesting)
		default:
			total += s.visit(ch, nesting+1, false)
		}
	}
	if alt != nil {
		at := alt.Type(s.lang)
		switch {
		case at == "else_clause":
			total += s.visitElse(alt, nesting)
		case at == "elif_clause" || at == "else_if_clause":
			total += s.visitElif(alt, nesting)
		case at == "if_statement" || at == "if_expression":
			total += s.visitIf(alt, nesting, true)
		default:
			total += 1
			total += s.visit(alt, nesting+1, false)
		}
	}
	return total
}

func (s *complexityScorer) visitElif(n *gts.Node, nesting int) int {
	total := 1
	cond := n.ChildByFieldName("condition", s.lang)
	conseq := n.ChildByFieldName("consequence", s.lang)
	if cond != nil {
		total += s.visit(cond, nesting, false)
	}
	if conseq != nil {
		total += s.visit(conseq, nesting+1, false)
	}
	for i := 0; i < n.NamedChildCount(); i++ {
		ch := n.NamedChild(i)
		if ch == cond || ch == conseq {
			continue
		}
		total += s.visit(ch, nesting+1, false)
	}
	return total
}

func (s *complexityScorer) visitElse(n *gts.Node, nesting int) int {
	if childIf := firstDirectIfChild(n, s.lang); childIf != nil {
		return s.visitIf(childIf, nesting, true)
	}
	total := 1
	for i := 0; i < n.NamedChildCount(); i++ {
		total += s.visit(n.NamedChild(i), nesting+1, false)
	}
	return total
}

func (s *complexityScorer) visit(n *gts.Node, nesting int, isRoot bool) int {
	if n == nil {
		return 0
	}
	typ := n.Type(s.lang)

	if !isRoot && nestedLambdaTypes[typ] {
		nextNest := nesting + 1
		if s.jsWrapper && nesting == 0 {
			nextNest = nesting
		}
		body := bodyNodeOf(n, s.lang)
		if body != n {
			return s.visit(body, nextNest, false)
		}
		total := 0
		for i := 0; i < n.NamedChildCount(); i++ {
			total += s.visit(n.NamedChild(i), nextNest, false)
		}
		return total
	}

	if typ == "if_statement" || typ == "if_expression" {
		return s.visitIf(n, nesting, false)
	}
	if typ == "elif_clause" || typ == "else_if_clause" {
		return s.visitElif(n, nesting)
	}
	if typ == "else_clause" {
		return s.visitElse(n, nesting)
	}

	if loopAndSwitchTypes[typ] {
		total := 1 + nesting
		body := n.ChildByFieldName("body", s.lang)
		if body != nil {
			for i := 0; i < n.NamedChildCount(); i++ {
				ch := n.NamedChild(i)
				if ch == body {
					total += s.visit(ch, nesting+1, false)
				} else {
					total += s.visit(ch, nesting, false)
				}
			}
		} else {
			for i := 0; i < n.NamedChildCount(); i++ {
				total += s.visit(n.NamedChild(i), nesting+1, false)
			}
		}
		return total
	}

	if ternaryTypes[typ] {
		total := 1 + nesting
		cond := n.ChildByFieldName("condition", s.lang)
		for i := 0; i < n.NamedChildCount(); i++ {
			ch := n.NamedChild(i)
			if cond != nil && ch == cond {
				total += s.visit(ch, nesting, false)
			} else {
				total += s.visit(ch, nesting+1, false)
			}
		}
		return total
	}

	if catchTypes[typ] {
		total := 1 + nesting
		for i := 0; i < n.NamedChildCount(); i++ {
			total += s.visit(n.NamedChild(i), nesting+1, false)
		}
		return total
	}

	if boolOpOf(n, s.lang) != "" && !s.seenBool[n] {
		return s.scoreLogicalRoot(n, nesting)
	}

	if typ == "goto_statement" {
		return 1
	}
	if typ == "break_statement" || typ == "continue_statement" || typ == "break_expression" || typ == "continue_expression" {
		if hasLabelChild(n, s.lang) {
			return 1
		}
		return 0
	}

	total := 0
	if !isRoot && (typ == "call_expression" || typ == "call" || typ == "method_invocation") {
		if s.isDirectRecursion(n) {
			total++
		}
	}
	for i := 0; i < n.NamedChildCount(); i++ {
		total += s.visit(n.NamedChild(i), nesting, false)
	}
	return total
}

func (s *complexityScorer) isDirectRecursion(call *gts.Node) bool {
	if s.funcName == "" || s.funcName == "<anonymous>" {
		return false
	}
	if call.Type(s.lang) == "method_invocation" {
		nameNode := call.ChildByFieldName("name", s.lang)
		objNode := call.ChildByFieldName("object", s.lang)
		if nameNode == nil || strings.TrimSpace(nameNode.Text(s.src)) != s.funcName {
			return false
		}
		return objNode == nil || strings.TrimSpace(objNode.Text(s.src)) == "this"
	}
	fn := call.ChildByFieldName("function", s.lang)
	if fn == nil && call.NamedChildCount() > 0 {
		fn = call.NamedChild(0)
	}
	if fn == nil {
		return false
	}
	txt := strings.TrimSpace(fn.Text(s.src))
	if txt == s.funcName {
		return true
	}
	if s.langName == "python" && txt == "self."+s.funcName {
		return true
	}
	if (s.langName == "javascript" || s.langName == "typescript" || s.langName == "tsx" || s.langName == "java") && txt == "this."+s.funcName {
		return true
	}
	return false
}

func hasLabelChild(n *gts.Node, lang *gts.Language) bool {
	for i := 0; i < n.NamedChildCount(); i++ {
		t := n.NamedChild(i).Type(lang)
		if t == "statement_identifier" || t == "label_name" || t == "identifier" || t == "label" || t == "lifetime" {
			return true
		}
	}
	return false
}

func firstDirectIfChild(n *gts.Node, lang *gts.Language) *gts.Node {
	for i := 0; i < n.NamedChildCount(); i++ {
		ch := n.NamedChild(i)
		t := ch.Type(lang)
		if t == "if_statement" || t == "if_expression" {
			return ch
		}
	}
	return nil
}

func boolOpOf(n *gts.Node, lang *gts.Language) string {
	if n == nil {
		return ""
	}
	t := n.Type(lang)
	if t != "binary_expression" && t != "logical_expression" && t != "boolean_operator" {
		return ""
	}
	for _, ch := range n.Children() {
		if ch.IsNamed() {
			continue
		}
		switch ch.Type(lang) {
		case "&&", "and":
			return "&&"
		case "||", "or":
			return "||"
		}
	}
	return ""
}

// ComputeComplexityFindings computes per-function Cognitive Complexity and
// deltas against baseSrc (when provided), emitting findings when thresholds are exceeded.
func ComputeComplexityFindings(path string, headSrc, baseSrc []byte, cfg ComplexityConfig, diff Diff) ([]FunctionComplexity, []Finding) {
	headFuncs, err := CognitiveComplexities(path, headSrc)
	if err != nil {
		return nil, nil
	}
	baseScores := map[string]int{}
	if len(baseSrc) > 0 {
		if bf, err := CognitiveComplexities(path, baseSrc); err == nil {
			for _, f := range bf {
				baseScores[f.Name] = f.Score
			}
		}
	}
	highThresh := cfg.High
	if highThresh <= 0 {
		highThresh = 15
	}
	var findings []Finding
	for i := range headFuncs {
		fn := &headFuncs[i]
		if prev, ok := baseScores[fn.Name]; ok {
			fn.Delta = fn.Score - prev
		} else {
			fn.Delta = fn.Score
		}
		touched := len(diff.Files) == 0
		if !touched {
			for ln := fn.StartLine; ln <= fn.EndLine; ln++ {
				if diff.IsNew(path, ln) {
					touched = true
					break
				}
			}
		}
		if !touched {
			continue
		}
		// Clean-as-You-Code: only flag complexity when the PR actually added or
		// worsened the function's complexity (delta > 0), never when unchanged/improved.
		if fn.Delta <= 0 {
			continue
		}
		if fn.Score > highThresh {
			f := newFinding(
				"COMPLEXITY.cognitive-high",
				"maintainability",
				"medium",
				path,
				fn.StartLine,
				fn.EndLine,
				fmt.Sprintf("Function %q has cognitive complexity %d (threshold %d, delta %+d)", fn.Name, fn.Score, highThresh, fn.Delta),
				fmt.Sprintf("score=%d delta=%+d", fn.Score, fn.Delta),
			)
			f.NewCode = true
			findings = append(findings, f)
		} else if cfg.MaxNew > 0 && fn.Delta > cfg.MaxNew {
			f := newFinding(
				"COMPLEXITY.cognitive-delta",
				"maintainability",
				"medium",
				path,
				fn.StartLine,
				fn.EndLine,
				fmt.Sprintf("Function %q increased cognitive complexity by +%d (now %d)", fn.Name, fn.Delta, fn.Score),
				fmt.Sprintf("score=%d delta=%+d", fn.Score, fn.Delta),
			)
			f.NewCode = true
			findings = append(findings, f)
		}
	}
	return headFuncs, findings
}
