package analyzer

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	gts "github.com/odvcencio/gotreesitter"
	"github.com/wapo-org/wapo-review/internal/ast"
)

func fileLang(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ts", ".mts", ".cts":
		return "typescript"
	case ".tsx":
		return "tsx"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	case ".py":
		return "python"
	case ".go":
		return "go"
	case ".rs":
		return "rust"
	case ".java":
		return "java"
	default:
		return ""
	}
}

// AnalyzeLogic runs AST-based logic and security dataflow checks with strict
// zero-FP guards across TypeScript, JavaScript, Python, Go, Rust, and Java.
func AnalyzeLogic(path string, src []byte) []Finding {
	p, err := ast.Parse(path, src)
	if err != nil {
		return nil
	}
	lang := p.Language
	langName := fileLang(path)
	var out []Finding
	seenBool := map[*gts.Node]bool{}

	var walk func(*gts.Node)
	walk = func(n *gts.Node) {
		if n == nil {
			return
		}
		t := n.Type(lang)
		line := int(n.StartPoint().Row) + 1

		// 1. LOGIC.dead-branch via AST boolean operand decomposition.
		if op := boolOpOf(n, lang); op != "" && !seenBool[n] {
			operands := flattenBoolOperands(n, op, lang, seenBool)
			if reason := findContradiction(operands, lang, src); reason != "" {
				out = append(out, newFinding(
					"LOGIC.dead-branch",
					"logic",
					"warning",
					path,
					line,
					int(n.EndPoint().Row)+1,
					"Contradictory or tautological boolean condition: "+reason,
					strings.TrimSpace(n.Text(src)),
				))
			}
		}

		// Constant literal condition `if (false)` / `if False:` / `if (true) ... else`.
		if t == "if_statement" || t == "if_expression" {
			if cond := n.ChildByFieldName("condition", lang); cond != nil {
				norm := strings.TrimSpace(stripOuterParensText(cond.Text(src)))
				if norm == "false" || norm == "False" {
					out = append(out, newFinding("LOGIC.dead-branch", "logic", "warning", path, line, line, "Condition is always false", norm))
				} else if (norm == "true" || norm == "True") && hasElseBranch(n, lang) {
					out = append(out, newFinding("LOGIC.dead-branch", "logic", "warning", path, line, line, "Else branch is unreachable because condition is always true", norm))
				}
			}
			// Identical if/else branch bodies.
			if dup := duplicateIfElseBody(n, lang, src); dup != "" {
				out = append(out, newFinding("LOGIC.duplicate-branch", "logic", "warning", path, line, int(n.EndPoint().Row)+1, "Identical conditional branches", dup))
			}
		}

		// 2. LOGIC.unhandled-error: empty catch/except block with no comment explaining intent.
		if t == "catch_clause" || t == "except_clause" {
			body := n.ChildByFieldName("body", lang)
			if body == nil && n.NamedChildCount() > 0 {
				body = n.NamedChild(n.NamedChildCount() - 1)
			}
			if body != nil && isEmptyCatchBody(body, lang, src) {
				out = append(out, newFinding("LOGIC.unhandled-error", "logic", "warning", path, line, int(body.EndPoint().Row)+1, "Empty error handler silently swallows errors", strings.TrimSpace(n.Text(src))))
			}
		}

		// 3. LOGIC.bounds: off-by-one loop (`<= len(x)` / `<= x.length`) or guard (`index > len(items)` before `items[index]`).
		if t == "for_statement" || t == "for_clause" {
			if finding, ok := checkLoopBounds(n, path, src); ok {
				out = append(out, finding)
			}
		}
		if t == "function_declaration" || t == "method_declaration" {
			if langName == "go" {
				if finding, ok := checkGoGuardOffByOne(n, path, src); ok {
					out = append(out, finding)
				}
				if finding, ok := checkGoGoroutineRace(n, lang, path, src); ok {
					out = append(out, finding)
				}
			}
		}

		// 4. LOGIC.resource-leak: Python `handle = open(...)` without `with` or `.close()`.
		if langName == "python" && t == "function_definition" {
			out = append(out, checkPythonResourceLeak(n, lang, path, src)...)
		}

		// 5. SEC.injection: dynamic SQL concatenation/interpolation or Python shell=True with dynamic command.
		if t == "call_expression" || t == "call" || t == "method_invocation" {
			if finding, ok := checkInjectionCall(n, lang, langName, path, src); ok {
				out = append(out, finding)
			}
			if langName == "go" {
				if finding, ok := checkGoSSRF(n, path, src); ok {
					out = append(out, finding)
				}
			}
		}

		for _, ch := range n.Children() {
			walk(ch)
		}
	}
	walk(p.Tree.RootNode())

	out = append(out, AnalyzeNullableParameters(path, src)...)
	return out
}

var (
	loopBoundGoRe = regexp.MustCompile(`(\w+)\s*<=\s*len\(\s*(\w+)\s*\)`)
	loopBoundJSRe = regexp.MustCompile(`(\w+)\s*<=\s*(\w+)\.length\b`)
	goGuardGtRe   = regexp.MustCompile(`if\s+(\w+)\s*>\s*len\(\s*(\w+)\s*\)`)
)

func isSubtractedBound(txt string, matchEnd int) bool {
	rest := strings.TrimLeft(txt[matchEnd:], " \t")
	if !strings.HasPrefix(rest, "-") {
		return false
	}
	term := strings.TrimLeft(rest[1:], " \t")
	if strings.HasPrefix(term, "0") && (len(term) == 1 || term[1] < '0' || term[1] > '9') {
		return false
	}
	return term != ""
}

func checkLoopBounds(n *gts.Node, path string, src []byte) (Finding, bool) {
	txt := n.Text(src)
	line := int(n.StartPoint().Row) + 1
	if loc := loopBoundGoRe.FindStringSubmatchIndex(txt); loc != nil && !isSubtractedBound(txt, loc[1]) {
		idxVar, arrVar := txt[loc[2]:loc[3]], txt[loc[4]:loc[5]]
		if strings.Contains(txt, arrVar+"["+idxVar+"]") && !hasTerminalBoundsGuard(txt, idxVar, arrVar) {
			return newFinding("LOGIC.bounds", "logic", "high", path, line, int(n.EndPoint().Row)+1,
				fmt.Sprintf("Off-by-one loop condition %s <= len(%s) indexes %s[%s]", idxVar, arrVar, arrVar, idxVar), txt[loc[0]:loc[1]]), true
		}
	}
	if loc := loopBoundJSRe.FindStringSubmatchIndex(txt); loc != nil && !isSubtractedBound(txt, loc[1]) {
		idxVar, arrVar := txt[loc[2]:loc[3]], txt[loc[4]:loc[5]]
		if strings.Contains(txt, arrVar+"["+idxVar+"]") && !hasTerminalBoundsGuard(txt, idxVar, arrVar) {
			return newFinding("LOGIC.bounds", "logic", "high", path, line, int(n.EndPoint().Row)+1,
				fmt.Sprintf("Off-by-one loop condition %s <= %s.length indexes %s[%s]", idxVar, arrVar, arrVar, idxVar), txt[loc[0]:loc[1]]), true
		}
	}
	return Finding{}, false
}

func hasTerminalBoundsGuard(loop, index, slice string) bool {
	bodyStart := strings.IndexByte(loop, '{')
	if bodyStart < 0 {
		return false
	}
	body := loop[bodyStart+1:]
	guard := regexp.MustCompile(`(?s)if\s+` + regexp.QuoteMeta(index) + `\s*(?:==|>=)\s*(?:len\(\s*` + regexp.QuoteMeta(slice) + `\s*\)|` + regexp.QuoteMeta(slice) + `\.length)\s*\{?\s*(?:return\b|break\b|continue\b)`)
	indexing := strings.Index(body, slice+"["+index+"]")
	for _, match := range guard.FindAllStringIndex(body, -1) {
		if indexing >= 0 && match[0] >= indexing {
			continue
		}
		// Require the guard to be at top-level depth inside the loop body (not nested in another conditional).
		depth := 0
		for _, ch := range body[:match[0]] {
			switch ch {
			case '{':
				depth++
			case '}':
				depth--
			}
		}
		if depth == 0 {
			return true
		}
	}
	return false
}

func checkGoGuardOffByOne(fn *gts.Node, path string, src []byte) (Finding, bool) {
	txt := fn.Text(src)
	m := goGuardGtRe.FindStringSubmatchIndex(txt)
	if m == nil {
		return Finding{}, false
	}
	sub := goGuardGtRe.FindStringSubmatch(txt)
	idxVar, arrVar := sub[1], sub[2]
	rest := txt[m[1]:]
	if strings.Contains(rest, arrVar+"["+idxVar+"]") && !strings.Contains(txt, idxVar+" >= len("+arrVar+")") {
		line := int(fn.StartPoint().Row) + 1 + strings.Count(txt[:m[0]], "\n")
		return newFinding("LOGIC.bounds", "logic", "high", path, line, line,
			fmt.Sprintf("Boundary check %s > len(%s) permits %s == len(%s) before indexing %s[%s]", idxVar, arrVar, idxVar, arrVar, arrVar, idxVar),
			sub[0]), true
	}
	return Finding{}, false
}

var (
	goMutateRe = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*(\+\+|--|\+=|-=|=[^=])`)
	goDeclRe   = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*:=`)
)

func checkGoGoroutineRace(fn *gts.Node, lang *gts.Language, path string, src []byte) (Finding, bool) {
	fnText := fn.Text(src)
	if !strings.Contains(fnText, "go ") {
		return Finding{}, false
	}
	// Collect local variables declared in the enclosing function outside goroutines.
	outerVars := map[string]bool{}
	for _, m := range goDeclRe.FindAllStringSubmatch(fnText, -1) {
		outerVars[m[1]] = true
	}
	var found Finding
	var ok bool
	var walk func(*gts.Node)
	walk = func(n *gts.Node) {
		if n == nil || ok {
			return
		}
		if n.Type(lang) == "go_statement" {
			gt := n.Text(src)
			if strings.Contains(gt, ".Lock()") || strings.Contains(gt, "atomic.") {
				return
			}
			for _, m := range goMutateRe.FindAllStringSubmatch(gt, -1) {
				v := m[1]
				if outerVars[v] && !strings.Contains(gt, v+":=") && !strings.Contains(gt, v+" :=") {
					line := int(n.StartPoint().Row) + 1
					found = newFinding("LOGIC.concurrency", "logic", "high", path, line, int(n.EndPoint().Row)+1,
						fmt.Sprintf("Goroutine mutates captured variable %q without synchronization", v), strings.TrimSpace(gt))
					ok = true
					return
				}
			}
		}
		for _, ch := range n.Children() {
			walk(ch)
		}
	}
	walk(fn)
	return found, ok
}

var pyOpenAssignRe = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*open\(`)

func checkPythonResourceLeak(fn *gts.Node, _ *gts.Language, path string, src []byte) []Finding {
	txt := fn.Text(src)
	var out []Finding
	for _, loc := range pyOpenAssignRe.FindAllStringSubmatchIndex(txt, -1) {
		handle := txt[loc[2]:loc[3]]
		lineStart := strings.LastIndex(txt[:loc[0]], "\n") + 1
		lineText := txt[lineStart:loc[1]]
		if strings.Contains(lineText, "with ") {
			continue
		}
		if strings.Contains(txt[loc[1]:], handle+".close(") {
			continue
		}
		line := int(fn.StartPoint().Row) + 1 + strings.Count(txt[:loc[0]], "\n")
		out = append(out, newFinding("LOGIC.resource-leak", "logic", "medium", path, line, line,
			fmt.Sprintf("File handle %q opened without a context manager or close()", handle), strings.TrimSpace(lineText)))
	}
	return out
}

var sqlClauseRe = regexp.MustCompile(`(?i)\b(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM)\b`)

func callMethodName(call *gts.Node, lang *gts.Language, src []byte) string {
	if call.Type(lang) == "method_invocation" {
		if nm := call.ChildByFieldName("name", lang); nm != nil {
			return strings.TrimSpace(nm.Text(src))
		}
	}
	fn := call.ChildByFieldName("function", lang)
	if fn == nil && call.NamedChildCount() > 0 {
		fn = call.NamedChild(0)
	}
	if fn == nil {
		return ""
	}
	txt := strings.TrimSpace(fn.Text(src))
	if idx := strings.LastIndex(txt, "."); idx >= 0 {
		return txt[idx+1:]
	}
	return txt
}

func callArgsText(call *gts.Node, lang *gts.Language, src []byte) string {
	if args := call.ChildByFieldName("arguments", lang); args != nil {
		return args.Text(src)
	}
	for i := 0; i < call.NamedChildCount(); i++ {
		ch := call.NamedChild(i)
		t := ch.Type(lang)
		if t == "arguments" || t == "argument_list" {
			return ch.Text(src)
		}
	}
	return ""
}

func checkInjectionCall(call *gts.Node, lang *gts.Language, langName, path string, src []byte) (Finding, bool) {
	txt := call.Text(src)
	line := int(call.StartPoint().Row) + 1
	callee := strings.ToLower(callMethodName(call, lang, src))

	// SQL injection: inspect ONLY direct SQL execution/query callees and their direct arguments,
	// never outer wrapper calls like `internalMutation(...)` or `describe(...)`.
	switch callee {
	case "execute", "executequery", "executeupdate", "query", "raw", "exec":
		argsTxt := callArgsText(call, lang, src)
		if len(argsTxt) > 2000 {
			return Finding{}, false
		}
		if sqlClauseRe.MatchString(argsTxt) && (strings.Contains(argsTxt, "+") || strings.Contains(argsTxt, "${")) {
			return newFinding("SEC.injection", "security", "critical", path, line, int(call.EndPoint().Row)+1,
				"Dynamic input concatenated or interpolated into SQL query", strings.TrimSpace(txt)), true
		}
		// Check single-identifier query variable built via SQL template interpolation in the same file.
		if langName == "typescript" || langName == "tsx" || langName == "javascript" {
			trimmedArgs := strings.TrimSpace(strings.Trim(argsTxt, "()"))
			if trimmedArgs != "" && !strings.ContainsAny(trimmedArgs, " ,\"'`") {
				assignRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(trimmedArgs) + `\s*=\s*` + "`[^`]*\\$\\{[^`]*`")
				if m := assignRe.FindString(string(src)); m != "" && sqlClauseRe.MatchString(m) {
					return newFinding("SEC.injection", "security", "critical", path, line, line,
						"Interpolated SQL query string passed to database query", strings.TrimSpace(txt)), true
				}
			}
		}
	}

	// Python command injection: direct subprocess.*(..., shell=True)
	if langName == "python" && strings.HasPrefix(strings.TrimSpace(txt), "subprocess.") && strings.Contains(txt, "shell=True") {
		return newFinding("SEC.injection", "security", "critical", path, line, int(call.EndPoint().Row)+1,
			"Subprocess executed with shell=True", strings.TrimSpace(txt)), true
	}
	return Finding{}, false
}

var goHTTPGetRe = regexp.MustCompile(`^http\.(Get|Post|PostForm|Head)\(\s*([A-Za-z_][A-Za-z0-9_.]*)`)

func checkGoSSRF(call *gts.Node, path string, src []byte) (Finding, bool) {
	txt := strings.TrimSpace(call.Text(src))
	if m := goHTTPGetRe.FindStringSubmatch(txt); m != nil {
		line := int(call.StartPoint().Row) + 1
		return newFinding("SEC.ssrf-egress", "security", "high", path, line, line,
			fmt.Sprintf("Outbound HTTP request %s uses dynamic URL %q without destination validation", m[1], m[2]), txt), true
	}
	return Finding{}, false
}

func flattenBoolOperands(n *gts.Node, targetOp string, lang *gts.Language, seen map[*gts.Node]bool) []*gts.Node {
	if n == nil {
		return nil
	}
	if boolOpOf(n, lang) == targetOp {
		seen[n] = true
		var ops []*gts.Node
		for i := 0; i < n.NamedChildCount(); i++ {
			ch := n.NamedChild(i)
			ops = append(ops, flattenBoolOperands(ch, targetOp, lang, seen)...)
		}
		return ops
	}
	return []*gts.Node{n}
}

func unwrapParensNode(n *gts.Node, lang *gts.Language) *gts.Node {
	for n != nil {
		t := n.Type(lang)
		if (t == "parenthesized_expression" || t == "parenthesized_pattern") && n.NamedChildCount() == 1 {
			n = n.NamedChild(0)
			continue
		}
		break
	}
	return n
}

func peelNegation(n *gts.Node, lang *gts.Language, src []byte) (bool, string) {
	neg := false
	cur := unwrapParensNode(n, lang)
	for cur != nil {
		t := cur.Type(lang)
		if t == "unary_expression" || t == "not_operator" {
			txt := strings.TrimSpace(cur.Text(src))
			if strings.HasPrefix(txt, "!") || strings.HasPrefix(txt, "not ") || strings.HasPrefix(txt, "not(") {
				if cur.NamedChildCount() == 1 {
					neg = !neg
					cur = unwrapParensNode(cur.NamedChild(0), lang)
					continue
				}
			}
		}
		break
	}
	if cur == nil {
		return neg, ""
	}
	return neg, normalizeExprWhitespace(cur.Text(src))
}

func normalizeExprWhitespace(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

func stripOuterParensText(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

func findContradiction(operands []*gts.Node, lang *gts.Language, src []byte) string {
	seenPos := map[string]bool{}
	seenNeg := map[string]bool{}
	seenEq := map[string]bool{}
	seenNeq := map[string]bool{}

	for _, op := range operands {
		neg, base := peelNegation(op, lang, src)
		if base == "" {
			continue
		}
		if neg {
			if seenPos[base] {
				return fmt.Sprintf("%s and !%s", base, base)
			}
			seenNeg[base] = true
		} else {
			if seenNeg[base] {
				return fmt.Sprintf("%s and !%s", base, base)
			}
			seenPos[base] = true
		}

		cur := unwrapParensNode(op, lang)
		if cur != nil && (cur.Type(lang) == "binary_expression" || cur.Type(lang) == "comparison_operator") && cur.NamedChildCount() == 2 {
			lhs := normalizeExprWhitespace(cur.NamedChild(0).Text(src))
			rhs := normalizeExprWhitespace(cur.NamedChild(1).Text(src))
			pair := lhs + "||" + rhs
			if rhs < lhs {
				pair = rhs + "||" + lhs
			}
			for _, ch := range cur.Children() {
				ct := ch.Type(lang)
				if ct == "===" || ct == "==" {
					if seenNeq[pair] {
						return fmt.Sprintf("%s == %s conflicts with !=", lhs, rhs)
					}
					seenEq[pair] = true
				} else if ct == "!==" || ct == "!=" {
					if seenEq[pair] {
						return fmt.Sprintf("%s != %s conflicts with ==", lhs, rhs)
					}
					seenNeq[pair] = true
				}
			}
		}
	}
	return ""
}

func isEmptyCatchBody(body *gts.Node, lang *gts.Language, src []byte) bool {
	if body == nil {
		return false
	}
	txt := strings.TrimSpace(body.Text(src))
	if strings.Contains(txt, "//") || strings.Contains(txt, "/*") || strings.Contains(txt, "#") {
		return false
	}
	if body.Type(lang) == "block" && body.NamedChildCount() == 1 && body.NamedChild(0).Type(lang) == "pass_statement" {
		return true
	}
	return body.NamedChildCount() == 0
}

func hasElseBranch(ifNode *gts.Node, lang *gts.Language) bool {
	for i := 0; i < ifNode.NamedChildCount(); i++ {
		t := ifNode.NamedChild(i).Type(lang)
		if t == "else_clause" || t == "elif_clause" {
			return true
		}
	}
	return false
}

func duplicateIfElseBody(ifNode *gts.Node, lang *gts.Language, src []byte) string {
	conseq := ifNode.ChildByFieldName("consequence", lang)
	if conseq == nil {
		for i := 0; i < ifNode.NamedChildCount(); i++ {
			ch := ifNode.NamedChild(i)
			t := ch.Type(lang)
			if t == "statement_block" || t == "block" {
				conseq = ch
				break
			}
		}
	}
	if conseq == nil {
		return ""
	}
	var elseBody *gts.Node
	for i := 0; i < ifNode.NamedChildCount(); i++ {
		ch := ifNode.NamedChild(i)
		if ch.Type(lang) == "else_clause" {
			for j := 0; j < ch.NamedChildCount(); j++ {
				ec := ch.NamedChild(j)
				et := ec.Type(lang)
				if et == "statement_block" || et == "block" {
					elseBody = ec
					break
				}
			}
		}
	}
	if elseBody == nil {
		return ""
	}
	a := normalizeExprWhitespace(conseq.Text(src))
	b := normalizeExprWhitespace(elseBody.Text(src))
	if a != "" && a != "{}" && a == b {
		return a
	}
	return ""
}

// AnalyzeNullableParameters inspects ONLY top-level function parameters
// (never nested object-type properties like `{cursor?: string | undefined}`)
// and flags unguarded property dereferences (TS/JS/Python) or `.unwrap()` (Rust).
func AnalyzeNullableParameters(path string, src []byte) []Finding {
	p, err := ast.Parse(path, src)
	if err != nil {
		return nil
	}
	lang := p.Language
	langName := fileLang(path)
	var out []Finding

	var walk func(*gts.Node)
	walk = func(n *gts.Node) {
		if n == nil {
			return
		}
		t := n.Type(lang)
		if topLevelFunctionTypes[t] || t == "arrow_function" || t == "function_expression" {
			paramsNode := n.ChildByFieldName("parameters", lang)
			bodyNode := n.ChildByFieldName("body", lang)
			if paramsNode != nil && bodyNode != nil {
				nullParams := extractTopLevelNullableParams(paramsNode, lang, langName, src)
				if len(nullParams) > 0 {
					bodyText := bodyNode.Text(src)
					for _, paramName := range nullParams {
						if langName == "rust" {
							re := regexp.MustCompile(`\b` + regexp.QuoteMeta(paramName) + `\.unwrap\(\)`)
							if loc := re.FindStringIndex(bodyText); loc != nil && !strings.Contains(bodyText[:loc[0]], paramName+".is_some()") {
								line := int(bodyNode.StartPoint().Row) + 1 + strings.Count(bodyText[:loc[0]], "\n")
								out = append(out, newFinding(
									"LOGIC.null-deref",
									"logic",
									"high",
									path,
									line,
									line,
									fmt.Sprintf("Option parameter %q calls .unwrap() without a guard", paramName),
									paramName+".unwrap()",
								))
							}
							continue
						}
						if isParamGuardedBeforeDeref(paramName, bodyText) {
							continue
						}
						if derefOffset := firstDirectDerefOffset(paramName, bodyText); derefOffset >= 0 {
							line := int(bodyNode.StartPoint().Row) + 1 + strings.Count(bodyText[:derefOffset], "\n")
							out = append(out, newFinding(
								"LOGIC.null-deref",
								"logic",
								"high",
								path,
								line,
								line,
								fmt.Sprintf("Nullable parameter %q is dereferenced without a null/undefined guard", paramName),
								paramName+".",
							))
						}
					}
				}
			}
		}
		for _, ch := range n.Children() {
			walk(ch)
		}
	}
	walk(p.Tree.RootNode())
	return out
}

func extractTopLevelNullableParams(paramsNode *gts.Node, lang *gts.Language, langName string, src []byte) []string {
	var names []string
	for i := 0; i < paramsNode.NamedChildCount(); i++ {
		param := paramsNode.NamedChild(i)
		pt := param.Type(lang)
		if pt != "required_parameter" && pt != "optional_parameter" && pt != "typed_parameter" && pt != "parameter" {
			continue
		}
		if param.ChildByFieldName("value", lang) != nil {
			continue
		}
		var nameNode *gts.Node
		if pat := param.ChildByFieldName("pattern", lang); pat != nil {
			if pat.Type(lang) == "identifier" {
				nameNode = pat
			}
		} else if id := param.ChildByFieldName("name", lang); id != nil {
			if id.Type(lang) == "identifier" {
				nameNode = id
			}
		} else if param.NamedChildCount() > 0 && param.NamedChild(0).Type(lang) == "identifier" {
			nameNode = param.NamedChild(0)
		}
		if nameNode == nil {
			continue
		}
		name := strings.TrimSpace(nameNode.Text(src))
		if name == "" {
			continue
		}

		if pt == "optional_parameter" {
			names = append(names, name)
			continue
		}

		typeAnn := param.ChildByFieldName("type", lang)
		if typeAnn == nil {
			for j := 0; j < param.NamedChildCount(); j++ {
				ct := param.NamedChild(j).Type(lang)
				if ct == "type_annotation" || ct == "type" || ct == "generic_type" {
					typeAnn = param.NamedChild(j)
					break
				}
			}
		}
		if langName == "rust" && typeAnn != nil && strings.HasPrefix(strings.TrimSpace(typeAnn.Text(src)), "Option<") {
			names = append(names, name)
			continue
		}
		if typeAnn != nil && isTopLevelNullableType(typeAnn, lang, src) {
			names = append(names, name)
		}
	}
	return names
}

func isTopLevelNullableType(typeNode *gts.Node, lang *gts.Language, src []byte) bool {
	if typeNode == nil {
		return false
	}
	t := typeNode.Type(lang)
	if t == "type_annotation" && typeNode.NamedChildCount() == 1 {
		return isTopLevelNullableType(typeNode.NamedChild(0), lang, src)
	}
	if t == "object_type" || t == "interface_body" {
		return false
	}
	if t == "union_type" || t == "binary_operator" {
		for i := 0; i < typeNode.NamedChildCount(); i++ {
			ch := typeNode.NamedChild(i)
			ct := ch.Type(lang)
			if ct == "union_type" {
				if isTopLevelNullableType(ch, lang, src) {
					return true
				}
				continue
			}
			txt := strings.TrimSpace(ch.Text(src))
			if txt == "null" || txt == "undefined" || txt == "None" {
				return true
			}
		}
	}
	if t == "generic_type" && strings.HasPrefix(strings.TrimSpace(typeNode.Text(src)), "Optional[") {
		return true
	}
	return false
}

func firstDirectDerefOffset(name, body string) int {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\.([A-Za-z_][A-Za-z0-9_]*)`)
	for _, loc := range re.FindAllStringIndex(body, -1) {
		// Skip property chains on another receiver such as obj.name.prop or obj?.name.prop.
		if loc[0] > 0 {
			prev := body[loc[0]-1]
			if prev == '.' {
				continue
			}
		}
		return loc[0]
	}
	return -1
}

func isParamGuardedBeforeDeref(name, body string) bool {
	deref := firstDirectDerefOffset(name, body)
	if deref < 0 {
		return true
	}
	prefix := body[:deref]
	esc := regexp.QuoteMeta(name)
	// Same-expression short-circuit / ternary / nullish coalescing / reassignment directly before deref.
	exprRe := regexp.MustCompile(
		`((\|\||&&)\s*!?\s*` + esc + `\b)|` +
			`(\b` + esc + `\s*\?\s*[^.?])|` +
			`(\b` + esc + `\s*(\?\?|\&\&))|` +
			`(\b` + esc + `\s*=\s*[^=])`,
	)
	if exprRe.MatchString(prefix) {
		return true
	}
	// Control-flow if-guards must either still enclose the dereference (open brace) or exit early (return/throw/continue/break).
	ifGuardRe := regexp.MustCompile(
		`\bif\s*(?:\(\s*)?(!\s*` + esc + `\b(?:\s*\))?|` + esc + `\s*(?:==|===)\s*(?:null|undefined|None)\s*\)?|` + esc + `\s+is\s+(?:not\s+)?None\s*:|` + esc + `\s*(?:!==?|===?)\s*(?:null|undefined|None)\s*\)?|` + esc + `\s*\)?)`,
	)
	for _, loc := range ifGuardRe.FindAllStringIndex(prefix, -1) {
		guard := prefix[loc[0]:loc[1]]
		negated := strings.Contains(guard, "!") || strings.Contains(guard, "==") || strings.Contains(guard, " is None")
		segment := prefix[loc[1]:]
		openBraces := strings.Count(segment, "{") - strings.Count(segment, "}")
		if openBraces > 0 && !negated {
			return true
		}
		if openBraces == 0 && negated && guardBlockExits(segment) {
			return true
		}
		if strings.Contains(guard, " is None") && strings.Contains(guard, "not") {
			return true
		}
	}
	return false
}

func guardBlockExits(segment string) bool {
	open := strings.IndexByte(segment, '{')
	if open < 0 {
		return false
	}
	depth := 1
	for i := open + 1; i < len(segment); i++ {
		switch segment[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return regexp.MustCompile(`\b(return|throw|raise|continue|break)\b`).MatchString(segment[open+1 : i])
			}
		}
	}
	return false
}
