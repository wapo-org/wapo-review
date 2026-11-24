package memory

import (
	"fmt"
	"sort"
	"strings"
)

func FormatContext(notes []Note, scope, queryContext string, maxChars int) string {
	type scored struct {
		n Note
		s int
	}
	q := map[string]bool{}
	for _, w := range strings.Fields(strings.ToLower(queryContext)) {
		w = strings.Trim(w, ".,:;()[]{}#`\"'")
		if len(w) > 2 {
			q[w] = true
		}
	}
	var ranked []scored
	for _, n := range notes {
		if scope != "all" && n.Scope != "all" && n.Scope != scope {
			continue
		}
		s := 0
		for _, w := range strings.Fields(strings.ToLower(n.Text)) {
			w = strings.Trim(w, ".,:;()[]{}#`\"'")
			if q[w] {
				s++
			}
		}
		ranked = append(ranked, scored{n, s})
	}
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].s > ranked[j].s })
	var out []string
	used := 0
	for _, v := range ranked {
		line := fmt.Sprintf("- %s", v.n.Text)
		if v.n.Scope != "all" {
			line = fmt.Sprintf("- [%s] %s", v.n.Scope, v.n.Text)
		}
		extra := len(line)
		if len(out) > 0 {
			extra++
		}
		if maxChars >= 0 && used+extra > maxChars {
			continue
		}
		out = append(out, line)
		used += extra
	}
	return strings.Join(out, "\n")
}
