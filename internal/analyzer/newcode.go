package analyzer

import (
	"strings"
)

type LineRange struct{ Start, End int }
type Diff struct {
	Files        map[string][]LineRange
	ChangedLines map[string]map[int]bool
}

func ParseUnifiedDiff(patch string) Diff {
	d := Diff{Files: map[string][]LineRange{}, ChangedLines: map[string]map[int]bool{}}
	file := ""
	line := 0
	inHunk := false
	for _, s := range strings.Split(patch, "\n") {
		if !inHunk && strings.HasPrefix(s, "+++ b/") {
			file = strings.TrimPrefix(s, "+++ b/")
			continue
		}
		if strings.HasPrefix(s, "@@") {
			inHunk = true
			i := strings.Index(s, "+")
			if i >= 0 {
				x := strings.Fields(s[i+1:])
				if len(x) > 0 {
					v := strings.SplitN(x[0], ",", 2)[0]
					line = strconvAtoi(v)
				}
			}
			continue
		}
		if strings.HasPrefix(s, "diff ") || strings.HasPrefix(s, "--- ") {
			inHunk = false
			continue
		}
		if file == "" || strings.HasPrefix(s, "index ") {
			continue
		}
		if strings.HasPrefix(s, "+") {
			if d.ChangedLines[file] == nil {
				d.ChangedLines[file] = map[int]bool{}
			}
			d.ChangedLines[file][line] = true
			d.Files[file] = appendRange(d.Files[file], line)
			line++
		} else if strings.HasPrefix(s, "-") || strings.HasPrefix(s, "\\") {
		} else {
			line++
		}
	}
	return d
}
func strconvAtoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}
func appendRange(rs []LineRange, n int) []LineRange {
	if len(rs) > 0 && n <= rs[len(rs)-1].End+1 {
		if n > rs[len(rs)-1].End {
			rs[len(rs)-1].End = n
		}
		return rs
	}
	return append(rs, LineRange{n, n})
}
func (d Diff) IsNew(file string, line int) bool { return d.ChangedLines[file][line] }
func ScopeFinding(f Finding, d Diff) bool {
	if f.NewCode {
		return true
	}
	end := f.EndLine
	if end < f.StartLine {
		end = f.StartLine
	}
	for n := f.StartLine; n <= end; n++ {
		if d.IsNew(f.File, n) {
			return true
		}
	}
	return false
}
