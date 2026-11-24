package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Skill struct{ Name, Content string }
type SkillLoader struct{ Directory string }

func (l SkillLoader) Load(names ...string) ([]Skill, error) {
	root, err := filepath.Abs(l.Directory)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	skills := make([]Skill, 0, len(names))
	for _, name := range names {
		if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") || name == "." || name == ".." {
			return nil, fmt.Errorf("invalid skill name %q", name)
		}
		path := filepath.Join(root, name, "SKILL.md")
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(root, resolved)
		if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
			return nil, errors.New("skill path escapes configured directory")
		}
		b, err := os.ReadFile(resolved)
		if err != nil {
			return nil, err
		}
		skills = append(skills, Skill{Name: name, Content: string(b)})
	}
	return skills, nil
}
func FormatSkills(skills []Skill) string {
	sort.Slice(skills, func(i, j int) bool { return skills[i].Name < skills[j].Name })
	var b strings.Builder
	for _, s := range skills {
		fmt.Fprintf(&b, "<skill name=%q>\n%s\n</skill>\n", s.Name, s.Content)
	}
	return b.String()
}
