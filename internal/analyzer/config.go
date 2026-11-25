package analyzer

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/wapo-org/wapo-review/internal/ast"
	"gopkg.in/yaml.v3"
)

type RepoConfig struct {
	Rules       map[string]RuleConfig  `yaml:"rules"`
	Exclude     []string               `yaml:"exclude"`
	Complexity  ComplexityConfig       `yaml:"complexity"`
	QualityGate QualityGateConfig      `yaml:"quality_gate"`
	Attributes  []ast.GitAttributeRule `yaml:"-"`
}
type RuleConfig struct {
	Enabled  *bool  `yaml:"enabled"`
	Severity string `yaml:"severity"`
}
type ComplexityConfig struct {
	High   int `yaml:"high"`
	MaxNew int `yaml:"max_new"`
}
type QualityGateConfig struct {
	MaxCritical          int      `yaml:"max_critical"`
	MaxHigh              int      `yaml:"max_high"`
	MaxNewCognitive      int      `yaml:"max_new_cognitive"`
	RequiredSandboxGates []string `yaml:"required_sandbox_gates"`
}

// LoadRepoConfig accepts only base-branch YAML. The caller must fetch that content
// from the base SHA, never from the pull request head.
func LoadRepoConfig(baseYAML, gitattributes []byte) (RepoConfig, error) {
	c := RepoConfig{Rules: map[string]RuleConfig{}, Complexity: ComplexityConfig{High: 15}}
	if len(baseYAML) > 1<<20 {
		return c, fmt.Errorf("repository config exceeds 1 MiB")
	}
	if len(strings.TrimSpace(string(baseYAML))) > 0 {
		if err := yaml.Unmarshal(baseYAML, &c); err != nil {
			return c, err
		}
	}
	for _, line := range strings.Split(string(gitattributes), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		r := ast.GitAttributeRule{Pattern: f[0]}
		for _, a := range f[1:] {
			if a == "linguist-generated" || a == "linguist-generated=true" {
				r.Generated = true
			} else if a == "-linguist-generated" || a == "linguist-generated=false" {
				r.Generated = false
			}
		}
		if r.Generated {
			c.Attributes = append(c.Attributes, r)
		}
	}
	return c, nil
}
func (c RepoConfig) Excluded(path string) bool {
	if ast.IsExcluded(path, nil, c.Attributes, c.Exclude).Excluded {
		return true
	}
	p := filepath.ToSlash(path)
	for _, g := range c.Exclude {
		if ok, _ := filepath.Match(g, p); ok {
			return true
		}
		if !strings.Contains(g, "/") {
			if ok, _ := filepath.Match(g, filepath.Base(p)); ok {
				return true
			}
		}
	}
	return false
}
