package internal_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoSourcesRemainRepositoryAgnostic(t *testing.T) {
	terms := []string{"pra" + "xis", "P" + "RA-", "arty" + "az"}
	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && (info.Name() == "legacy-python" || info.Name() == ".git") {
			return filepath.SkipDir
		}
		if info.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, term := range terms {
			if strings.Contains(strings.ToLower(string(content)), strings.ToLower(term)) {
				t.Errorf("%s contains repository-specific term %q", path, term)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
