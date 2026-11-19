package safety

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tz0127302-cell/git-supply-guard/internal/model"
)

func TestRepositoryAvoidsReproductionMaterial(t *testing.T) {
	root := moduleRoot(t)
	phrases := []string{
		"explo" + "it",
		"pay" + "load",
		"proof of " + "concept",
		"proof-of-" + "concept",
		"integer " + "truncation",
		"remote code " + "execution",
		"arbitrary code " + "execution",
		"weapo" + "nize",
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		base := d.Name()
		if d.IsDir() {
			if base == ".git" || base == "bin" || base == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data[:min(len(data), 8000)]), "\x00") && !strings.HasSuffix(base, ".svg") {
			return nil
		}
		lower := strings.ToLower(string(data))
		rel, _ := filepath.Rel(root, path)
		for _, phrase := range phrases {
			if strings.Contains(lower, phrase) {
				t.Errorf("%s contains banned material", rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCatalogIsDocumented(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join(moduleRoot(t), "docs", "CHECKS.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(doc)
	for _, id := range model.AllIDs() {
		if !strings.Contains(text, id) {
			t.Errorf("docs/CHECKS.md does not mention %s", id)
		}
	}
	action, err := os.ReadFile(filepath.Join(moduleRoot(t), "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(action), "using: composite") && !strings.Contains(string(action), `using: "composite"`) {
		t.Fatal("action.yml is not a composite action")
	}
	ci, err := os.ReadFile(filepath.Join(moduleRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ci), "go test ./...") {
		t.Fatal("CI does not run go test ./...")
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
