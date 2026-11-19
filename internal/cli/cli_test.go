package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tz0127302-cell/git-supply-guard/internal/model"
)

func TestVersionAndHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"version"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "git-supply-guard") {
		t.Fatalf("version code=%d out=%s", code, stdout.String())
	}
	stdout.Reset()
	if code := Execute([]string{"--help"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "gsg scan") {
		t.Fatalf("help code=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Execute(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("no args code=%d", code)
	}
}

func TestScanFixtureCLI(t *testing.T) {
	root := filepath.Join(moduleRoot(t), "examples", "risky-checkout")
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"scan", root, "--json", "--no-color"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String(), "fixture-token") {
		t.Fatal("password leaked into JSON")
	}
	var rep model.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Result != "fail" || rep.ExitCode != 1 || rep.Summary.Critical < 1 {
		t.Fatalf("report %#v", rep.Summary)
	}
	stdout.Reset()
	if code := Execute([]string{"scan", root, "--fail-on", "none", "--no-color"}, &stdout, &stderr); code != 0 {
		t.Fatalf("fail-on none code=%d", code)
	}
	clean := filepath.Join(moduleRoot(t), "examples", "clean-checkout")
	stdout.Reset()
	if code := Execute([]string{"scan", clean, "--fail-on", "high", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("clean code=%d %s", code, stdout.String())
	}
}

func TestCloneRefusalJSON(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "dest")
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"clone", "--json", "https://fixture-user:fixture-token@example.invalid/demo.git", dest}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d %s %s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "fixture-token") {
		t.Fatal("password leaked")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("dest exists")
	}
}

func TestHardenCLI(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"harden", dir, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("dry-run code=%d %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "H-SUBMODULE-RECURSE") {
		t.Fatal(stdout.String())
	}
	stdout.Reset()
	if code := Execute([]string{"harden", dir, "--apply"}, &stdout, &stderr); code != 2 {
		t.Fatalf("apply code=%d %s", code, stderr.String())
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
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
