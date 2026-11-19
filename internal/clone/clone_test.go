package clone

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tz0127302-cell/git-supply-guard/internal/model"
)

func TestCloneRefusesHelpersAndCredentials(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "dest")
	_, err := Clone(context.Background(), Request{URL: "ext::synthetic-transport", Dest: dest, AllowLocal: true})
	if err == nil {
		t.Fatal("helper URL was cloned")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatal("destination was created for a refused URL")
	}
	_, err = Clone(context.Background(), Request{
		URL:  "https://fixture-user:fixture-token@example.invalid/demo.git",
		Dest: dest,
	})
	if err == nil || strings.Contains(err.Error(), "fixture-token") {
		t.Fatalf("err = %v", err)
	}
}

func TestCloneLocalSkipsSubmodulesFiltersAndHooks(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "canary")
	script := filepath.Join(t.TempDir(), "smudge.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho ran >> '"+canary+"'\ncat\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	global := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(global, []byte("[filter \"synthetic\"]\n\tsmudge = "+script+"\n\trequired = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")

	sub := initRepo(t)
	if err := os.WriteFile(filepath.Join(sub, "MARKER"), []byte("sub\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, sub, "add", "MARKER")
	runGit(t, sub, "commit", "-m", "sub")

	parent := initRepo(t)
	if err := os.WriteFile(filepath.Join(parent, "README.md"), []byte("parent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, ".gitattributes"), []byte("* filter=synthetic\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitmodules := "[submodule \"vendor/lib\"]\n\tpath = vendor/lib\n\turl = " + sub + "\n"
	if err := os.WriteFile(filepath.Join(parent, ".gitmodules"), []byte(gitmodules), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, parent, "add", "README.md", ".gitattributes", ".gitmodules")
	sha := strings.TrimSpace(gitOut(t, sub, "rev-parse", "HEAD"))
	runGit(t, parent, "update-index", "--add", "--cacheinfo", "160000,"+sha+",vendor/lib")
	runGit(t, parent, "commit", "-m", "parent")

	dest := filepath.Join(t.TempDir(), "dest")
	result, err := Clone(context.Background(), Request{
		URL:        parent,
		Dest:       dest,
		AllowLocal: true,
		Checkout:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.CheckedOut {
		t.Fatalf("notes: %v", result.Notes)
	}
	if _, statErr := os.Stat(canary); !os.IsNotExist(statErr) {
		t.Fatal("smudge filter ran during clone")
	}
	if _, statErr := os.Stat(filepath.Join(dest, "vendor", "lib", "MARKER")); !os.IsNotExist(statErr) {
		t.Fatal("submodule was fetched")
	}
	body, err := os.ReadFile(filepath.Join(dest, "README.md"))
	if err != nil || string(body) != "parent\n" {
		t.Fatalf("readme %q %v", body, err)
	}
	cfg, err := os.ReadFile(filepath.Join(dest, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfg), "hooksPath") {
		t.Fatalf("hooks path was persisted:\n%s", cfg)
	}
	if result.Scan == nil || !hasID(result.Scan.Findings, model.IDSubProtocol) {
		t.Fatalf("expected the local submodule URL to be reported, findings=%v", result.Scan)
	}
	joined := strings.Join(result.Notes, "\n")
	if !strings.Contains(joined, "did not recurse") {
		t.Fatalf("notes %v", result.Notes)
	}
}

func hasID(findings []model.Finding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-b", "main")
	return dir
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	_ = gitOut(t, dir, args...)
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	hooks := t.TempDir()
	base := []string{
		"-c", "commit.gpgsign=false",
		"-c", "core.fsmonitor=",
		"-c", "user.email=gsg@example.invalid",
		"-c", "user.name=gsg-test",
		"-c", "core.hooksPath=" + hooks,
		"-c", "submodule.recurse=false",
		"-c", "filter.synthetic.smudge=",
		"-c", "filter.synthetic.clean=",
		"-c", "filter.synthetic.process=",
		"-c", "filter.synthetic.required=false",
	}
	cmd := exec.Command("git", append(base, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=gsg-test",
		"GIT_AUTHOR_EMAIL=gsg@example.invalid",
		"GIT_COMMITTER_NAME=gsg-test",
		"GIT_COMMITTER_EMAIL=gsg@example.invalid",
		"GIT_CONFIG_GLOBAL="+os.Getenv("GIT_CONFIG_GLOBAL"),
		"GIT_CONFIG_SYSTEM="+os.Getenv("GIT_CONFIG_SYSTEM"),
		"GIT_TERMINAL_PROMPT=0",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
