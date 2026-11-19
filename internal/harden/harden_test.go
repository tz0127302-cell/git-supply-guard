package harden

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDryRunDoesNotWrite(t *testing.T) {
	repo := initRepo(t)
	before, err := os.ReadFile(filepath.Join(repo, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(context.Background(), Request{Root: repo, Apply: false})
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(repo, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("dry-run changed local config")
	}
	if result.Applied {
		t.Fatal("dry-run reported applied settings")
	}
	if !hasAdvice(result, "H-SUBMODULE-RECURSE") || !hasAdvice(result, "H-GIT-UPDATE") {
		t.Fatalf("advice %#v", result.Advice)
	}
}

func TestApplyWritesOnlySafeKeys(t *testing.T) {
	repo := initRepo(t)
	if _, err := Run(context.Background(), Request{Root: repo, Apply: true}); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"submodule.recurse", "fetch.fsckObjects", "transfer.fsckObjects", "receive.fsckObjects", "protocol.file.allow"} {
		if got := configGet(t, repo, key); got == "" {
			t.Errorf("missing %s", key)
		}
	}
	text := configList(t, repo)
	if strings.Contains(text, "hooksPath") || strings.Contains(strings.ToLower(text), "credential") {
		t.Fatalf("unexpected keys:\n%s", text)
	}
	second, err := Run(context.Background(), Request{Root: repo, Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if second.Applied {
		t.Fatal("second apply wrote keys that were already set")
	}
}

func TestApplyRequiresRepository(t *testing.T) {
	dir := t.TempDir()
	if _, err := Run(context.Background(), Request{Root: dir, Apply: true}); err == nil {
		t.Fatal("apply succeeded outside a repository")
	}
	result, err := Run(context.Background(), Request{Root: dir, Apply: false})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsRepo {
		t.Fatal("plain directory was treated as a repository")
	}
}

func configGet(t *testing.T, repo, key string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", repo, "config", "--local", "--get", key)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func configList(t *testing.T, repo string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", repo, "config", "--local", "--list")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("config list: %v\n%s", err, out)
	}
	return string(out)
}

func hasAdvice(result *Result, id string) bool {
	for _, item := range result.Advice {
		if item.ID == id {
			return true
		}
	}
	return false
}

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	hooks := t.TempDir()
	cmd := exec.Command("git",
		"-c", "commit.gpgsign=false",
		"-c", "core.fsmonitor=",
		"-c", "core.hooksPath="+hooks,
		"init", "-b", "main",
	)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	return dir
}
