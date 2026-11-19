package scan

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tz0127302-cell/git-supply-guard/internal/model"
)

func TestRecursiveCloneLineDoesNotFlagNegation(t *testing.T) {
	if recursiveCloneLine("git clone --no-recurse-submodules https://example.invalid/a.git") {
		t.Fatal("negated flag was treated as recursive")
	}
	if !recursiveCloneLine("git clone --recurse-submodules https://example.invalid/a.git") {
		t.Fatal("missed recurse flag")
	}
	if !recursiveCloneLine("git submodule update --init --recursive") {
		t.Fatal("missed submodule update")
	}
	if !isAutomation(".github/workflows/ci.yml") || !isAutomation("examples/app/.github/workflows/ci.yml") {
		t.Fatal("workflow files should be automation")
	}
	if !isAutomation("scripts/fetch.sh") || !isAutomation("tools/scripts/fetch.sh") {
		t.Fatal("shell scripts under scripts/ should be automation")
	}
	if isAutomation("docs/ci.yml") || isAutomation("README.md") {
		t.Fatal("docs were treated as automation")
	}
	if broadRefspec("+refs/heads/*:refs/remotes/origin/*") {
		t.Fatal("branch refspec was treated as broad")
	}
	if !broadRefspec("+refs/*:refs/*") {
		t.Fatal("broad refspec was missed")
	}
	if !pathEscapes("../../outside") || pathEscapes("vendor/left-pad") {
		t.Fatal("path escape check")
	}
	if _, ok := trackedHook("hooks/post-commit.sample"); ok {
		t.Fatal("sample hook was flagged")
	}
	if id, ok := trackedHook("hooks/pre-commit"); !ok || id != model.IDHookTracked {
		t.Fatalf("tracked hook id=%s ok=%v", id, ok)
	}
}

func TestRiskyFixture(t *testing.T) {
	root := filepath.Join(moduleRoot(t), "examples", "risky-checkout")
	result, err := Scan(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(result)
	if strings.Contains(string(blob), "fixture-token") {
		t.Fatal("fixture password leaked into the result")
	}
	got := map[string]int{}
	for _, finding := range result.Findings {
		got[finding.ID]++
		if finding.Detail == "" || finding.Remediation == "" || finding.Title == "" {
			t.Fatalf("incomplete finding %#v", finding)
		}
	}
	want := map[string]int{
		model.IDSubRelative:    1,
		model.IDSubProtocol:    2,
		model.IDSubCredentials: 1,
		model.IDSubPath:        1,
		model.IDSubIgnore:      1,
		model.IDAttrFilter:     1,
		model.IDAttrExport:     2,
		model.IDAttrMerge:      1,
		model.IDHookTracked:    1,
		model.IDLinkGitMeta:    1,
		model.IDLinkOutside:    1,
		model.IDCloneRecursive: 1,
		model.IDRepoNotGit:     1,
	}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("%s count=%d want %d", id, got[id], n)
		}
	}
	for id, n := range got {
		if want[id] == 0 {
			t.Errorf("unexpected %s x%d", id, n)
		}
	}
	if t.Failed() {
		for _, finding := range result.Findings {
			t.Logf("%s %s %s", finding.Severity, finding.ID, finding.Location)
		}
	}
	if !model.Fails(result.Findings, model.High) {
		t.Fatal("fixture should fail a high threshold")
	}
}

func TestUpdateCommandFindingDoesNotRunIt(t *testing.T) {
	root := t.TempDir()
	canary := filepath.Join(t.TempDir(), "canary")
	writeFile(t, filepath.Join(root, ".gitmodules"), "[submodule \"vendor/ext-demo\"]\n\tpath = vendor/ext-demo\n\turl = https://example.invalid/demo.git\n\tupdate = !gsg-fixture-command\n")
	writeFile(t, filepath.Join(root, "gsg-fixture-command"), "#!/bin/sh\necho ran >> "+shellQuote(canary)+"\n")
	result, err := Scan(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(result, model.IDSubUpdateCmd) {
		t.Fatalf("findings %#v", result.Findings)
	}
	if _, statErr := os.Stat(canary); !os.IsNotExist(statErr) {
		t.Fatal("update command was executed")
	}
}

func TestCleanFixture(t *testing.T) {
	root := filepath.Join(moduleRoot(t), "examples", "clean-checkout")
	result, err := Scan(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if model.Fails(result.Findings, model.High) {
		t.Fatalf("clean fixture failed: %#v", result.Findings)
	}
	ids := map[string]int{}
	for _, finding := range result.Findings {
		ids[finding.ID]++
	}
	if ids[model.IDSubInventory] != 1 || ids[model.IDRepoNotGit] != 1 {
		t.Fatalf("ids %#v", ids)
	}
	if len(result.Submodules) != 1 || result.Submodules[0].Protocol != "https" {
		t.Fatalf("submodules %#v", result.Submodules)
	}
}

func TestConfigSmellsDoNotRunCommands(t *testing.T) {
	repo := initRepo(t)
	writeFile(t, filepath.Join(repo, "README.md"), "hello\n")
	runGit(t, repo, "add", "README.md")
	runGit(t, repo, "commit", "-m", "init")

	canary := filepath.Join(t.TempDir(), "canary")
	script := filepath.Join(t.TempDir(), "canary.sh")
	writeFile(t, script, "#!/bin/sh\necho ran >> "+shellQuote(canary)+"\n")
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.config")
	writeFile(t, outside, "[credential]\n\thelper = OUTSIDE-MARKER-DO-NOT-LEAK\n")
	writeFile(t, filepath.Join(repo, "included.config"), "[credential]\n\thelper = included-helper\n")
	writeFile(t, filepath.Join(repo, "hooks", "pre-commit"), "#!/bin/sh\necho tracked\n")
	writeFile(t, filepath.Join(repo, "scripts", "fetch.sh"), "#!/bin/sh\ngit clone --recurse-submodules https://example.invalid/demo.git\n")
	writeFile(t, filepath.Join(repo, ".gitattributes"), "* filter=lfs\nSECURITY.md export-ignore\nvendor/x merge=ours\n")
	writeFile(t, filepath.Join(repo, "SECURITY.md"), "policy\n")
	if err := os.Symlink("/tmp/gsg-outside-test", filepath.Join(repo, "escape")); err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(repo, ".git", "hooks", "pre-commit")
	if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, hook, "#!/bin/sh\necho ran >> "+shellQuote(canary)+"\n")
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}

	extra := `
[core]
	hooksPath = hooks
	fsmonitor = ` + script + `
[credential]
	helper = synthetic-helper
[protocol "file"]
	allow = always
[protocol]
	allow = always
[fetch]
	fsckObjects = false
	recurseSubmodules = true
[safe]
	directory = *
[url "file:///tmp/gsg-fixture-rewrite"]
	insteadOf = https://example.invalid/
[filter "lab"]
	smudge = ` + script + `
[alias]
	clone = status
[diff]
	external = ` + script + `
[merge "lab"]
	driver = ` + script + ` %O %A %B
[remote "origin"]
	url = https://example.invalid/demo.git
	mirror = true
	fetch = +refs/*:refs/*
[include]
	path = ../included.config
[include]
	path = ` + outside + `
[http]
	extraHeader = X-Synthetic: do-not-print-this-value
`
	f, err := os.OpenFile(filepath.Join(repo, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(extra); err != nil {
		t.Fatal(err)
	}
	f.Close()

	result, err := Scan(context.Background(), Options{Root: repo})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(canary); !os.IsNotExist(err) {
		t.Fatal("scan executed a configured command or hook")
	}
	blob, _ := json.Marshal(result)
	text := string(blob)
	if strings.Contains(text, "OUTSIDE-MARKER-DO-NOT-LEAK") {
		t.Fatal("outside include was read")
	}
	if strings.Contains(text, "do-not-print-this-value") {
		t.Fatal("HTTP header value was printed")
	}
	if !strings.Contains(text, "included-helper") {
		t.Fatal("inside include was not audited")
	}
	need := []string{
		model.IDCfgCredential, model.IDCfgFileAllow, model.IDCfgFsckOff, model.IDCfgSafeStar,
		model.IDCfgInsteadOf, model.IDCfgFilter, model.IDCfgAlias, model.IDCfgCommand,
		model.IDCfgProtocolAny, model.IDCfgHTTPHeader, model.IDSubRecurse, model.IDRefBroad,
		model.IDMergeDriver, model.IDPatchExternal, model.IDImportInclude, model.IDHookPathInside,
		model.IDHookInstalled, model.IDHookTracked, model.IDAttrLFS, model.IDAttrExport,
		model.IDAttrMerge, model.IDLinkOutside, model.IDCloneRecursive,
	}
	have := map[string]bool{}
	for _, finding := range result.Findings {
		have[finding.ID] = true
	}
	for _, id := range need {
		if !have[id] {
			t.Errorf("missing %s", id)
		}
	}
	if t.Failed() {
		for _, finding := range result.Findings {
			t.Log(finding.ID, finding.Location)
		}
	}
}

func TestOrphanGitlink(t *testing.T) {
	sub := initRepo(t)
	writeFile(t, filepath.Join(sub, "MARKER"), "sub\n")
	runGit(t, sub, "add", "MARKER")
	runGit(t, sub, "commit", "-m", "sub")
	sha := strings.TrimSpace(gitOut(t, sub, "rev-parse", "HEAD"))

	parent := initRepo(t)
	writeFile(t, filepath.Join(parent, "README.md"), "parent\n")
	runGit(t, parent, "add", "README.md")
	runGit(t, parent, "commit", "-m", "parent")
	runGit(t, parent, "update-index", "--add", "--cacheinfo", "160000,"+sha+",vendor/orphan")
	runGit(t, parent, "commit", "-m", "gitlink")

	result, err := Scan(context.Background(), Options{Root: parent})
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(result, model.IDGitlinkOrphan) {
		t.Fatalf("findings %#v", result.Findings)
	}
}

func TestGitSymlinkIsNotFollowed(t *testing.T) {
	real := initRepo(t)
	canary := filepath.Join(t.TempDir(), "canary")
	hook := filepath.Join(real, ".git", "hooks", "post-checkout")
	if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, hook, "#!/bin/sh\necho ran >> "+shellQuote(canary)+"\n")
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	if err := os.Symlink(filepath.Join(real, ".git"), filepath.Join(root, ".git")); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "git"), "#!/bin/sh\necho invoked >> "+shellQuote(canary)+"\nexit 0\n")
	if err := os.Chmod(filepath.Join(bin, "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	result, err := Scan(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(canary); !os.IsNotExist(statErr) {
		t.Fatal("scan followed .git or invoked git")
	}
	if !hasID(result, model.IDLinkGitSymlink) {
		t.Fatalf("findings %#v", result.Findings)
	}
	if hasID(result, model.IDRepoNotGit) {
		t.Fatal("symlink .git was also reported as a missing repository")
	}
}

func TestDeclaredSubmoduleWithoutGitlink(t *testing.T) {
	repo := initRepo(t)
	writeFile(t, filepath.Join(repo, "README.md"), "hello\n")
	writeFile(t, filepath.Join(repo, ".gitmodules"), "[submodule \"vendor/demo\"]\n\tpath = vendor/demo\n\turl = https://example.invalid/demo.git\n")
	runGit(t, repo, "add", "README.md", ".gitmodules")
	runGit(t, repo, "commit", "-m", "declare")
	result, err := Scan(context.Background(), Options{Root: repo})
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(result, model.IDSubNoGitlink) {
		t.Fatalf("findings %#v", result.Findings)
	}
	if model.Fails(result.Findings, model.High) {
		t.Fatalf("https submodule should not fail high: %#v", result.Findings)
	}
}

func hasID(result *Result, id string) bool {
	for _, finding := range result.Findings {
		if finding.ID == id {
			return true
		}
	}
	return false
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
		"-c", "tag.gpgsign=false",
		"-c", "core.fsmonitor=",
		"-c", "user.email=gsg@example.invalid",
		"-c", "user.name=gsg-test",
		"-c", "core.hooksPath=" + hooks,
		"-c", "submodule.recurse=false",
	}
	cmd := exec.Command("git", append(base, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=gsg-test",
		"GIT_AUTHOR_EMAIL=gsg@example.invalid",
		"GIT_COMMITTER_NAME=gsg-test",
		"GIT_COMMITTER_EMAIL=gsg@example.invalid",
		"GIT_TERMINAL_PROMPT=0",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
