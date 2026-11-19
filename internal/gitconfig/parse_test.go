package gitconfig

import "testing"

func TestParseSectionsAndQuotes(t *testing.T) {
	const src = `
# comment
[submodule "vendor/lib"]
	path = vendor/lib
	url = "../left pad.git"
	update = !gsg-fixture-command
[submodule]
	recurse = true
[includeIf "gitdir:~/src/"]
	path = ../other
`
	file, warnings := Parse("config", []byte(src))
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	if got, ok := file.First("submodule", "vendor/lib", "path"); !ok || got != "vendor/lib" {
		t.Fatalf("path = %q ok=%v", got, ok)
	}
	if got, _ := file.First("submodule", "vendor/lib", "url"); got != "../left pad.git" {
		t.Fatalf("url = %q", got)
	}
	if got, _ := file.First("submodule", "vendor/lib", "update"); got != "!gsg-fixture-command" {
		t.Fatalf("update = %q", got)
	}
	if got, _ := file.First("submodule", "", "recurse"); got != "true" || !IsTrue(got) {
		t.Fatalf("recurse = %q", got)
	}
	incs := file.Values("includeif", "gitdir:~/src/", "path")
	if len(incs) != 1 || incs[0].Value != "../other" {
		t.Fatalf("include %#v", incs)
	}
}

func TestParseContinuationAndComment(t *testing.T) {
	const src = "[remote \"origin\"]\n\tfetch = +refs/heads/*:refs/remotes/origin/* ; keep\n\turl = https://example.invalid/demo.git\n"
	file, warnings := Parse("c", []byte(src))
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	got, ok := file.First("remote", "origin", "fetch")
	if !ok || got != "+refs/heads/*:refs/remotes/origin/*" {
		t.Fatalf("fetch = %q", got)
	}
}

func TestValuelessBoolean(t *testing.T) {
	file, _ := Parse("c", []byte("[core]\n\tbare\n"))
	got, ok := file.First("core", "", "bare")
	if !ok || !IsTrue(got) {
		t.Fatalf("bare = %q ok=%v", got, ok)
	}
	if !IsFalse("no") || IsTrue("false") {
		t.Fatal("bool helpers")
	}
}
