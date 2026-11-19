package redact

import "testing"

func TestURLPassword(t *testing.T) {
	got := URL("https://fixture-user:fixture-token@example.invalid/demo.git")
	want := "https://fixture-user:***@example.invalid/demo.git"
	if got != want {
		t.Fatalf("got %s", got)
	}
	scp := URL("user:fixture-token@host:repo.git")
	if scp != "user:***@host:repo.git" {
		t.Fatalf("scp %s", scp)
	}
	plain := URL("git@github.com:org/repo.git")
	if plain != "git@github.com:org/repo.git" {
		t.Fatalf("plain %s", plain)
	}
}

func TestClip(t *testing.T) {
	if got := Clip("one\ntwo", 0); got != "one two" {
		t.Fatalf("%q", got)
	}
	if got := Clip("abcdef", 4); got != "abc…" {
		t.Fatalf("%q", got)
	}
}
