package urlclass

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		in       string
		protocol string
		helper   bool
		rel      bool
		local    bool
		creds    bool
	}{
		{"https://example.com/a.git", "https", false, false, false, false},
		{"https://fixture-user:fixture-token@example.invalid/demo.git", "https", false, false, false, true},
		{"git@github.com:org/repo.git", "ssh", false, false, false, false},
		{"ssh://git@github.com/org/repo.git", "ssh", false, false, false, false},
		{"git+ssh://git@github.com/org/repo.git", "git+ssh", false, false, false, false},
		{"git://github.com/org/repo.git", "git", false, false, false, false},
		{"http://example.com/a.git", "http", false, false, false, false},
		{"file:///tmp/gsg-fixture-not-a-repo", "file", false, false, true, false},
		{"/tmp/repo.git", "file", false, false, true, false},
		{"../left-pad.git", "relative", false, true, true, false},
		{"ext::synthetic-transport", "ext", true, false, false, false},
		{"fd::3", "fd", true, false, false, false},
		{"user:pass@host:repo.git", "ssh", false, false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			info := Classify(tc.in)
			if info.Protocol != tc.protocol || info.Helper != tc.helper || info.Relative != tc.rel || info.Local != tc.local || info.Credentials != tc.creds {
				t.Fatalf("%+v", info)
			}
			if tc.creds && containsToken(info.Redacted) {
				t.Fatalf("redacted URL leaked a password: %s", info.Redacted)
			}
		})
	}
}

func containsToken(s string) bool {
	return len(s) > 0 && (contains(s, "fixture-token") || contains(s, "pass@") || contains(s, ":pass"))
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(s) > 0 && (indexOf(s, sub) >= 0)))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestRefuseClone(t *testing.T) {
	if got := RefuseClone(Classify("https://example.com/a.git"), Policy{}); got != "" {
		t.Fatal(got)
	}
	if got := RefuseClone(Classify("ext::synthetic-transport"), Policy{AllowLocal: true}); got == "" {
		t.Fatal("helper was allowed")
	}
	if got := RefuseClone(Classify("/tmp/repo"), Policy{}); got == "" {
		t.Fatal("local path was allowed")
	}
	if got := RefuseClone(Classify("/tmp/repo"), Policy{AllowLocal: true}); got != "" {
		t.Fatal(got)
	}
	if got := RefuseClone(Classify("https://user:fixture-token@example.invalid/a.git"), Policy{}); got == "" {
		t.Fatal("credentials were allowed")
	}
	if got := RefuseClone(Classify("http://example.com/a.git"), Policy{}); got == "" {
		t.Fatal("http was allowed")
	}
	if got := RefuseClone(Classify("http://example.com/a.git"), Policy{AllowHTTP: true}); got != "" {
		t.Fatal(got)
	}
}
