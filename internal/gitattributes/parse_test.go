package gitattributes

import "testing"

func TestParse(t *testing.T) {
	const src = `
# comment
* filter=synthetic-smudge
SECURITY.md export-ignore
vendor/creds merge=ours
*.bin binary -diff
"quoted path" diff=custom
`
	lines := Parse(src)
	if len(lines) != 5 {
		t.Fatalf("lines: %#v", lines)
	}
	if lines[0].Attrs[0].Key != "filter" || lines[0].Attrs[0].Value != "synthetic-smudge" {
		t.Fatalf("%#v", lines[0])
	}
	if lines[3].Attrs[0].Key != "binary" || lines[3].Attrs[0].State != StateSet {
		t.Fatalf("%#v", lines[3])
	}
	if lines[3].Attrs[1].Key != "diff" || lines[3].Attrs[1].State != StateUnset {
		t.Fatalf("%#v", lines[3])
	}
	names := FilterDrivers(src)
	if len(names) != 1 || names[0] != "synthetic-smudge" {
		t.Fatalf("drivers %#v", names)
	}
}

func TestFilterDriversRejectsOddNames(t *testing.T) {
	if got := FilterDrivers("* filter=bad$name\n"); len(got) != 0 {
		t.Fatalf("%#v", got)
	}
}
