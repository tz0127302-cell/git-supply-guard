// Package gitconfig parses the subset of git config used by local audits.
// It never executes the values it reads.
package gitconfig

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
)

// File is a parsed git config.
type File struct {
	Path string
	Keys []Entry
}

// Entry is one key. Section and Key are lower-case. Subsection keeps its
// original case, matching git.
type Entry struct {
	Section    string
	Subsection string
	Key        string
	Value      string
	Line       int
}

// Parse parses data. Malformed lines are returned in Warnings and skipped so
// one odd line does not hide the rest of the file.
func Parse(path string, data []byte) (*File, []string) {
	f := &File{Path: path}
	if bytes.Contains(data, []byte{0}) {
		return f, []string{path + ": file contains NUL bytes and was not parsed"}
	}
	var warnings []string
	section := ""
	subsection := ""
	for _, ll := range logicalLines(data) {
		line := strings.TrimSpace(ll.Text)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			name, sub, ok := parseSection(line)
			if !ok {
				warnings = append(warnings, fmt.Sprintf("%s:%d: skipped unreadable section header", path, ll.Line))
				continue
			}
			section = name
			subsection = sub
			continue
		}
		if section == "" {
			warnings = append(warnings, fmt.Sprintf("%s:%d: key appears before a section", path, ll.Line))
			continue
		}
		key, value, ok := parseKV(line)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("%s:%d: skipped unreadable key", path, ll.Line))
			continue
		}
		f.Keys = append(f.Keys, Entry{
			Section:    section,
			Subsection: subsection,
			Key:        key,
			Value:      value,
			Line:       ll.Line,
		})
	}
	return f, warnings
}

// Values returns every occurrence of section.(subsection).key.
// An empty subsection matches only keys in the bare section.
func (f *File) Values(section, subsection, key string) []Entry {
	if f == nil {
		return nil
	}
	section = strings.ToLower(section)
	key = strings.ToLower(key)
	var out []Entry
	for _, e := range f.Keys {
		if e.Section == section && e.Subsection == subsection && e.Key == key {
			out = append(out, e)
		}
	}
	return out
}

// First returns the first matching value.
func (f *File) First(section, subsection, key string) (string, bool) {
	vs := f.Values(section, subsection, key)
	if len(vs) == 0 {
		return "", false
	}
	return vs[0].Value, true
}

// InSection returns keys whose section matches. Subsection may be empty to
// return every subsection, including the bare section.
func (f *File) InSection(section string) []Entry {
	if f == nil {
		return nil
	}
	section = strings.ToLower(section)
	var out []Entry
	for _, e := range f.Keys {
		if e.Section == section {
			out = append(out, e)
		}
	}
	return out
}

// IsTrue reports git's true booleans.
func IsTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "on", "1":
		return true
	default:
		return false
	}
}

// IsFalse reports git's false booleans.
func IsFalse(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "no", "off", "0":
		return true
	default:
		return false
	}
}

// IsBool reports whether v is a git boolean.
func IsBool(v string) bool {
	return IsTrue(v) || IsFalse(v)
}

type logical struct {
	Text string
	Line int
}

func logicalLines(data []byte) []logical {
	text := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	text = bytes.TrimPrefix(text, []byte{0xEF, 0xBB, 0xBF})
	raw := bytes.Split(text, []byte("\n"))
	var out []logical
	var b strings.Builder
	start := 1
	cont := false
	for i, rawLine := range raw {
		line := strings.TrimRight(string(rawLine), "\r")
		if cont {
			b.WriteString(line)
		} else {
			b.Reset()
			b.WriteString(line)
			start = i + 1
		}
		s := b.String()
		if oddTrailingBackslash(s) {
			b.Reset()
			b.WriteString(s[:len(s)-1])
			cont = true
			continue
		}
		out = append(out, logical{Text: b.String(), Line: start})
		cont = false
	}
	if cont {
		out = append(out, logical{Text: b.String(), Line: start})
	}
	return out
}

func oddTrailingBackslash(s string) bool {
	n := 0
	for len(s) > n && s[len(s)-1-n] == '\\' {
		n++
	}
	return n%2 == 1
}

func parseSection(s string) (name, sub string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" || s[0] != '[' {
		return "", "", false
	}
	// Drop a comment that starts after the closing bracket.
	i := 1
	for i < len(s) && s[i] != ']' && !unicode.IsSpace(rune(s[i])) {
		i++
	}
	name = s[1:i]
	if name == "" || !validName(name) {
		return "", "", false
	}
	for i < len(s) && unicode.IsSpace(rune(s[i])) {
		i++
	}
	if i < len(s) && s[i] == '"' {
		var n int
		sub, n, ok = parseQuoted(s[i:])
		if !ok {
			return "", "", false
		}
		i += n
		for i < len(s) && unicode.IsSpace(rune(s[i])) {
			i++
		}
	}
	if i >= len(s) || s[i] != ']' {
		return "", "", false
	}
	return strings.ToLower(name), sub, true
}

func validName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func parseKV(s string) (key, value string, ok bool) {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && isKeyChar(s[i]) {
		i++
	}
	if i == 0 {
		return "", "", false
	}
	key = strings.ToLower(s[:i])
	rest := strings.TrimSpace(s[i:])
	if rest == "" || rest[0] == '#' || rest[0] == ';' {
		return key, "true", true
	}
	if rest[0] != '=' {
		return "", "", false
	}
	rest = strings.TrimSpace(rest[1:])
	if rest == "" {
		return key, "", true
	}
	if rest[0] == '"' {
		v, _, qok := parseQuoted(rest)
		if !qok {
			return "", "", false
		}
		return key, v, true
	}
	return key, unescapeLoose(stripComment(rest)), true
}

func isKeyChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-'
}

func stripComment(s string) string {
	in := s
	for i := 0; i < len(in); i++ {
		if in[i] != '#' && in[i] != ';' {
			continue
		}
		if i == 0 || unicode.IsSpace(rune(in[i-1])) {
			return strings.TrimSpace(in[:i])
		}
	}
	return strings.TrimSpace(in)
}

func unescapeLoose(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'b':
			b.WriteByte('\b')
		case '"', '\\':
			b.WriteByte(s[i])
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func parseQuoted(s string) (string, int, bool) {
	if s == "" || s[0] != '"' {
		return "", 0, false
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 >= len(s) {
				return "", 0, false
			}
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'b':
				b.WriteByte('\b')
			case '"', '\\':
				b.WriteByte(s[i])
			default:
				b.WriteByte(s[i])
			}
		case '"':
			return b.String(), i + 1, true
		default:
			b.WriteByte(s[i])
		}
	}
	return "", 0, false
}
