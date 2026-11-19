// Package gitattributes parses .gitattributes lines used by the audit.
package gitattributes

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// State is how an attribute is set on a line.
type State string

const (
	StateSet         State = "set"
	StateUnset       State = "unset"
	StateValue       State = "value"
	StateUnspecified State = "unspecified"
)

// Attr is one attribute assignment.
type Attr struct {
	Key   string
	State State
	Value string
}

// Line is one attributes rule.
type Line struct {
	Pattern string
	Attrs   []Attr
	Number  int
}

// Parse parses attributes text. Blank lines, comments, and macro definitions
// are skipped. A broken line is skipped rather than failing the file.
func Parse(text string) []Line {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	var out []Line
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[attr]") {
			continue
		}
		pattern, rest, ok := firstField(line)
		if !ok || pattern == "" {
			continue
		}
		var attrs []Attr
		for rest != "" {
			var field string
			field, rest, ok = firstField(rest)
			if !ok || field == "" {
				break
			}
			attrs = append(attrs, parseAttr(field))
		}
		if len(attrs) == 0 {
			continue
		}
		out = append(out, Line{Pattern: pattern, Attrs: attrs, Number: i + 1})
	}
	return out
}

// FilterDrivers lists distinct filter driver names with a safe spelling.
// Names that contain spaces or shell characters are omitted so callers can
// pass the rest as git config keys without executing anything.
func FilterDrivers(text string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, line := range Parse(text) {
		for _, attr := range line.Attrs {
			if attr.Key != "filter" || attr.State != StateValue || !validDriver(attr.Value) {
				continue
			}
			if _, ok := seen[attr.Value]; ok {
				continue
			}
			seen[attr.Value] = struct{}{}
			out = append(out, attr.Value)
		}
	}
	return out
}

func validDriver(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func parseAttr(field string) Attr {
	switch {
	case strings.HasPrefix(field, "-") && len(field) > 1:
		return Attr{Key: field[1:], State: StateUnset}
	case strings.HasPrefix(field, "!") && len(field) > 1:
		return Attr{Key: field[1:], State: StateUnspecified}
	case strings.Contains(field, "="):
		k, v, _ := strings.Cut(field, "=")
		return Attr{Key: k, State: StateValue, Value: unquote(v)}
	default:
		return Attr{Key: field, State: StateSet}
	}
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// firstField returns the next field, honoring double quotes.
func firstField(s string) (field, rest string, ok bool) {
	s = strings.TrimLeftFunc(s, isSpace)
	if s == "" {
		return "", "", true
	}
	if s[0] == '"' {
		var b strings.Builder
		for i := 1; i < len(s); {
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				return "", "", false
			}
			if r == '"' {
				return b.String(), strings.TrimLeftFunc(s[i+size:], isSpace), true
			}
			if r == '\\' {
				i += size
				if i >= len(s) {
					return "", "", false
				}
				r, size = utf8.DecodeRuneInString(s[i:])
			}
			b.WriteRune(r)
			i += size
		}
		return "", "", false
	}
	i := 0
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		if isSpace(r) {
			break
		}
		i += size
	}
	return s[:i], strings.TrimLeftFunc(s[i:], isSpace), true
}

func isSpace(r rune) bool {
	return r == ' ' || r == '\t'
}
