// Package redact removes secrets from text that git-supply-guard prints.
package redact

import (
	"net/url"
	"strings"
	"unicode/utf8"
)

// URL redacts password material in a git URL. Non-URL text is returned with
// the same password-shaped userinfo removed when it is present.
func URL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.User != nil {
		if pwd, ok := u.User.Password(); ok && pwd != "" {
			return schemeUserHost(u)
		}
	}
	if redacted, ok := scrubSCP(raw); ok {
		return redacted
	}
	return scrubUserinfo(raw)
}

func scrubSCP(s string) (string, bool) {
	at := strings.LastIndex(s, "@")
	if at <= 0 || strings.Contains(s, "://") {
		return "", false
	}
	userinfo := s[:at]
	colon := strings.Index(userinfo, ":")
	if colon <= 0 {
		return "", false
	}
	return userinfo[:colon] + ":***@" + s[at+1:], true
}

func schemeUserHost(u *url.URL) string {
	var b strings.Builder
	b.WriteString(u.Scheme)
	b.WriteString("://")
	if u.User != nil {
		name := u.User.Username()
		b.WriteString(name)
		b.WriteString(":***@")
	}
	b.WriteString(u.Host)
	b.WriteString(u.EscapedPath())
	if u.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(u.RawQuery)
	}
	if u.Fragment != "" {
		b.WriteByte('#')
		b.WriteString(u.Fragment)
	}
	return b.String()
}

func scrubUserinfo(s string) string {
	// scheme://user:password@host
	const sep = "://"
	i := strings.Index(s, sep)
	if i < 0 {
		return s
	}
	rest := s[i+len(sep):]
	at := strings.Index(rest, "@")
	if at < 0 {
		return s
	}
	userinfo := rest[:at]
	colon := strings.Index(userinfo, ":")
	if colon < 0 {
		return s
	}
	return s[:i+len(sep)] + userinfo[:colon] + ":***@" + rest[at+1:]
}

// Clip shortens s to at most n runes and flattens newlines.
func Clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	if n <= 1 {
		return "…"
	}
	return string(runes[:n-1]) + "…"
}

// Text redacts URL userinfo inside a larger string and clips it.
func Text(s string, n int) string {
	return Clip(URL(s), n)
}
