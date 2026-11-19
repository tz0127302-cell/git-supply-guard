// Package urlclass classifies git URLs without contacting them.
package urlclass

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/tz0127302-cell/git-supply-guard/internal/redact"
)

// Info describes a remote URL or a path git might treat as one.
type Info struct {
	Raw         string
	Protocol    string
	Host        string
	Relative    bool
	Helper      bool
	Local       bool
	Credentials bool
	Redacted    string
}

// Policy decides which protocols gsg clone will pass to git.
type Policy struct {
	AllowHTTP  bool
	AllowGit   bool
	AllowLocal bool
}

// Classify labels a URL. It does not resolve relative URLs and it does not
// open the network.
func Classify(raw string) Info {
	s := strings.TrimSpace(raw)
	info := Info{Raw: s, Protocol: "empty", Redacted: redact.URL(s)}
	if s == "" {
		return info
	}
	if strings.Contains(s, "://") {
		return classifyScheme(s, info)
	}
	if i := strings.Index(s, "::"); i > 0 && !strings.Contains(s[:i], "/") {
		info.Protocol = strings.ToLower(s[:i])
		info.Helper = true
		info.Redacted = redact.Clip(info.Redacted, 120)
		return info
	}
	if host, creds, ok := scpLike(s); ok {
		info.Protocol = "ssh"
		info.Host = host
		info.Credentials = creds
		info.Redacted = redact.URL(s)
		return info
	}
	if filepath.IsAbs(s) {
		info.Protocol = "file"
		info.Local = true
		return info
	}
	info.Protocol = "relative"
	info.Relative = true
	info.Local = true
	return info
}

func classifyScheme(s string, info Info) Info {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" {
		info.Protocol = "unknown"
		return info
	}
	info.Protocol = strings.ToLower(u.Scheme)
	info.Host = u.Hostname()
	if u.User != nil {
		if pwd, ok := u.User.Password(); ok && pwd != "" {
			info.Credentials = true
		}
	}
	info.Redacted = redact.URL(s)
	switch info.Protocol {
	case "file":
		info.Local = true
	case "ext", "fd":
		info.Helper = true
	default:
		if strings.Contains(u.Opaque, ":") && info.Protocol != "http" && info.Protocol != "https" && info.Protocol != "ssh" && info.Protocol != "git" && info.Protocol != "git+ssh" {
			info.Helper = true
		}
	}
	if info.Helper {
		info.Redacted = redact.Clip(info.Redacted, 120)
	}
	return info
}

func scpLike(s string) (host string, creds bool, ok bool) {
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") {
		return "", false, false
	}
	rest := s
	if at := strings.LastIndex(s, "@"); at >= 0 {
		userinfo := s[:at]
		rest = s[at+1:]
		if strings.Contains(userinfo, ":") {
			creds = true
		}
	}
	colon := strings.Index(rest, ":")
	if colon <= 0 || colon == len(rest)-1 {
		return "", false, false
	}
	host = rest[:colon]
	path := rest[colon+1:]
	if host == "" || strings.Contains(host, "/") || strings.HasPrefix(path, "//") {
		return "", false, false
	}
	return host, creds, true
}

// SubmoduleSeverity returns critical, high, or empty when the protocol is a
// normal https or ssh URL. Relative URLs are reported by a separate check.
func (info Info) SubmoduleSeverity() string {
	if info.Relative && info.Protocol == "relative" {
		return ""
	}
	switch info.Protocol {
	case "https", "ssh", "git+ssh":
		if info.Helper {
			return "critical"
		}
		return ""
	case "http", "git":
		return "high"
	case "empty":
		return "high"
	default:
		return "critical"
	}
}

// RefuseClone explains why gsg clone will not pass this URL to git.
// A nil error means the URL is allowed under pol.
func RefuseClone(info Info, pol Policy) string {
	if info.Credentials {
		return "refusing URL with embedded credentials; remove the username and password and use a credential helper"
	}
	if info.Protocol == "empty" {
		return "refusing an empty URL"
	}
	if info.Helper || info.Protocol == "ext" || info.Protocol == "fd" {
		return "refusing transport helper URL; gsg only clones https and ssh unless you explicitly allow http, git, or a local path"
	}
	switch info.Protocol {
	case "https", "ssh", "git+ssh":
		return ""
	case "http":
		if pol.AllowHTTP {
			return ""
		}
		return "refusing cleartext http URL; pass --allow-http to continue"
	case "git":
		if pol.AllowGit {
			return ""
		}
		return "refusing unauthenticated git:// URL; pass --allow-git to continue"
	case "file", "relative":
		if pol.AllowLocal {
			return ""
		}
		return "refusing local path; pass --allow-local to clone from the filesystem"
	default:
		return "refusing URL protocol " + info.Protocol
	}
}
