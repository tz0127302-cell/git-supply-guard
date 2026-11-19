// Package clone wraps git clone so it does not recurse into submodules and
// does not run hooks or smudge filters.
package clone

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tz0127302-cell/git-supply-guard/internal/gitattributes"
	"github.com/tz0127302-cell/git-supply-guard/internal/safegit"
	"github.com/tz0127302-cell/git-supply-guard/internal/scan"
	"github.com/tz0127302-cell/git-supply-guard/internal/urlclass"
)

// Refusal is a URL gsg will not pass to git.
type Refusal struct {
	URL    string
	Reason string
}

func (r *Refusal) Error() string { return r.Reason }

// Request is one clone.
type Request struct {
	URL        string
	Dest       string
	AllowHTTP  bool
	AllowGit   bool
	AllowLocal bool
	Checkout   bool
	GitBin     string
}

// Result is a finished clone plus the audit of the destination.
type Result struct {
	Destination string
	CheckedOut  bool
	Scan        *scan.Result
	Notes       []string
}

// Clone clones url into dest without submodule recursion. Hooks and smudge
// filters are not executed. Submodule URLs are reported by the follow-up scan
// and are not fetched.
func Clone(ctx context.Context, req Request) (*Result, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
	}
	info := urlclass.Classify(req.URL)
	if reason := urlclass.RefuseClone(info, urlclass.Policy{
		AllowHTTP:  req.AllowHTTP,
		AllowGit:   req.AllowGit,
		AllowLocal: req.AllowLocal,
	}); reason != "" {
		return nil, &Refusal{URL: info.Redacted, Reason: reason}
	}
	dest, err := filepath.Abs(req.Dest)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(dest); err == nil {
		return nil, fmt.Errorf("destination already exists: %s", dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return nil, err
	}
	gitBin := req.GitBin
	if gitBin == "" {
		gitBin = "git"
	}
	template, err := os.MkdirTemp("", "gsg-template-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(template)

	runner, err := safegit.NewRunner("", gitBin)
	if err != nil {
		return nil, err
	}
	defer runner.Close()

	if _, err := runner.Run(ctx, cloneArgs(template, req.URL, dest)...); err != nil {
		_ = os.RemoveAll(dest)
		return nil, err
	}

	notes := []string{
		"Clone did not recurse into submodules and did not fetch them.",
		"Hooks were not executed.",
	}
	if req.AllowHTTP {
		notes = append(notes, "Cleartext http was explicitly allowed.")
	}
	if req.AllowGit {
		notes = append(notes, "Unauthenticated git protocol was explicitly allowed.")
	}
	if req.AllowLocal {
		notes = append(notes, "Local filesystem clone was explicitly allowed.")
	}

	checkedOut := false
	if req.Checkout {
		runner.Dir = dest
		drivers, hasHead, err := filterDrivers(ctx, runner)
		switch {
		case err != nil:
			notes = append(notes, "Could not list attributes before checkout; checkout was skipped.")
		case !hasHead:
			notes = append(notes, "Repository has no commits; checkout was skipped.")
		default:
			args := append(filterOverrides(drivers), "checkout", "--no-recurse-submodules", "-f", "HEAD")
			if _, err := runner.Run(ctx, args...); err != nil {
				notes = append(notes, "Checkout failed; the repository is present without a worktree. "+err.Error())
			} else {
				checkedOut = true
				notes = append(notes, "Checkout did not run smudge filters.")
			}
		}
	} else {
		notes = append(notes, "Checkout was skipped.")
	}

	audited, err := scan.Scan(ctx, scan.Options{Root: dest, GitBin: gitBin})
	if err != nil {
		return &Result{Destination: dest, CheckedOut: checkedOut, Notes: notes}, err
	}
	audited.Notes = append(notes, audited.Notes...)
	return &Result{Destination: dest, CheckedOut: checkedOut, Scan: audited, Notes: audited.Notes}, nil
}

func cloneArgs(template, rawURL, dest string) []string {
	return []string{
		"clone",
		"--no-checkout",
		"--no-recurse-submodules",
		"--no-local",
		"--template", template,
		"--",
		rawURL,
		dest,
	}
}

func filterDrivers(ctx context.Context, runner *safegit.Runner) ([]string, bool, error) {
	if _, err := runner.Run(ctx, "rev-parse", "--verify", "--quiet", "HEAD"); err != nil {
		return nil, false, nil
	}
	out, err := runner.Run(ctx, "ls-tree", "-r", "-z", "HEAD")
	if err != nil {
		return nil, true, err
	}
	var names []string
	seen := map[string]struct{}{}
	for _, rec := range splitZ(out) {
		path, hash, ok := treePath(rec)
		if !ok || (path != ".gitattributes" && !strings.HasSuffix(path, "/.gitattributes")) {
			continue
		}
		blob, err := runner.Run(ctx, "cat-file", "blob", hash)
		if err != nil {
			continue
		}
		for _, name := range gitattributes.FilterDrivers(string(blob)) {
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names, true, nil
}

func filterOverrides(names []string) []string {
	all := append([]string{"lfs"}, names...)
	seen := map[string]struct{}{}
	var args []string
	for _, name := range all {
		if !driverOK(name) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		args = append(args,
			"-c", "filter."+name+".smudge=",
			"-c", "filter."+name+".clean=",
			"-c", "filter."+name+".process=",
			"-c", "filter."+name+".required=false",
		)
	}
	return args
}

func driverOK(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r == '-' || r == '_' || r == '.' || (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			continue
		}
		return false
	}
	return true
}

func splitZ(out []byte) [][]byte {
	if len(out) == 0 {
		return nil
	}
	parts := bytesSplit(out)
	return parts
}

func bytesSplit(out []byte) [][]byte {
	var parts [][]byte
	start := 0
	for i, b := range out {
		if b == 0 {
			if i > start {
				parts = append(parts, out[start:i])
			}
			start = i + 1
		}
	}
	if start < len(out) {
		parts = append(parts, out[start:])
	}
	return parts
}

func treePath(rec []byte) (path, hash string, ok bool) {
	tab := -1
	for i, b := range rec {
		if b == '\t' {
			tab = i
			break
		}
	}
	if tab < 0 {
		return "", "", false
	}
	meta := string(rec[:tab])
	fields := strings.Split(meta, " ")
	if len(fields) != 3 || !hexHash(fields[2]) {
		return "", "", false
	}
	return string(rec[tab+1:]), fields[2], true
}

func hexHash(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
