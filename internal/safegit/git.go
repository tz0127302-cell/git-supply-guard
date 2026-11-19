// Package safegit builds git command arguments that do not run repository hooks.
package safegit

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Protect returns -c overrides that apply only to this git process.
// hooksDir must be an empty directory the caller created. The overrides are
// not written into a repository.
func Protect(hooksDir string) []string {
	return []string{
		"-c", "core.hooksPath=" + hooksDir,
		"-c", "core.fsmonitor=",
		"-c", "submodule.recurse=false",
		"-c", "fetch.recurseSubmodules=false",
		"-c", "protocol.file.allow=user",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.fd.allow=never",
	}
}

// Env returns a child environment that will not prompt and will not run the
// Git LFS smudge filter.
func Env() []string {
	base := os.Environ()
	extra := []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GCM_INTERACTIVE=Never",
	}
	return append(base, extra...)
}

// Runner executes git with process-local safety overrides.
type Runner struct {
	Bin      string
	HooksDir string
	Dir      string
}

// NewRunner creates an empty hooks directory and a runner that uses it.
func NewRunner(dir, bin string) (*Runner, error) {
	if bin == "" {
		bin = "git"
	}
	hooks, err := os.MkdirTemp("", "gsg-hooks-*")
	if err != nil {
		return nil, err
	}
	return &Runner{Bin: bin, HooksDir: hooks, Dir: dir}, nil
}

// Close removes the temporary hooks directory.
func (r *Runner) Close() {
	if r != nil && r.HooksDir != "" {
		_ = os.RemoveAll(r.HooksDir)
	}
}

// Run executes git. args follow the safety -c overrides, so they must not
// start with a user-controlled -c that re-enables hooks. Output is combined.
func (r *Runner) Run(ctx context.Context, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	full := append(Protect(r.HooksDir), args...)
	cmd := exec.CommandContext(ctx, r.Bin, full...)
	if r.Dir != "" {
		cmd.Dir = r.Dir
	}
	cmd.Env = Env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 240 {
			msg = msg[:240] + "…"
		}
		return out, fmt.Errorf("git %s: %w (%s)", strings.Join(redactArgs(args), " "), err, msg)
	}
	return out, nil
}

func redactArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.Contains(a, "://") || strings.Contains(a, "@") {
			out[i] = clip(a, 80)
			continue
		}
		out[i] = a
	}
	return out
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// WithTimeout returns a child context.
func WithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, d)
}
