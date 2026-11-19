// Package harden prints safer local git settings and, with --apply, writes
// a small set of them. It does not change global config and it does not
// update the git binary.
package harden

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tz0127302-cell/git-supply-guard/internal/gitconfig"
	"github.com/tz0127302-cell/git-supply-guard/internal/model"
	"github.com/tz0127302-cell/git-supply-guard/internal/redact"
	"github.com/tz0127302-cell/git-supply-guard/internal/safegit"
)

// Request is one harden run. Apply writes local config; the default is dry-run.
type Request struct {
	Root   string
	Apply  bool
	GitBin string
}

// Result is the recommendation list.
type Result struct {
	Root    string
	IsRepo  bool
	Applied bool
	Advice  []model.Advice
	Notes   []string
}

type setting struct {
	id      string
	key     string
	desired string
	reason  string
}

var appliedSettings = []setting{
	{
		id: "H-SUBMODULE-RECURSE", key: "submodule.recurse", desired: "false",
		reason: "Do not recurse into submodules unless a command asks for it.",
	},
	{
		id: "H-FETCH-FSCK", key: "fetch.fsckObjects", desired: "true",
		reason: "Reject malformed objects during fetch.",
	},
	{
		id: "H-TRANSFER-FSCK", key: "transfer.fsckObjects", desired: "true",
		reason: "Reject malformed objects on transfer.",
	},
	{
		id: "H-RECEIVE-FSCK", key: "receive.fsckObjects", desired: "true",
		reason: "Reject malformed objects on receive.",
	},
	{
		id: "H-FILE-ALLOW", key: "protocol.file.allow", desired: "user",
		reason: "Allow file URLs only when a person passes one on the command line.",
	},
}

// Run builds recommendations. When Apply is set, the five local settings
// above are written with git config --local.
func Run(ctx context.Context, req Request) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	root := req.Root
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", abs)
	}
	gitBin := req.GitBin
	if gitBin == "" {
		gitBin = "git"
	}
	notes := []string{}
	if req.Apply {
		notes = append(notes, "Local config was updated. Global config was not changed.")
	} else {
		notes = append(notes, "Dry-run. No config was changed. Re-run with --apply to write the local settings.")
	}
	notes = append(notes, detectedGit(ctx, gitBin))

	isRepo, configPath := localConfigPath(abs)
	current := map[string]string{}
	if isRepo {
		if data, err := os.ReadFile(configPath); err == nil {
			file, warnings := gitconfig.Parse(configPath, data)
			for _, warning := range warnings {
				notes = append(notes, warning)
			}
			for _, entry := range file.Keys {
				full := strings.ToLower(entry.Section + "." + joinSub(entry.Subsection) + entry.Key)
				current[full] = entry.Value
			}
		}
	} else {
		notes = append(notes, "This directory is not a git repository. Recommendations are printed, and --apply needs a checkout.")
		if req.Apply {
			return nil, fmt.Errorf("cannot apply settings outside a git repository")
		}
	}

	var advice []model.Advice
	advice = append(advice, model.Advice{
		ID:     "H-GIT-UPDATE",
		Reason: "Install Git 2.56.1, or the patched release on your maintenance line (2.55.1, 2.54.1, 2.53.1, 2.52.1, 2.51.3, or 2.50.2). git-supply-guard does not update Git and does not decide whether your build already includes those fixes.",
	})
	advice = append(advice, model.Advice{
		ID:     "H-CLONE-FLAGS",
		Reason: "Clone with: git -c submodule.recurse=false clone --no-recurse-submodules <url>. Review .gitmodules before initializing submodules.",
	})
	advice = append(advice, model.Advice{
		ID:     "H-UNTRUSTED-INPUT",
		Reason: "Do not feed Git untrusted fast-import streams or binary patches. The patched Git release is the fix for that class of bug.",
	})

	var runner *safegit.Runner
	if req.Apply {
		runner, err = safegit.NewRunner(abs, gitBin)
		if err != nil {
			return nil, err
		}
		defer runner.Close()
	}
	appliedAny := false
	for _, setting := range appliedSettings {
		cur := lookup(current, setting.key)
		item := model.Advice{
			ID:      setting.id,
			Key:     setting.key,
			Desired: setting.desired,
			Current: cur,
			Apply:   true,
			Reason:  setting.reason,
		}
		if req.Apply && cur != setting.desired {
			if _, err := runner.Run(ctx, "config", "--local", setting.key, setting.desired); err != nil {
				return nil, fmt.Errorf("set %s: %w", setting.key, err)
			}
			item.Applied = true
			appliedAny = true
		}
		advice = append(advice, item)
	}

	advice = append(advice, review("H-REVIEW-CREDENTIAL", "credential.helper", lookup(current, "credential.helper"),
		"Review credential.helper. gsg does not change it. A local helper travels with a copied .git directory.")...)
	advice = append(advice, review("H-REVIEW-HOOKS", "core.hooksPath", lookup(current, "core.hooksPath"),
		"Review core.hooksPath. gsg does not change it. A path inside the worktree runs committed scripts.")...)
	advice = append(advice, review("H-REVIEW-SAFE", "safe.directory", lookup(current, "safe.directory"),
		"Do not set safe.directory to *. gsg does not change this key.")...)
	advice = append(advice, model.Advice{
		ID:     "H-REVIEW-FILTERS",
		Reason: "Review filter.*.smudge, filter.*.clean, and diff textconv commands before the next checkout. gsg clone refuses to run them; a normal git checkout might.",
	})

	return &Result{Root: abs, IsRepo: isRepo, Applied: appliedAny, Advice: advice, Notes: notes}, nil
}

func review(id, key, current, reason string) []model.Advice {
	item := model.Advice{ID: id, Key: key, Current: redact.Text(current, 80), Reason: reason}
	if current == "" {
		item.Current = ""
		item.Reason = reason + " Nothing is set in local config."
	}
	return []model.Advice{item}
}

func lookup(current map[string]string, key string) string {
	return current[strings.ToLower(key)]
}

func joinSub(sub string) string {
	if sub == "" {
		return ""
	}
	return sub + "."
}

func localConfigPath(root string) (bool, string) {
	gitPath := filepath.Join(root, ".git")
	st, err := os.Lstat(gitPath)
	if err != nil {
		return false, ""
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return false, ""
	}
	if st.IsDir() {
		return true, filepath.Join(gitPath, "config")
	}
	data, err := os.ReadFile(gitPath)
	if err != nil {
		return false, ""
	}
	text := strings.TrimSpace(string(data))
	const prefix = "gitdir:"
	if !strings.HasPrefix(strings.ToLower(text), prefix) {
		return false, ""
	}
	raw := strings.TrimSpace(text[len(prefix):])
	if !filepath.IsAbs(raw) {
		raw = filepath.Join(root, raw)
	}
	return true, filepath.Join(filepath.Clean(raw), "config")
}

func detectedGit(ctx context.Context, bin string) string {
	cmd := exec.CommandContext(ctx, bin, "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "Git was not detected on PATH. Install a patched release before trusting clones."
	}
	line := strings.TrimSpace(string(out))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	return "Detected " + line + ". Compare it with the official Git security announcement rather than with this tool."
}
