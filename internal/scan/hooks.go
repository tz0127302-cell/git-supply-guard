package scan

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/tz0127302-cell/git-supply-guard/internal/model"
)

var hookNames = map[string]bool{
	"applypatch-msg": true, "pre-applypatch": true, "post-applypatch": true,
	"pre-commit": true, "pre-merge-commit": true, "prepare-commit-msg": true,
	"commit-msg": true, "post-commit": true, "pre-rebase": true,
	"post-checkout": true, "post-merge": true, "pre-push": true,
	"pre-receive": true, "update": true, "proc-receive": true,
	"post-receive": true, "post-update": true, "reference-transaction": true,
	"push-to-checkout": true, "pre-auto-gc": true, "post-rewrite": true,
	"sendemail-validate": true, "fsmonitor-watchman": true,
	"p4-changelist": true, "p4-prepare-changelist": true,
	"p4-post-changelist": true, "p4-pre-submit": true,
	"post-index-change": true,
}

var hookDirs = map[string]bool{
	"hooks": true, ".githooks": true, ".git-hooks": true, "githooks": true,
}

func trackedHook(rel string) (string, bool) {
	rel = path.Clean(filepath.ToSlash(rel))
	base := path.Base(rel)
	if base == "." || base == "/" || strings.HasSuffix(base, ".sample") {
		return "", false
	}
	dir := path.Base(path.Dir(rel))
	if hookDirs[dir] && hookNames[base] {
		return model.IDHookTracked, true
	}
	if strings.HasPrefix(rel, ".husky/") && (hookNames[base] || strings.Contains(rel, "/_/")) {
		return model.IDHookHusky, true
	}
	return "", false
}

func hookFinding(rel, id string) model.Finding {
	if id == model.IDHookHusky {
		return model.Finding{
			ID:          id,
			Title:       "Repository-controlled Husky hook",
			Severity:    model.Medium,
			Category:    "hook",
			Location:    rel,
			Detail:      "This file is a Husky hook entrypoint. It does not run unless hooks are installed for the clone. This scan did not run it.",
			Remediation: "Review the script before installing hooks or pointing core.hooksPath at .husky.",
		}
	}
	return model.Finding{
		ID:          id,
		Title:       "Tracked git hook script",
		Severity:    model.High,
		Category:    "hook",
		Location:    rel,
		Detail:      "This file is stored in the repository under a hook directory. It runs only if Git is pointed at that directory. This scan did not run it.",
		Remediation: "Review the script. Do not set core.hooksPath to a committed directory unless you trust it.",
	}
}

func installedHookFindings(gitDir string) []model.Finding {
	dir := filepath.Join(gitDir, "hooks")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []model.Finding
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".sample") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		executable := info.Mode()&0o111 != 0
		if !hookNames[name] && !executable {
			continue
		}
		out = append(out, model.Finding{
			ID:          model.IDHookInstalled,
			Title:       "Hook installed in the local git directory",
			Severity:    model.Medium,
			Category:    "hook",
			Location:    filepath.ToSlash(filepath.Join(".git", "hooks", name)),
			Detail:      "A non-sample hook file is present in .git/hooks. This scan did not execute it.",
			Remediation: "Confirm the hook belongs to this machine before the next git command.",
		})
	}
	return out
}
