package scan

import (
	"path/filepath"
	"strings"

	"github.com/tz0127302-cell/git-supply-guard/internal/model"
	"github.com/tz0127302-cell/git-supply-guard/internal/redact"
)

func symlinkFinding(root, linkPath, target, rel string) (model.Finding, bool) {
	shown := redact.Clip(target, 120)
	if targetsGitMetadata(target) || targetsGitMetadata(resolvedLink(linkPath, target)) {
		return model.Finding{
			ID:          model.IDLinkGitMeta,
			Title:       "Symbolic link points at git metadata",
			Severity:    model.Critical,
			Category:    "symlink",
			Location:    rel,
			Detail:      "Symbolic link target is " + shown + ". It points at git metadata or a hook path. This scan did not follow it.",
			Remediation: "Remove the link or retarget it after you have reviewed the destination.",
		}, true
	}
	if filepath.IsAbs(target) || linkOutside(root, linkPath, target) {
		return model.Finding{
			ID:          model.IDLinkOutside,
			Title:       "Symbolic link points outside the worktree",
			Severity:    model.High,
			Category:    "symlink",
			Location:    rel,
			Detail:      "Symbolic link target is " + shown + ", which does not stay inside this worktree.",
			Remediation: "Retarget the link inside the worktree, or remove it before trusting the checkout.",
		}, true
	}
	return model.Finding{}, false
}

func resolvedLink(linkPath, target string) string {
	if filepath.IsAbs(target) {
		return filepath.Clean(target)
	}
	return filepath.Clean(filepath.Join(filepath.Dir(linkPath), target))
}

func linkOutside(root, linkPath, target string) bool {
	dest := resolvedLink(linkPath, target)
	rel, err := filepath.Rel(root, dest)
	if err != nil {
		return true
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func targetsGitMetadata(p string) bool {
	if strings.TrimSpace(p) == "" {
		return false
	}
	slash := filepath.ToSlash(filepath.Clean(p))
	if slash == ".git" || strings.HasPrefix(slash, ".git/") || strings.HasSuffix(slash, "/.git") || strings.Contains(slash, "/.git/") {
		return true
	}
	return false
}
