package scan

import (
	"bytes"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/tz0127302-cell/git-supply-guard/internal/model"
	"github.com/tz0127302-cell/git-supply-guard/internal/redact"
)

const (
	maxWalkFiles = 50000
	maxPathBytes = 4096
)

func walkWorktree(root string, exclude []string, c *collector) {
	n := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			c.note(relSlash(root, path) + ": " + err.Error())
			return nil
		}
		rel := relSlash(root, path)
		if rel == "." {
			return nil
		}
		base := filepath.Base(path)
		if base == ".git" {
			if rel != ".git" {
				c.add(nestedGitFinding(rel, d.Type()&os.ModeSymlink != 0))
			}
			if d.IsDir() && d.Type()&os.ModeSymlink == 0 {
				return fs.SkipDir
			}
			return nil
		}
		if excluded(rel, exclude) {
			if d.IsDir() && d.Type()&os.ModeSymlink == 0 {
				return fs.SkipDir
			}
			return nil
		}
		n++
		if n > maxWalkFiles {
			c.add(model.Finding{
				ID:          model.IDLimit,
				Title:       "Walk stopped at the file limit",
				Severity:    model.Medium,
				Category:    "limit",
				Location:    rel,
				Detail:      "The worktree walk stopped after 50000 entries. Later files were not audited.",
				Remediation: "Scan a smaller directory, or exclude generated trees with --exclude.",
			})
			return fs.SkipAll
		}
		if len(rel) > maxPathBytes {
			c.add(model.Finding{
				ID:          model.IDPathLong,
				Title:       "Unusually long path",
				Severity:    model.Low,
				Category:    "path",
				Location:    redact.Clip(rel, 120),
				Detail:      "This path is unusually long. Review the tree before a recursive clone.",
				Remediation: "Inspect the path and avoid recursive clones until you understand the tree.",
			})
		}
		if d.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				c.note(rel + ": could not read symbolic link")
				return nil
			}
			if finding, ok := symlinkFinding(root, path, target, rel); ok {
				c.add(finding)
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			c.add(model.Finding{
				ID:          model.IDModeSpecial,
				Title:       "Special file in the worktree",
				Severity:    model.Medium,
				Category:    "mode",
				Location:    rel,
				Detail:      "This worktree entry is not a regular file, directory, or symbolic link.",
				Remediation: "Remove the special file unless it is intentional.",
			})
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if executableMeta(base) && info.Mode()&0o111 != 0 {
			c.add(model.Finding{
				ID:          model.IDModeExecMeta,
				Title:       "Metadata file is executable",
				Severity:    model.Low,
				Category:    "mode",
				Location:    rel,
				Detail:      "This git metadata file has an executable bit set.",
				Remediation: "Clear the executable bit unless a script really should live at this path.",
			})
		}
		if id, ok := trackedHook(rel); ok {
			c.add(hookFinding(rel, id))
		}
		switch base {
		case ".gitattributes":
			readAttributesFile(path, rel, c)
		case ".gitmodules":
			readGitmodulesFile(root, path, rel, c)
		case ".gitconfig":
			if rel == ".gitconfig" {
				c.add(model.Finding{
					ID:          model.IDImportFile,
					Title:       "Committed gitconfig is present",
					Severity:    model.Low,
					Category:    "import",
					Location:    rel,
					Detail:      "A .gitconfig file is stored in the worktree. Git does not load it unless config includes it.",
					Remediation: "Review the file before including it from a git config.",
				})
			}
		}
		if isAutomation(rel) {
			scanAutomation(path, rel, c)
		}
		return nil
	})
}

func nestedGitFinding(rel string, symlink bool) model.Finding {
	if symlink {
		return model.Finding{
			ID:          model.IDLinkGitSymlink,
			Title:       "Nested .git entry is a symbolic link",
			Severity:    model.Critical,
			Category:    "symlink",
			Location:    rel,
			Detail:      "A nested .git entry is a symbolic link. This scan did not follow it and did not execute hooks.",
			Remediation: "Replace the link with a normal git directory or a gitdir file you have reviewed.",
		}
	}
	return model.Finding{
		ID:          model.IDLinkGitSymlink,
		Title:       "Nested git metadata directory",
		Severity:    model.Medium,
		Category:    "symlink",
		Location:    rel,
		Detail:      "A nested .git directory or file is present. This scan did not enter it.",
		Remediation: "Confirm it is an intentional embedded repository or submodule checkout.",
	}
}

func executableMeta(base string) bool {
	switch base {
	case ".gitmodules", ".gitattributes", ".gitconfig":
		return true
	default:
		return false
	}
}

func readAttributesFile(path, rel string, c *collector) {
	data, err := readRegular(path, maxRead)
	if err != nil {
		noteRead(c, rel, err)
		return
	}
	for _, finding := range analyzeAttributes(rel, string(data)) {
		c.add(finding)
	}
}

func readGitmodulesFile(root, path, rel string, c *collector) {
	if rel != ".gitmodules" {
		c.add(model.Finding{
			ID:          model.IDSubDuplicate,
			Title:       "gitmodules file is not at the worktree root",
			Severity:    model.Medium,
			Category:    "submodule",
			Location:    rel,
			Detail:      "Git only uses the root .gitmodules file. Another copy can confuse reviewers.",
			Remediation: "Keep submodule declarations in the root .gitmodules file.",
		})
	}
	// The root file is parsed once by the orchestrator so submodule inventory
	// stays in one place. Nested copies are still parsed here.
	if rel == ".gitmodules" {
		return
	}
	data, err := readRegular(path, maxRead)
	if err != nil {
		noteRead(c, rel, err)
		return
	}
	c.consumeGitmodules(rel, data)
}

func scanAutomation(path, rel string, c *collector) {
	data, err := readRegular(path, maxRead)
	if err != nil {
		noteRead(c, rel, err)
		return
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	n := 0
	for i, line := range strings.Split(text, "\n") {
		if !recursiveCloneLine(line) {
			continue
		}
		n++
		if n > 20 {
			c.note(rel + ": stopped after 20 recursive-clone mentions")
			return
		}
		c.add(model.Finding{
			ID:          model.IDCloneRecursive,
			Title:       "Automation mentions a recursive clone",
			Severity:    model.Medium,
			Category:    "clone",
			Location:    loc(rel, i+1),
			Detail:      "This automation file mentions a recursive clone or a recursive submodule update. A recursive clone can pull extra repositories and hook configuration.",
			Remediation: "Clone without recursion, then review .gitmodules before initializing submodules.",
		})
	}
}

func isAutomation(rel string) bool {
	rel = filepath.ToSlash(rel)
	base := path.Base(rel)
	switch base {
	case "Makefile", "makefile", "GNUmakefile", "justfile", "Jenkinsfile",
		".gitlab-ci.yml", "bitbucket-pipelines.yml", "azure-pipelines.yml":
		return true
	}
	if (strings.HasPrefix(rel, ".github/workflows/") || strings.Contains(rel, "/.github/workflows/")) &&
		(strings.HasSuffix(rel, ".yml") || strings.HasSuffix(rel, ".yaml")) {
		return true
	}
	if (strings.HasPrefix(rel, "scripts/") || strings.Contains(rel, "/scripts/")) &&
		(strings.HasSuffix(rel, ".sh") || strings.HasSuffix(rel, ".bash")) {
		return true
	}
	return false
}

func recursiveCloneLine(line string) bool {
	lower := strings.ToLower(line)
	if hasFlag(lower, "--recurse-submodules") {
		return true
	}
	if strings.Contains(lower, "submodule") && strings.Contains(lower, "update") && hasFlag(lower, "--recursive") {
		return true
	}
	if strings.Contains(lower, "git") && strings.Contains(lower, "clone") && hasFlag(lower, "--recursive") {
		return true
	}
	return false
}

func hasFlag(line, flag string) bool {
	rest := line
	for {
		i := strings.Index(rest, flag)
		if i < 0 {
			return false
		}
		if i >= 3 && rest[i-3:i] == "no-" {
			rest = rest[i+len(flag):]
			continue
		}
		return true
	}
}

func noteRead(c *collector, rel string, err error) {
	if err == nil {
		return
	}
	if err == errNotRegular {
		c.add(model.Finding{
			ID:          model.IDLinkGitMeta,
			Title:       "Metadata file is not a regular file",
			Severity:    model.High,
			Category:    "symlink",
			Location:    rel,
			Detail:      "This metadata file is a symbolic link or another non-regular file. The target was not followed.",
			Remediation: "Replace it with a regular file whose contents you have reviewed.",
		})
		return
	}
	if err == errTooBig {
		c.add(model.Finding{
			ID:          model.IDLimit,
			Title:       "File exceeds the scan size limit",
			Severity:    model.Medium,
			Category:    "limit",
			Location:    rel,
			Detail:      "The file is larger than 2 MiB and was not parsed.",
			Remediation: "Inspect the file manually. gsg does not execute it.",
		})
		return
	}
	c.note(rel + ": " + err.Error())
}
