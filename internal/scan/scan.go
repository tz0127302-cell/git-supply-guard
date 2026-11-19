// Package scan audits a checkout for git supply-chain and clone hygiene.
// It reads files and git metadata. It does not execute hooks, filters, or
// submodule commands.
package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/tz0127302-cell/git-supply-guard/internal/gitconfig"
	"github.com/tz0127302-cell/git-supply-guard/internal/model"
	"github.com/tz0127302-cell/git-supply-guard/internal/safegit"
)

// Options controls one scan.
type Options struct {
	Root      string
	Exclude   []string
	IgnoreIDs map[string]struct{}
	GitBin    string
}

// Result is the audit, before severity filtering.
type Result struct {
	Root       string
	IsRepo     bool
	Findings   []model.Finding
	Notes      []string
	Submodules []model.SubmoduleRef
}

type collector struct {
	findings []model.Finding
	notes    []string
	seen     map[string]struct{}
	refs     []model.SubmoduleRef
	flagged  map[string]bool
	gitlinks map[string]string
	treeRead bool
}

func (c *collector) add(f model.Finding) {
	if f.ID == "" || f.Severity == "" {
		return
	}
	if c.seen == nil {
		c.seen = map[string]struct{}{}
	}
	key := dedupeKey(f)
	if _, ok := c.seen[key]; ok {
		return
	}
	c.seen[key] = struct{}{}
	c.findings = append(c.findings, f)
}

func (c *collector) note(s string) {
	if strings.TrimSpace(s) == "" {
		return
	}
	c.notes = append(c.notes, s)
}

func (c *collector) consumeGitmodules(rel string, data []byte) {
	file, warnings := gitconfig.Parse(rel, data)
	for _, warning := range warnings {
		c.note(warning)
	}
	findings, refs, flagged := analyzeSubmodules(rel, file)
	for _, finding := range findings {
		c.add(finding)
	}
	if rel == ".gitmodules" {
		c.refs = refs
		if c.flagged == nil {
			c.flagged = map[string]bool{}
		}
		for name, ok := range flagged {
			if ok {
				c.flagged[name] = true
			}
		}
	}
}

type gitLayout struct {
	isRepo   bool
	gitDir   string
	gitFile  bool
	symlink  bool
	linkText string
}

// Scan audits root. The returned findings are sorted and have ignored IDs
// removed. Hooks are not executed.
func Scan(ctx context.Context, opts Options) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	root, err := prepareRoot(opts.Root)
	if err != nil {
		return nil, err
	}
	c := &collector{flagged: map[string]bool{}, gitlinks: map[string]string{}}
	layout := inspectGit(root, c)
	c.note("This scan did not execute hooks, filters, or submodule commands.")

	if layout.isRepo {
		loadLocalConfig(ctx, root, layout.gitDir, c)
		c.addAll(installedHookFindings(layout.gitDir))
		readTree(ctx, root, opts.GitBin, c)
	} else if !layout.symlink {
		c.add(model.Finding{
			ID:          model.IDRepoNotGit,
			Title:       "Directory is not a git repository",
			Severity:    model.Info,
			Category:    "repo",
			Location:    ".",
			Detail:      "No .git directory or gitdir file was found. Index, gitlink, and local config checks were skipped. Tracked files were still audited.",
			Remediation: "Run gsg from a git checkout when you also want local config and gitlink checks.",
		})
	}

	readRootGitmodules(root, c)
	walkWorktree(root, opts.Exclude, c)
	finishSubmodules(c)

	findings := make([]model.Finding, 0, len(c.findings))
	for _, finding := range c.findings {
		if _, skip := opts.IgnoreIDs[finding.ID]; skip {
			continue
		}
		if excluded(locationPath(finding.Location), opts.Exclude) {
			continue
		}
		findings = append(findings, finding)
	}
	sortFindings(findings)
	return &Result{
		Root:       root,
		IsRepo:     layout.isRepo,
		Findings:   findings,
		Notes:      c.notes,
		Submodules: c.refs,
	}, nil
}

func (c *collector) addAll(findings []model.Finding) {
	for _, finding := range findings {
		c.add(finding)
	}
}

func prepareRoot(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		path = "."
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s is not a directory", abs)
	}
	return abs, nil
}

func inspectGit(root string, c *collector) gitLayout {
	p := filepath.Join(root, ".git")
	st, err := os.Lstat(p)
	if err != nil {
		return gitLayout{}
	}
	if st.Mode()&os.ModeSymlink != 0 {
		target, _ := os.Readlink(p)
		c.add(model.Finding{
			ID:          model.IDLinkGitSymlink,
			Title:       ".git is a symbolic link",
			Severity:    model.Critical,
			Category:    "symlink",
			Location:    ".git",
			Detail:      ".git is a symbolic link to " + redactClip(target) + ". This scan did not follow it and did not run git commands against it.",
			Remediation: "Use a real .git directory or a regular gitdir file.",
		})
		return gitLayout{symlink: true, linkText: target}
	}
	if st.IsDir() {
		return gitLayout{isRepo: true, gitDir: p}
	}
	if !st.Mode().IsRegular() {
		c.add(model.Finding{
			ID:          model.IDLinkGitSymlink,
			Title:       ".git is not a regular file or directory",
			Severity:    model.High,
			Category:    "symlink",
			Location:    ".git",
			Detail:      ".git has an unusual file type. This scan did not follow it.",
			Remediation: "Replace it with a normal git directory or gitdir file.",
		})
		return gitLayout{}
	}
	data, err := readRegular(p, 64*1024)
	if err != nil {
		c.note(".git: " + err.Error())
		return gitLayout{}
	}
	text := strings.TrimSpace(string(data))
	const prefix = "gitdir:"
	if !strings.HasPrefix(strings.ToLower(text), prefix) {
		c.note(".git file does not contain a gitdir pointer")
		return gitLayout{}
	}
	raw := strings.TrimSpace(text[len(prefix):])
	abs := raw
	if !filepath.IsAbs(raw) {
		abs = filepath.Join(root, filepath.FromSlash(raw))
	}
	abs = filepath.Clean(abs)
	c.add(model.Finding{
		ID:          model.IDRepoGitfile,
		Title:       "Checkout uses a gitdir file",
		Severity:    model.Info,
		Category:    "repo",
		Location:    ".git",
		Detail:      "This checkout points its gitdir at " + redactClip(raw) + ". That is normal for a submodule or a linked worktree. Confirm the path is one you expect.",
		Remediation: "If this is not a submodule or linked worktree, inspect the gitdir before running further git commands.",
	})
	st, err = os.Lstat(abs)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		c.note("gitdir path is not a real directory; git commands were skipped")
		return gitLayout{gitFile: true}
	}
	return gitLayout{isRepo: true, gitDir: abs, gitFile: true}
}

func redactClip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

func loadLocalConfig(ctx context.Context, root, gitDir string, c *collector) {
	if gitDir == "" {
		return
	}
	seen := map[string]struct{}{}
	var walk func(abs string, depth int)
	walk = func(abs string, depth int) {
		if depth > 4 {
			c.note("stopped following config includes at depth 4")
			return
		}
		abs = filepath.Clean(abs)
		if _, ok := seen[abs]; ok {
			return
		}
		seen[abs] = struct{}{}
		st, err := os.Lstat(abs)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				c.note(relSlash(root, abs) + ": " + err.Error())
			}
			return
		}
		rel := relSlash(root, abs)
		if !insideRoot(root, abs) {
			rel = abs
		}
		if st.Mode()&os.ModeSymlink != 0 {
			c.add(includeLike(rel, "config file is a symbolic link and was not read"))
			return
		}
		data, err := readRegular(abs, maxRead)
		if err != nil {
			noteRead(c, rel, err)
			return
		}
		file, warnings := gitconfig.Parse(rel, data)
		for _, warning := range warnings {
			c.note(warning)
		}
		findings, includes := analyzeConfig(root, rel, abs, file)
		c.addAll(findings)
		for _, inc := range includes {
			incRel := rel
			stInc, statErr := os.Lstat(inc.abs)
			symlink := statErr == nil && stInc.Mode()&os.ModeSymlink != 0
			c.add(includeFinding(incRel, inc, symlink))
			if symlink || !inc.inside {
				continue
			}
			walk(inc.abs, depth+1)
		}
	}
	walk(filepath.Join(gitDir, "config"), 0)
}

func includeLike(rel, detail string) model.Finding {
	return model.Finding{
		ID:          model.IDImportInclude,
		Title:       "Local config imports another file",
		Severity:    model.Medium,
		Category:    "import",
		Location:    rel,
		Detail:      detail,
		Remediation: "Keep git config as a regular file inside the repository metadata you expect.",
	}
}

func readRootGitmodules(root string, c *collector) {
	path := filepath.Join(root, ".gitmodules")
	data, err := readRegular(path, maxRead)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		noteRead(c, ".gitmodules", err)
		return
	}
	c.consumeGitmodules(".gitmodules", data)
}

func finishSubmodules(c *collector) {
	for i := range c.refs {
		if sha, ok := c.gitlinks[filepath.ToSlash(filepath.Clean(c.refs[i].Path))]; ok {
			c.refs[i].Commit = sha
		}
	}
	declared := map[string]bool{}
	for _, ref := range c.refs {
		if ref.Path == "" || pathEscapes(ref.Path) {
			continue
		}
		declared[filepath.ToSlash(filepath.Clean(ref.Path))] = true
	}
	if c.treeRead {
		for path, sha := range c.gitlinks {
			if declared[path] {
				continue
			}
			c.add(model.Finding{
				ID:          model.IDGitlinkOrphan,
				Title:       "Gitlink without a gitmodules entry",
				Severity:    model.High,
				Category:    "gitlink",
				Location:    path,
				Detail:      "The tree records gitlink " + sha + " at this path, but .gitmodules has no matching path. A recursive clone has no URL to review for it.",
				Remediation: "Add a reviewed URL to .gitmodules or remove the gitlink.",
			})
		}
		for _, ref := range c.refs {
			if ref.Path == "" || pathEscapes(ref.Path) {
				continue
			}
			clean := filepath.ToSlash(filepath.Clean(ref.Path))
			if _, ok := c.gitlinks[clean]; ok {
				continue
			}
			c.add(model.Finding{
				ID:          model.IDSubNoGitlink,
				Title:       "Submodule has no committed gitlink",
				Severity:    model.Low,
				Category:    "submodule",
				Location:    ".gitmodules",
				Detail:      fmt.Sprintf("Submodule %q declares path %q, but that path is not a gitlink in HEAD.", ref.Name, clean),
				Remediation: "Commit the gitlink or remove the unused submodule entry.",
			})
		}
	}
	flagged := map[string]bool{}
	for name, ok := range c.flagged {
		if ok {
			flagged[name] = true
		}
	}
	for _, ref := range c.refs {
		quoted := strconv.Quote(ref.Name)
		for _, finding := range c.findings {
			if finding.Severity == model.Info {
				continue
			}
			if strings.Contains(finding.Detail, quoted) {
				flagged[ref.Name] = true
				break
			}
		}
	}
	for _, finding := range inventoryFindings(".gitmodules", c.refs, flagged) {
		c.add(finding)
	}
}

func readTree(ctx context.Context, root, gitBin string, c *collector) {
	if gitBin == "" {
		gitBin = "git"
	}
	if _, err := exec.LookPath(gitBin); err != nil {
		c.note("git executable not found; index and tree checks were skipped")
		return
	}
	runner, err := safegit.NewRunner(root, gitBin)
	if err != nil {
		c.note(err.Error())
		return
	}
	defer runner.Close()
	if _, err := runner.Run(ctx, "rev-parse", "--verify", "--quiet", "HEAD"); err != nil {
		c.note("repository has no commits; tree checks were skipped")
		return
	}
	out, err := runner.Run(ctx, "ls-tree", "-r", "-z", "HEAD")
	if err != nil {
		c.note("could not list the tree; gitlink checks were skipped")
		return
	}
	c.treeRead = true
	for _, entry := range parseLSTree(out) {
		if len(entry.Path) > maxPathBytes {
			c.add(model.Finding{
				ID:          model.IDPathLong,
				Title:       "Unusually long path",
				Severity:    model.Low,
				Category:    "path",
				Location:    "tree:" + redactClip(entry.Path),
				Detail:      "This tree path is unusually long. Review the tree before a recursive clone.",
				Remediation: "Inspect the path before cloning recursively.",
			})
		}
		switch entry.Mode {
		case "100644", "100755", "120000", "160000":
		default:
			c.add(model.Finding{
				ID:          model.IDModeSpecial,
				Title:       "Tree entry has an unusual mode",
				Severity:    model.Medium,
				Category:    "mode",
				Location:    "tree:" + entry.Path,
				Detail:      "HEAD records mode " + entry.Mode + " for this path.",
				Remediation: "Confirm the mode is intentional before checking the file out.",
			})
		}
		switch entry.Mode {
		case "160000":
			c.gitlinks[filepath.ToSlash(entry.Path)] = entry.Hash
		case "120000":
			blob, err := runner.Run(ctx, "cat-file", "blob", entry.Hash)
			if err != nil || !validHash(entry.Hash) {
				c.note("could not read symlink blob for " + entry.Path)
				continue
			}
			target := string(bytes.TrimRight(blob, "\n"))
			if finding, ok := symlinkFinding(root, filepath.Join(root, filepath.FromSlash(entry.Path)), target, "tree:"+entry.Path); ok {
				c.add(finding)
			}
		}
		if strings.HasSuffix(entry.Path, ".gitattributes") || entry.Path == ".gitattributes" {
			disk := filepath.Join(root, filepath.FromSlash(entry.Path))
			if _, err := os.Lstat(disk); err == nil {
				continue
			}
			if !validHash(entry.Hash) {
				continue
			}
			blob, err := runner.Run(ctx, "cat-file", "blob", entry.Hash)
			if err != nil {
				continue
			}
			for _, finding := range analyzeAttributes(entry.Path, string(blob)) {
				c.add(finding)
			}
		}
	}
}

type treeEntry struct {
	Mode string
	Type string
	Hash string
	Path string
}

func parseLSTree(out []byte) []treeEntry {
	var entries []treeEntry
	for _, rec := range bytes.Split(out, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		tab := bytes.IndexByte(rec, '\t')
		if tab < 0 {
			continue
		}
		meta := strings.Split(string(rec[:tab]), " ")
		if len(meta) != 3 || !validHash(meta[2]) {
			continue
		}
		entries = append(entries, treeEntry{
			Mode: meta[0],
			Type: meta[1],
			Hash: meta[2],
			Path: string(rec[tab+1:]),
		})
	}
	return entries
}

func validHash(s string) bool {
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

func locationPath(location string) string {
	location = strings.TrimPrefix(location, "tree:")
	if i := strings.LastIndex(location, ":"); i > 0 && allDigits(location[i+1:]) {
		return location[:i]
	}
	return location
}

func sortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := findings[i].Severity.Rank(), findings[j].Severity.Rank()
		if ri != rj {
			return ri > rj
		}
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		if findings[i].Location != findings[j].Location {
			return findings[i].Location < findings[j].Location
		}
		return findings[i].Detail < findings[j].Detail
	})
}
