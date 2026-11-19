package scan

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/tz0127302-cell/git-supply-guard/internal/gitconfig"
	"github.com/tz0127302-cell/git-supply-guard/internal/model"
	"github.com/tz0127302-cell/git-supply-guard/internal/redact"
	"github.com/tz0127302-cell/git-supply-guard/internal/urlclass"
)

type submod struct {
	name   string
	path   string
	url    string
	update string
	ignore string
	line   int
}

func submodulesOf(f *gitconfig.File) (mods []submod, dupNames []int) {
	if f == nil {
		return nil, nil
	}
	index := map[string]int{}
	seenHeader := map[string]bool{}
	current := ""
	for _, e := range f.Keys {
		if e.Section != "submodule" || e.Subsection == "" {
			continue
		}
		if e.Subsection != current {
			current = e.Subsection
			if seenHeader[current] {
				dupNames = append(dupNames, e.Line)
			}
			seenHeader[current] = true
		}
		i, ok := index[e.Subsection]
		if !ok {
			index[e.Subsection] = len(mods)
			mods = append(mods, submod{name: e.Subsection, line: e.Line})
			i = len(mods) - 1
		}
		switch e.Key {
		case "path":
			if mods[i].path == "" {
				mods[i].path = e.Value
				mods[i].line = e.Line
			}
		case "url":
			if mods[i].url == "" {
				mods[i].url = e.Value
				mods[i].line = e.Line
			}
		case "update":
			if mods[i].update == "" {
				mods[i].update = e.Value
			}
		case "ignore":
			if mods[i].ignore == "" {
				mods[i].ignore = e.Value
			}
		}
	}
	return mods, dupNames
}

func analyzeSubmodules(relFile string, f *gitconfig.File) (findings []model.Finding, refs []model.SubmoduleRef, flagged map[string]bool) {
	flagged = map[string]bool{}
	mods, dupLines := submodulesOf(f)
	for _, line := range dupLines {
		findings = append(findings, model.Finding{
			ID:          model.IDSubDuplicate,
			Title:       "Duplicate submodule section",
			Severity:    model.Medium,
			Category:    "submodule",
			Location:    loc(relFile, line),
			Detail:      "The same submodule name is declared more than once. Git keeps one of the blocks and reviewers can miss the other.",
			Remediation: "Keep a single submodule section for each name.",
		})
	}
	paths := map[string]string{}
	for _, m := range mods {
		where := loc(relFile, m.line)
		ref := model.SubmoduleRef{
			Name:     m.name,
			Path:     m.path,
			URL:      redact.URL(m.url),
			Protocol: "missing",
		}
		if m.url != "" {
			info := urlclass.Classify(m.url)
			ref.Protocol = info.Protocol
			ref.URL = info.Redacted
			findings = append(findings, submoduleURLFindings(m.name, info, where)...)
		} else {
			findings = append(findings, model.Finding{
				ID:          model.IDSubProtocol,
				Title:       "Submodule has no URL",
				Severity:    model.High,
				Category:    "submodule",
				Location:    where,
				Detail:      fmt.Sprintf("Submodule %q does not set a URL.", m.name),
				Remediation: "Set an https or ssh URL you have reviewed, or remove the submodule.",
			})
		}
		if strings.TrimSpace(m.path) == "" {
			findings = append(findings, model.Finding{
				ID:          model.IDSubPath,
				Title:       "Submodule has no path",
				Severity:    model.High,
				Category:    "submodule",
				Location:    where,
				Detail:      fmt.Sprintf("Submodule %q does not set path.", m.name),
				Remediation: "Set path to a directory inside the repository.",
			})
		} else if pathEscapes(m.path) {
			findings = append(findings, model.Finding{
				ID:          model.IDSubPath,
				Title:       "Submodule path escapes the repository",
				Severity:    model.High,
				Category:    "submodule",
				Location:    where,
				Detail:      fmt.Sprintf("Submodule %q sets path to %q, which does not stay inside the worktree.", m.name, m.path),
				Remediation: "Use a relative path that stays inside the repository.",
			})
		} else {
			clean := filepath.ToSlash(filepath.Clean(m.path))
			if prev, ok := paths[clean]; ok {
				findings = append(findings, model.Finding{
					ID:          model.IDSubDuplicate,
					Title:       "Duplicate submodule path",
					Severity:    model.Medium,
					Category:    "submodule",
					Location:    where,
					Detail:      fmt.Sprintf("Path %q is used by both %q and %q.", clean, prev, m.name),
					Remediation: "Give each submodule its own path.",
				})
			}
			paths[clean] = m.name
		}
		update := strings.TrimSpace(m.update)
		switch {
		case strings.HasPrefix(update, "!"):
			findings = append(findings, model.Finding{
				ID:          model.IDSubUpdateCmd,
				Title:       "Submodule update runs a configured command",
				Severity:    model.Critical,
				Category:    "submodule",
				Location:    where,
				Detail:      fmt.Sprintf("Submodule %q sets update to a command (%s). Git runs that command when the submodule is updated. This scan did not run it.", m.name, redact.Clip(update, 80)),
				Remediation: "Set update to checkout unless you have reviewed that command.",
			})
		case strings.EqualFold(update, "merge") || strings.EqualFold(update, "rebase"):
			findings = append(findings, model.Finding{
				ID:          model.IDSubUpdateMerge,
				Title:       "Submodule update integrates history",
				Severity:    model.Low,
				Category:    "submodule",
				Location:    where,
				Detail:      fmt.Sprintf("Submodule %q sets update to %s. Updating it integrates commits instead of checking out the recorded gitlink.", m.name, strings.ToLower(update)),
				Remediation: "Prefer update = checkout unless you intend to integrate submodule history.",
			})
		}
		if strings.EqualFold(strings.TrimSpace(m.ignore), "all") {
			findings = append(findings, model.Finding{
				ID:          model.IDSubIgnore,
				Title:       "Submodule changes are ignored",
				Severity:    model.Medium,
				Category:    "submodule",
				Location:    where,
				Detail:      fmt.Sprintf("Submodule %q sets ignore to all, so status can hide drift from the recorded commit.", m.name),
				Remediation: "Remove ignore = all unless hiding that drift is intentional.",
			})
		}
		refs = append(refs, ref)
	}
	for _, finding := range findings {
		for _, m := range mods {
			if strings.Contains(finding.Detail, fmt.Sprintf("%q", m.name)) && finding.Severity != model.Info {
				flagged[m.name] = true
			}
		}
	}
	return findings, refs, flagged
}

func submoduleURLFindings(name string, info urlclass.Info, where string) []model.Finding {
	var out []model.Finding
	if info.Credentials {
		out = append(out, model.Finding{
			ID:          model.IDSubCredentials,
			Title:       "Submodule URL contains credentials",
			Severity:    model.Critical,
			Category:    "submodule",
			Location:    where,
			Detail:      fmt.Sprintf("Submodule %q URL contains a password (%s). The password was not printed.", name, info.Redacted),
			Remediation: "Remove the username and password from the URL and use a credential helper outside the repository.",
		})
	}
	if info.Relative && info.Protocol == "relative" {
		out = append(out, model.Finding{
			ID:          model.IDSubRelative,
			Title:       "Submodule URL is relative",
			Severity:    model.High,
			Category:    "submodule",
			Location:    where,
			Detail:      fmt.Sprintf("Submodule %q uses a relative URL (%s). A recursive clone resolves it against the superproject remote, which can fetch a different repository than a reviewer expects.", name, info.Redacted),
			Remediation: "Use an absolute https or ssh URL you have reviewed.",
		})
		return out
	}
	switch info.SubmoduleSeverity() {
	case "critical":
		out = append(out, model.Finding{
			ID:          model.IDSubProtocol,
			Title:       "Submodule URL uses an unexpected protocol",
			Severity:    model.Critical,
			Category:    "submodule",
			Location:    where,
			Detail:      protocolDetail(name, info),
			Remediation: "Replace the URL with an https or ssh URL you have reviewed. gsg does not invoke transport helpers.",
		})
	case "high":
		out = append(out, model.Finding{
			ID:          model.IDSubProtocol,
			Title:       "Submodule URL uses an unexpected protocol",
			Severity:    model.High,
			Category:    "submodule",
			Location:    where,
			Detail:      protocolDetail(name, info),
			Remediation: "Prefer an https or ssh URL. Cleartext http and unauthenticated git:// URLs are easy to confuse with a trusted remote.",
		})
	}
	return out
}

func protocolDetail(name string, info urlclass.Info) string {
	if info.Helper {
		return fmt.Sprintf("Submodule %q uses the %s transport helper (%s). A helper is an external program. This scan did not invoke it.", name, info.Protocol, info.Redacted)
	}
	if info.Local || info.Protocol == "file" {
		return fmt.Sprintf("Submodule %q uses a local file URL (%s). A recursive clone would read that path.", name, info.Redacted)
	}
	return fmt.Sprintf("Submodule %q uses protocol %s (%s).", name, info.Protocol, info.Redacted)
}

func pathEscapes(p string) bool {
	if strings.TrimSpace(p) == "" {
		return false
	}
	if filepath.IsAbs(p) {
		return true
	}
	slash := filepath.ToSlash(filepath.Clean(p))
	return slash == ".." || strings.HasPrefix(slash, "../")
}

func inventoryFindings(relFile string, refs []model.SubmoduleRef, flagged map[string]bool) []model.Finding {
	var out []model.Finding
	for _, ref := range refs {
		if flagged[ref.Name] {
			continue
		}
		out = append(out, model.Finding{
			ID:          model.IDSubInventory,
			Title:       "Submodule recorded",
			Severity:    model.Info,
			Category:    "submodule",
			Location:    relFile,
			Detail:      fmt.Sprintf("Submodule %q at %s uses %s (%s). No policy problem was found for this entry. A recursive clone would still fetch it.", ref.Name, emptyDash(ref.Path), ref.Protocol, ref.URL),
			Remediation: "Review the URL before running git submodule update.",
		})
	}
	return out
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
