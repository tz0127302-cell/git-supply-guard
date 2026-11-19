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

type includeRef struct {
	raw    string
	line   int
	abs    string
	inside bool
}

var shadowedAlias = map[string]bool{
	"clone": true, "fetch": true, "pull": true, "submodule": true,
	"checkout": true, "switch": true, "merge": true, "am": true,
	"apply": true, "rebase": true,
}

func analyzeConfig(root, relFile, configAbs string, f *gitconfig.File) (findings []model.Finding, includes []includeRef) {
	if f == nil {
		return nil, nil
	}
	for _, e := range f.Keys {
		where := loc(relFile, e.Line)
		switch {
		case e.Section == "credential" && e.Key == "helper" && strings.TrimSpace(e.Value) != "":
			findings = append(findings, model.Finding{
				ID:          model.IDCfgCredential,
				Title:       "Local credential helper override",
				Severity:    model.High,
				Category:    "config",
				Location:    where,
				Detail:      "Local config sets credential.helper to " + redact.Text(e.Value, 80) + ". A copied .git directory keeps this override. This scan did not run it.",
				Remediation: "Unset the local helper unless you meant to override the user or system helper.",
			})
		case e.Section == "protocol" && e.Subsection == "file" && e.Key == "allow" && strings.EqualFold(e.Value, "always"):
			findings = append(findings, model.Finding{
				ID:          model.IDCfgFileAllow,
				Title:       "File protocol is always allowed",
				Severity:    model.High,
				Category:    "config",
				Location:    where,
				Detail:      "protocol.file.allow is always. Git may honor file URLs from configuration, not only from an explicit clone.",
				Remediation: "Set protocol.file.allow to user, or remove the local override.",
			})
		case e.Section == "protocol" && e.Key == "allow" && strings.EqualFold(e.Value, "always") && (e.Subsection == "" || e.Subsection == "ext" || e.Subsection == "fd"):
			findings = append(findings, model.Finding{
				ID:          model.IDCfgProtocolAny,
				Title:       "Transport helpers are broadly allowed",
				Severity:    model.High,
				Category:    "config",
				Location:    where,
				Detail:      fmt.Sprintf("Local config sets protocol%s.allow to always.", subsectionLabel(e.Subsection)),
				Remediation: "Remove the override so Git keeps its narrower transport defaults.",
			})
		case (e.Section == "fetch" || e.Section == "transfer" || e.Section == "receive") && e.Key == "fsckobjects" && gitconfig.IsFalse(e.Value):
			findings = append(findings, model.Finding{
				ID:          model.IDCfgFsckOff,
				Title:       "Object fsck is disabled",
				Severity:    model.Medium,
				Category:    "config",
				Location:    where,
				Detail:      fmt.Sprintf("%s.fsckObjects is false. Git will not reject malformed objects on that path.", e.Section),
				Remediation: "Set fetch.fsckObjects, transfer.fsckObjects, and receive.fsckObjects to true.",
			})
		case e.Section == "safe" && e.Key == "directory" && strings.TrimSpace(e.Value) == "*":
			findings = append(findings, model.Finding{
				ID:          model.IDCfgSafeStar,
				Title:       "safe.directory disables ownership checks",
				Severity:    model.High,
				Category:    "config",
				Location:    where,
				Detail:      "safe.directory is *. Git will treat every directory as a safe repository for this config.",
				Remediation: "Remove the wildcard and list only repositories you trust.",
			})
		case e.Section == "url" && e.Key == "insteadof":
			findings = append(findings, insteadOfFinding(e, where))
		case e.Section == "filter" && (e.Key == "smudge" || e.Key == "clean" || e.Key == "process") && strings.TrimSpace(e.Value) != "":
			findings = append(findings, model.Finding{
				ID:          model.IDCfgFilter,
				Title:       "Checkout filter command is configured",
				Severity:    model.Critical,
				Category:    "config",
				Location:    where,
				Detail:      fmt.Sprintf("Filter %q sets %s to a command (%s). Git can run it while checking files out. This scan did not run it.", emptyDash(e.Subsection), e.Key, redact.Text(e.Value, 80)),
				Remediation: "Remove the local filter command unless you trust it for every checkout.",
			})
		case e.Section == "diff" && e.Subsection == "" && e.Key == "external" && strings.TrimSpace(e.Value) != "":
			findings = append(findings, patchCommand(where, "diff.external", e.Value))
		case e.Section == "diff" && e.Subsection != "" && (e.Key == "command" || e.Key == "textconv") && strings.TrimSpace(e.Value) != "":
			findings = append(findings, patchCommand(where, "diff."+e.Subsection+"."+e.Key, e.Value))
		case e.Section == "merge" && e.Key == "driver" && strings.TrimSpace(e.Value) != "":
			findings = append(findings, model.Finding{
				ID:          model.IDMergeDriver,
				Title:       "Custom merge driver command",
				Severity:    model.High,
				Category:    "merge",
				Location:    where,
				Detail:      fmt.Sprintf("Merge driver %q is a command (%s). Git runs it when merging matching files. This scan did not run it.", emptyDash(e.Subsection), redact.Text(e.Value, 80)),
				Remediation: "Remove the driver unless you have reviewed how it rewrites merged files.",
			})
		case e.Section == "alias" && shadowedAlias[e.Key]:
			findings = append(findings, model.Finding{
				ID:          model.IDCfgAlias,
				Title:       "Alias shadows a git command",
				Severity:    model.Medium,
				Category:    "config",
				Location:    where,
				Detail:      fmt.Sprintf("Local alias %s is set (%s). It changes what that command does in this repository.", e.Key, redact.Text(e.Value, 80)),
				Remediation: "Review the alias before cloning, fetching, or merging with it.",
			})
		case e.Section == "core" && e.Key == "fsmonitor" && strings.TrimSpace(e.Value) != "" && !gitconfig.IsBool(e.Value):
			findings = append(findings, model.Finding{
				ID:          model.IDCfgCommand,
				Title:       "Filesystem monitor command is configured",
				Severity:    model.High,
				Category:    "config",
				Location:    where,
				Detail:      "core.fsmonitor is a command (" + redact.Text(e.Value, 80) + "). Git can run it during status and checkout. This scan did not run it.",
				Remediation: "Unset the local fsmonitor unless you trust that command.",
			})
		case e.Section == "core" && e.Key == "sshcommand" && strings.TrimSpace(e.Value) != "":
			findings = append(findings, model.Finding{
				ID:          model.IDCfgCommand,
				Title:       "SSH command override",
				Severity:    model.Medium,
				Category:    "config",
				Location:    where,
				Detail:      "core.sshCommand is set (" + redact.Text(e.Value, 80) + "). Git uses it for ssh remotes.",
				Remediation: "Confirm the override is yours before fetching from ssh remotes.",
			})
		case e.Section == "core" && e.Key == "hookspath" && strings.TrimSpace(e.Value) != "":
			if finding, ok := hooksPathFinding(root, e.Value, where); ok {
				findings = append(findings, finding)
			}
		case e.Section == "http" && e.Key == "extraheader" && strings.TrimSpace(e.Value) != "":
			findings = append(findings, model.Finding{
				ID:          model.IDCfgHTTPHeader,
				Title:       "Local config adds an HTTP header",
				Severity:    model.Medium,
				Category:    "config",
				Location:    where,
				Detail:      "http.extraHeader is set in local config. The value was not printed.",
				Remediation: "Remove extra headers from local config unless this repository should send them.",
			})
		case e.Section == "submodule" && e.Subsection == "" && e.Key == "recurse" && gitconfig.IsTrue(e.Value):
			findings = append(findings, model.Finding{
				ID:          model.IDSubRecurse,
				Title:       "Submodule recursion is enabled",
				Severity:    model.High,
				Category:    "submodule",
				Location:    where,
				Detail:      "submodule.recurse is true. Git commands in this repository can fetch submodules without an extra flag.",
				Remediation: "Set submodule.recurse to false and update submodules only after reviewing .gitmodules.",
			})
		case e.Section == "fetch" && e.Key == "recursesubmodules" && (gitconfig.IsTrue(e.Value) || strings.EqualFold(e.Value, "on-demand")):
			sev := model.Medium
			if gitconfig.IsTrue(e.Value) {
				sev = model.High
			}
			findings = append(findings, model.Finding{
				ID:          model.IDSubRecurse,
				Title:       "Fetch recursion is enabled",
				Severity:    sev,
				Category:    "submodule",
				Location:    where,
				Detail:      "fetch.recurseSubmodules is " + strings.ToLower(strings.TrimSpace(e.Value)) + ". Fetch can enter submodules on its own.",
				Remediation: "Set fetch.recurseSubmodules to false.",
			})
		case e.Section == "submodule" && e.Subsection != "" && e.Key == "url":
			info := urlclass.Classify(e.Value)
			findings = append(findings, submoduleURLFindings(e.Subsection, info, where)...)
		case e.Section == "submodule" && e.Subsection != "" && e.Key == "update" && strings.HasPrefix(strings.TrimSpace(e.Value), "!"):
			findings = append(findings, model.Finding{
				ID:          model.IDSubUpdateCmd,
				Title:       "Submodule update runs a configured command",
				Severity:    model.Critical,
				Category:    "submodule",
				Location:    where,
				Detail:      fmt.Sprintf("Local config sets submodule.%s.update to a command (%s). This scan did not run it.", e.Subsection, redact.Clip(e.Value, 80)),
				Remediation: "Set the update mode to checkout unless you have reviewed the command.",
			})
		case e.Section == "remote" && e.Key == "mirror" && gitconfig.IsTrue(e.Value):
			findings = append(findings, model.Finding{
				ID:          model.IDRefBroad,
				Title:       "Remote is configured as a mirror",
				Severity:    model.Medium,
				Category:    "ref",
				Location:    where,
				Detail:      fmt.Sprintf("remote.%s.mirror is true, so fetch imports a broad set of refs.", emptyDash(e.Subsection)),
				Remediation: "Use a normal fetch refspec unless you intend to mirror every ref.",
			})
		case e.Section == "remote" && e.Key == "fetch" && broadRefspec(e.Value):
			findings = append(findings, model.Finding{
				ID:          model.IDRefBroad,
				Title:       "Fetch refspec is broader than branches",
				Severity:    model.Medium,
				Category:    "ref",
				Location:    where,
				Detail:      fmt.Sprintf("remote.%s.fetch is %s. A broad refspec imports more than branch tips.", emptyDash(e.Subsection), redact.Clip(e.Value, 80)),
				Remediation: "Prefer +refs/heads/*:refs/remotes/<name>/* unless you have reviewed the extra refs.",
			})
		case (e.Section == "include" || e.Section == "includeif") && e.Key == "path" && strings.TrimSpace(e.Value) != "":
			abs := resolveInclude(configAbs, e.Value)
			includes = append(includes, includeRef{
				raw:    e.Value,
				line:   e.Line,
				abs:    abs,
				inside: insideRoot(root, abs),
			})
		}
	}
	return findings, includes
}

func subsectionLabel(sub string) string {
	if sub == "" {
		return ""
	}
	return "." + sub
}

func insteadOfFinding(e gitconfig.Entry, where string) model.Finding {
	info := urlclass.Classify(e.Subsection)
	sev := model.Medium
	switch info.SubmoduleSeverity() {
	case "critical":
		sev = model.Critical
	case "high":
		sev = model.High
	}
	if info.Helper || info.Protocol == "file" || info.Local {
		sev = model.Critical
	}
	return model.Finding{
		ID:          model.IDCfgInsteadOf,
		Title:       "Local URL rewrite",
		Severity:    sev,
		Category:    "config",
		Location:    where,
		Detail:      fmt.Sprintf("URLs with prefix %s are rewritten to %s. This changes what fetch and clone contact.", redact.Clip(e.Value, 80), info.Redacted),
		Remediation: "Remove the local insteadOf rule unless you trust that rewrite.",
	}
}

func patchCommand(where, key, value string) model.Finding {
	return model.Finding{
		ID:          model.IDPatchExternal,
		Title:       "External diff or textconv command",
		Severity:    model.High,
		Category:    "patch",
		Location:    where,
		Detail:      key + " is a command (" + redact.Text(value, 80) + "). Git can run it when formatting a diff or patch. This scan did not run it.",
		Remediation: "Unset the command unless you trust it for every diff.",
	}
}

func hooksPathFinding(root, value, where string) (model.Finding, bool) {
	v := strings.TrimSpace(value)
	if v == "" || v == "/dev/null" || v == "NUL" {
		return model.Finding{}, false
	}
	abs := v
	if !filepath.IsAbs(v) {
		abs = filepath.Join(root, filepath.FromSlash(v))
	}
	abs = filepath.Clean(abs)
	if insideRoot(root, abs) {
		return model.Finding{
			ID:          model.IDHookPathInside,
			Title:       "Hooks path points inside the worktree",
			Severity:    model.Critical,
			Category:    "hook",
			Location:    where,
			Detail:      "core.hooksPath is " + redact.Clip(v, 120) + ", which is inside this worktree. Git will run hook scripts stored in the repository. This scan did not run them.",
			Remediation: "Unset core.hooksPath or point it at a directory you review outside the committed tree.",
		}, true
	}
	return model.Finding{
		ID:          model.IDHookPathOutside,
		Title:       "Hooks path points outside the worktree",
		Severity:    model.High,
		Category:    "hook",
		Location:    where,
		Detail:      "core.hooksPath is " + redact.Clip(v, 120) + ", outside this worktree. This scan did not run those hooks.",
		Remediation: "Confirm you trust that directory before the next git command that can run a hook.",
	}, true
}

func resolveInclude(configAbs, raw string) string {
	raw = expandHome(strings.TrimSpace(raw))
	if filepath.IsAbs(raw) {
		return filepath.Clean(raw)
	}
	return filepath.Clean(filepath.Join(filepath.Dir(configAbs), filepath.FromSlash(raw)))
}

func broadRefspec(v string) bool {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "+")
	src, _, _ := strings.Cut(s, ":")
	src = strings.TrimSpace(src)
	return src == "refs/*" || src == "*" || strings.HasPrefix(src, "refs/replace")
}

func includeFinding(relFile string, inc includeRef, symlink bool) model.Finding {
	detail := fmt.Sprintf("Local config includes %s.", redact.Clip(inc.raw, 120))
	if symlink {
		detail = fmt.Sprintf("Local config includes %s, which is a symbolic link. The target was not read.", redact.Clip(inc.raw, 120))
	} else if !inc.inside {
		detail = fmt.Sprintf("Local config includes %s, which is outside this worktree. The file was not read.", redact.Clip(inc.raw, 120))
	} else {
		detail = fmt.Sprintf("Local config includes %s from inside the worktree. Imported settings were audited with the local config.", redact.Clip(inc.raw, 120))
	}
	return model.Finding{
		ID:          model.IDImportInclude,
		Title:       "Local config imports another file",
		Severity:    model.Medium,
		Category:    "import",
		Location:    loc(relFile, inc.line),
		Detail:      detail,
		Remediation: "Keep includes limited to files you trust. Imported config can change helpers, hooks, and filters.",
	}
}
