package scan

import (
	"fmt"
	"strings"

	"github.com/tz0127302-cell/git-supply-guard/internal/gitattributes"
	"github.com/tz0127302-cell/git-supply-guard/internal/model"
)

func analyzeAttributes(relFile, text string) []model.Finding {
	var out []model.Finding
	for _, line := range gitattributes.Parse(text) {
		where := loc(relFile, line.Number)
		for _, attr := range line.Attrs {
			switch attr.Key {
			case "filter":
				if attr.State != gitattributes.StateValue || attr.Value == "" {
					continue
				}
				if strings.EqualFold(attr.Value, "lfs") {
					out = append(out, model.Finding{
						ID:          model.IDAttrLFS,
						Title:       "Git LFS filter is configured",
						Severity:    model.Low,
						Category:    "attribute",
						Location:    where,
						Detail:      fmt.Sprintf("Pattern %s sets filter=lfs. Checkout can run the LFS filter. This scan did not run it.", line.Pattern),
						Remediation: "Confirm the installed LFS filter is the official one and not a local command with the same name.",
					})
					continue
				}
				out = append(out, model.Finding{
					ID:          model.IDAttrFilter,
					Title:       "Custom checkout filter",
					Severity:    model.High,
					Category:    "attribute",
					Location:    where,
					Detail:      fmt.Sprintf("Pattern %s sets filter=%s. Checkout runs that filter's smudge or clean command when it is configured. This scan did not run it.", line.Pattern, attr.Value),
					Remediation: "Remove the filter or confirm both the attribute and the filter command.",
				})
			case "export-ignore":
				if attr.State == gitattributes.StateUnset || attr.State == gitattributes.StateUnspecified {
					continue
				}
				if !sensitiveExport(line.Pattern) {
					continue
				}
				out = append(out, model.Finding{
					ID:          model.IDAttrExport,
					Title:       "export-ignore hides a sensitive path",
					Severity:    model.Medium,
					Category:    "attribute",
					Location:    where,
					Detail:      fmt.Sprintf("Pattern %s is export-ignore. git archive can omit that path while a clone still contains it.", line.Pattern),
					Remediation: "Confirm security policy, workflow, and gitmodules files should be omitted from archives.",
				})
			case "merge":
				if attr.State != gitattributes.StateValue {
					continue
				}
				switch strings.ToLower(attr.Value) {
				case "", "text", "binary", "union":
					continue
				}
				title := "Custom merge driver attribute"
				detail := fmt.Sprintf("Pattern %s sets merge=%s. A custom merge driver can rewrite or drop incoming changes.", line.Pattern, attr.Value)
				if strings.EqualFold(attr.Value, "ours") {
					title = "Merge driver keeps the current side"
					detail = fmt.Sprintf("Pattern %s sets merge=ours. Merges can drop incoming changes for matching files.", line.Pattern)
				}
				out = append(out, model.Finding{
					ID:          model.IDAttrMerge,
					Title:       title,
					Severity:    model.Medium,
					Category:    "attribute",
					Location:    where,
					Detail:      detail,
					Remediation: "Remove the merge attribute unless that behavior is intentional.",
				})
			case "diff":
				if attr.State != gitattributes.StateValue {
					continue
				}
				switch strings.ToLower(attr.Value) {
				case "", "text", "binary", "lfs":
					continue
				}
				out = append(out, model.Finding{
					ID:          model.IDAttrDiff,
					Title:       "Custom diff driver attribute",
					Severity:    model.Medium,
					Category:    "attribute",
					Location:    where,
					Detail:      fmt.Sprintf("Pattern %s sets diff=%s. A matching diff driver can run a command when Git formats a patch.", line.Pattern, attr.Value),
					Remediation: "Confirm the diff driver in git config, or remove the attribute.",
				})
			}
		}
	}
	return out
}

func sensitiveExport(pattern string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	if p == "*" || p == "**" || p == "." {
		return true
	}
	for _, needle := range []string{
		"security.md",
		"codeowners",
		".gitmodules",
		".github",
		"code_of_conduct.md",
	} {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}
