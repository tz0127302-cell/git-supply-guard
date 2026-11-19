// Package model holds the shared report types for git-supply-guard.
package model

import "strings"

// Severity is the rank of a finding. The empty string is not a valid finding
// severity. Threshold "none" means the process should not fail on findings.
type Severity string

const (
	Info     Severity = "info"
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
	None     Severity = "none"
)

// Rank orders severities. Unknown values rank below info.
func (s Severity) Rank() int {
	switch s {
	case Info:
		return 1
	case Low:
		return 2
	case Medium:
		return 3
	case High:
		return 4
	case Critical:
		return 5
	default:
		return 0
	}
}

// ParseSeverity accepts the severities used by flags, including "none".
func ParseSeverity(raw string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "info":
		return Info, nil
	case "low":
		return Low, nil
	case "medium", "med":
		return Medium, nil
	case "high":
		return High, nil
	case "critical", "crit":
		return Critical, nil
	case "none":
		return None, nil
	default:
		return "", errSeverity(raw)
	}
}

type errSeverity string

func (e errSeverity) Error() string {
	return "unknown severity " + string(e) + " (use info, low, medium, high, critical, or none)"
}

// Finding is one audit result. Detail and Remediation are safe to print:
// callers must redact secrets before constructing a finding.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Location    string   `json:"location"`
	Detail      string   `json:"detail"`
	Remediation string   `json:"remediation"`
}

// Summary counts findings by severity.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// Summarize counts findings.
func Summarize(findings []Finding) Summary {
	var sum Summary
	for _, f := range findings {
		switch f.Severity {
		case Critical:
			sum.Critical++
		case High:
			sum.High++
		case Medium:
			sum.Medium++
		case Low:
			sum.Low++
		case Info:
			sum.Info++
		}
		sum.Total++
	}
	return sum
}

// Fails reports whether any finding meets the threshold. A threshold of none
// or empty never fails.
func Fails(findings []Finding, threshold Severity) bool {
	if threshold == None || threshold == "" {
		return false
	}
	need := threshold.Rank()
	for _, f := range findings {
		if f.Severity.Rank() >= need {
			return true
		}
	}
	return false
}

// FilterSeverity keeps findings at or above min. None keeps everything.
func FilterSeverity(findings []Finding, min Severity) []Finding {
	if min == None || min == "" || min == Info {
		return findings
	}
	out := make([]Finding, 0, len(findings))
	need := min.Rank()
	for _, f := range findings {
		if f.Severity.Rank() >= need {
			out = append(out, f)
		}
	}
	return out
}

// SubmoduleRef is one recorded submodule, whether or not it was fetched.
type SubmoduleRef struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	URL      string `json:"url"`
	Protocol string `json:"protocol"`
	Commit   string `json:"commit,omitempty"`
}

// CloneSection describes a gsg clone that already happened.
type CloneSection struct {
	URL               string `json:"url"`
	Destination       string `json:"destination"`
	CheckedOut        bool   `json:"checkedOut"`
	Recursed          bool   `json:"recursed"`
	FiltersExecuted   bool   `json:"filtersExecuted"`
	HooksExecuted     bool   `json:"hooksExecuted"`
	SubmodulesFetched bool   `json:"submodulesFetched"`
}

// Advice is one harden recommendation.
type Advice struct {
	ID      string `json:"id"`
	Key     string `json:"key,omitempty"`
	Desired string `json:"desired,omitempty"`
	Current string `json:"current,omitempty"`
	Apply   bool   `json:"apply"`
	Applied bool   `json:"applied"`
	Reason  string `json:"reason"`
}

// Report is the stable JSON document printed by every command.
type Report struct {
	Tool            string         `json:"tool"`
	Version         string         `json:"version"`
	Command         string         `json:"command"`
	Target          string         `json:"target,omitempty"`
	GitRepository   bool           `json:"gitRepository"`
	Threshold       string         `json:"threshold,omitempty"`
	Result          string         `json:"result"`
	ExitCode        int            `json:"exitCode"`
	Findings        []Finding      `json:"findings"`
	Summary         Summary        `json:"summary"`
	Notes           []string       `json:"notes,omitempty"`
	Submodules      []SubmoduleRef `json:"submodules,omitempty"`
	Clone           *CloneSection  `json:"clone,omitempty"`
	Recommendations []Advice       `json:"recommendations,omitempty"`
	Error           string         `json:"error,omitempty"`
}
