// Package report prints human and JSON audit reports.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tz0127302-cell/git-supply-guard/internal/model"
	"github.com/tz0127302-cell/git-supply-guard/internal/version"
)

const (
	reset = "\033[0m"
	bold  = "\033[1m"
	dim   = "\033[2m"
	red   = "\033[31m"
	bred  = "\033[1;31m"
	yel   = "\033[33m"
	cyn   = "\033[36m"
	grn   = "\033[1;32m"
)

// IsTerminal reports whether w is a character device.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// ColorEnabled is true when the user did not disable color and w is a terminal.
func ColorEnabled(w io.Writer, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	return IsTerminal(w)
}

// WriteJSON writes a stable indented document.
func WriteJSON(w io.Writer, rep model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}

// WriteHuman writes a scan, clone, or harden report.
func WriteHuman(w io.Writer, rep model.Report, color bool) {
	paint := func(code, text string) string {
		if !color || code == "" {
			return text
		}
		return code + text + reset
	}
	fmt.Fprintf(w, "%s %s\n", paint(bold, "git-supply-guard"), version.Version)
	fmt.Fprintf(w, "command    %s\n", rep.Command)
	if rep.Target != "" {
		fmt.Fprintf(w, "target     %s\n", rep.Target)
	}
	if rep.Command == "scan" || rep.Command == "clone" {
		git := "no"
		if rep.GitRepository {
			git = "yes"
		}
		fmt.Fprintf(w, "git        %s\n", git)
		fmt.Fprintf(w, "hooks      not executed\n")
	}
	if rep.Clone != nil {
		fmt.Fprintf(w, "cloned     %s\n", rep.Clone.Destination)
		fmt.Fprintf(w, "recursed   %s\n", noYes(rep.Clone.Recursed))
		fmt.Fprintf(w, "checkout   %s\n", noYes(rep.Clone.CheckedOut))
		fmt.Fprintf(w, "filters    %s\n", executed(rep.Clone.FiltersExecuted))
	}
	if len(rep.Submodules) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, paint(bold, "Submodules a recursive clone would fetch"))
		fmt.Fprintln(w, "These URLs were not fetched.")
		for _, sub := range rep.Submodules {
			fmt.Fprintf(w, "  %s\n", empty(sub.Name))
			fmt.Fprintf(w, "    path      %s\n", empty(sub.Path))
			fmt.Fprintf(w, "    url       %s\n", empty(sub.URL))
			fmt.Fprintf(w, "    protocol  %s\n", empty(sub.Protocol))
			if sub.Commit != "" {
				fmt.Fprintf(w, "    commit    %s\n", short(sub.Commit))
			}
		}
	}
	if len(rep.Findings) == 0 && rep.Command != "harden" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, paint(grn, "No findings."))
	}
	if len(rep.Findings) > 0 {
		fmt.Fprintln(w)
		for _, f := range rep.Findings {
			fmt.Fprintf(w, "%s  %s  %s\n", paint(sevColor(f.Severity), fmt.Sprintf("%-8s", f.Severity)), f.ID, paint(bold, f.Title))
			if f.Location != "" {
				fmt.Fprintf(w, "          %s\n", f.Location)
			}
			fmt.Fprintf(w, "          %s\n", wrap(f.Detail, 10))
			if f.Remediation != "" {
				fmt.Fprintf(w, "          fix: %s\n", wrap(f.Remediation, 15))
			}
			fmt.Fprintln(w)
		}
	}
	if len(rep.Recommendations) > 0 {
		fmt.Fprintln(w, paint(bold, "Recommendations"))
		for _, item := range rep.Recommendations {
			state := "review"
			if item.Apply {
				state = "would set"
				if item.Applied {
					state = "set"
				} else if item.Current == item.Desired && item.Desired != "" {
					state = "already set"
				}
			}
			fmt.Fprintf(w, "  %-12s %s\n", state, item.ID)
			if item.Key != "" {
				line := item.Key
				if item.Desired != "" {
					line += "=" + item.Desired
				}
				if item.Current != "" {
					line += "  current: " + item.Current
				}
				fmt.Fprintf(w, "               %s\n", line)
			}
			fmt.Fprintf(w, "               %s\n", wrap(item.Reason, 15))
		}
		fmt.Fprintln(w)
	}
	if len(rep.Notes) > 0 {
		fmt.Fprintln(w, paint(dim, "Notes"))
		for _, note := range rep.Notes {
			fmt.Fprintf(w, "  %s\n", note)
		}
		fmt.Fprintln(w)
	}
	if rep.Command != "harden" && rep.Error == "" {
		fmt.Fprintf(w, "summary    %d critical, %d high, %d medium, %d low, %d info\n",
			rep.Summary.Critical, rep.Summary.High, rep.Summary.Medium, rep.Summary.Low, rep.Summary.Info)
		if rep.Threshold != "" {
			fmt.Fprintf(w, "threshold  %s\n", rep.Threshold)
		}
		label := strings.ToUpper(rep.Result)
		code := grn
		if rep.Result == "fail" {
			code = bred
		}
		fmt.Fprintf(w, "result     %s\n", paint(code, label))
	}
	if rep.Error != "" {
		fmt.Fprintf(w, "%s\n", paint(bred, rep.Error))
	}
}

func sevColor(s model.Severity) string {
	switch s {
	case model.Critical:
		return bred
	case model.High:
		return red
	case model.Medium:
		return yel
	case model.Low:
		return cyn
	default:
		return dim
	}
}

func noYes(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func executed(v bool) string {
	if v {
		return "executed"
	}
	return "not executed"
}

func empty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func wrap(s string, indent int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	pad := strings.Repeat(" ", indent)
	return strings.ReplaceAll(s, "\n", "\n"+pad)
}
