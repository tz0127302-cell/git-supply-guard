// Package cli is the gsg command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tz0127302-cell/git-supply-guard/internal/clone"
	"github.com/tz0127302-cell/git-supply-guard/internal/harden"
	"github.com/tz0127302-cell/git-supply-guard/internal/model"
	"github.com/tz0127302-cell/git-supply-guard/internal/report"
	"github.com/tz0127302-cell/git-supply-guard/internal/scan"
	"github.com/tz0127302-cell/git-supply-guard/internal/version"
)

const usage = `git-supply-guard audits clone, submodule, hook, and filter hygiene.

Usage:
  gsg scan [path] [flags]
  gsg clone <url> <dir> [flags]
  gsg harden [path] [flags]
  gsg version

Scan flags:
  --json                 print the report as JSON
  --fail-on <severity>   exit 1 at this severity (default high; use none to never fail)
  --min-severity <sev>   hide findings below this severity (default info)
  --exclude <path>       skip a path prefix; repeat the flag to skip more than one
  --ignore <id>          drop a finding id such as GSG-SUB-010; repeatable
  --quiet                show only findings at or above the fail threshold
  --no-color             disable color

Clone flags:
  --allow-local          permit a filesystem path or file:// URL
  --allow-http           permit cleartext http
  --allow-git            permit the unauthenticated git:// protocol
  --no-checkout          clone metadata only; do not check files out
  Transport helpers (ext::, fd::) are always refused.
  Submodules are not fetched. Hooks and smudge filters are not executed.

Harden flags:
  --apply                write the local safe settings (default is a dry-run)
  --json
  --no-color

Exit codes:
  0  no finding at or above the threshold
  1  a finding met the threshold
  2  the command was refused or failed

gsg is a defensive audit. It is not a substitute for installing the official
Git security updates.
`

// Execute runs one invocation and returns the process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	case "-v", "--version", "version":
		fmt.Fprintf(stdout, "git-supply-guard %s\n", version.Version)
		return 0
	case "scan":
		return cmdScan(args[1:], stdout, stderr)
	case "clone":
		return cmdClone(args[1:], stdout, stderr)
	case "harden":
		return cmdHarden(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

type commonFlags struct {
	json        bool
	noColor     bool
	quiet       bool
	failOn      string
	minSeverity string
	exclude     []string
	ignore      []string
}

func cmdScan(args []string, stdout, stderr io.Writer) int {
	flags, rest, err := parseFlags(args, map[string]bool{
		"--fail-on": true, "--min-severity": true, "--exclude": true, "--ignore": true,
	})
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	if flags.help {
		fmt.Fprint(stdout, usage)
		return 0
	}
	cf, err := commonFrom(flags)
	if err != nil {
		return writeErr(stdout, stderr, cf, "scan", "", err)
	}
	path := "."
	if len(rest) > 0 {
		path = rest[0]
	}
	if len(rest) > 1 {
		return writeErr(stdout, stderr, cf, "scan", path, errors.New("scan accepts one path"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := scan.Scan(ctx, scan.Options{
		Root:      path,
		Exclude:   cf.exclude,
		IgnoreIDs: ignoreSet(cf.ignore),
	})
	if err != nil {
		return writeErr(stdout, stderr, cf, "scan", path, err)
	}
	return emitScan(stdout, stderr, cf, "scan", result, nil)
}

func cmdClone(args []string, stdout, stderr io.Writer) int {
	flags, rest, err := parseFlags(args, map[string]bool{
		"--fail-on": true, "--min-severity": true, "--exclude": true, "--ignore": true,
	})
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	if flags.help {
		fmt.Fprint(stdout, usage)
		return 0
	}
	cf, err := commonFrom(flags)
	if err != nil {
		return writeErr(stdout, stderr, cf, "clone", "", err)
	}
	if len(rest) != 2 {
		return writeErr(stdout, stderr, cf, "clone", "", errors.New("clone requires <url> and <dir>"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cloned, err := clone.Clone(ctx, clone.Request{
		URL:        rest[0],
		Dest:       rest[1],
		AllowHTTP:  flags.bools["--allow-http"],
		AllowGit:   flags.bools["--allow-git"],
		AllowLocal: flags.bools["--allow-local"],
		Checkout:   !flags.bools["--no-checkout"],
	})
	if err != nil {
		var refused *clone.Refusal
		if errors.As(err, &refused) {
			return writeErr(stdout, stderr, cf, "clone", rest[1], err)
		}
		return writeErr(stdout, stderr, cf, "clone", rest[1], err)
	}
	return emitScan(stdout, stderr, cf, "clone", cloned.Scan, &model.CloneSection{
		URL:               rest[0],
		Destination:       cloned.Destination,
		CheckedOut:        cloned.CheckedOut,
		Recursed:          false,
		FiltersExecuted:   false,
		HooksExecuted:     false,
		SubmodulesFetched: false,
	})
}

func cmdHarden(args []string, stdout, stderr io.Writer) int {
	flags, rest, err := parseFlags(args, map[string]bool{})
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	if flags.help {
		fmt.Fprint(stdout, usage)
		return 0
	}
	cf := commonFlags{json: flags.bools["--json"], noColor: flags.bools["--no-color"]}
	path := "."
	if len(rest) > 0 {
		path = rest[0]
	}
	if len(rest) > 1 {
		return writeErr(stdout, stderr, cf, "harden", path, errors.New("harden accepts one path"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	result, err := harden.Run(ctx, harden.Request{Root: path, Apply: flags.bools["--apply"]})
	if err != nil {
		return writeErr(stdout, stderr, cf, "harden", path, err)
	}
	rep := model.Report{
		Tool:            "git-supply-guard",
		Version:         version.Version,
		Command:         "harden",
		Target:          result.Root,
		GitRepository:   result.IsRepo,
		Result:          "pass",
		ExitCode:        0,
		Findings:        []model.Finding{},
		Summary:         model.Summary{},
		Notes:           result.Notes,
		Recommendations: result.Advice,
	}
	writeReport(stdout, cf, rep)
	return 0
}

func emitScan(stdout, stderr io.Writer, cf commonFlags, command string, result *scan.Result, cloned *model.CloneSection) int {
	threshold, _ := model.ParseSeverity(cf.failOn)
	minSev, _ := model.ParseSeverity(cf.minSeverity)
	findings := model.FilterSeverity(result.Findings, minSev)
	fail := model.Fails(findings, threshold)
	code := 0
	status := "pass"
	if fail {
		code = 1
		status = "fail"
	}
	url := ""
	if cloned != nil {
		url = cloned.URL
		cloned.URL = redactURL(url)
	}
	rep := model.Report{
		Tool:          "git-supply-guard",
		Version:       version.Version,
		Command:       command,
		Target:        result.Root,
		GitRepository: result.IsRepo,
		Threshold:     string(threshold),
		Result:        status,
		ExitCode:      code,
		Findings:      findings,
		Summary:       model.Summarize(findings),
		Notes:         result.Notes,
		Submodules:    result.Submodules,
		Clone:         cloned,
	}
	if rep.Findings == nil {
		rep.Findings = []model.Finding{}
	}
	writeReport(stdout, cf, rep)
	_ = stderr
	return code
}

func redactURL(raw string) string {
	// Local import avoided at the top of emit by using the clone refusal path.
	// The scan package already redacts submodule URLs. Redact the clone URL here
	// through a tiny wrapper to avoid printing passwords if a caller bypassed refusal.
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		if at := strings.Index(rest, "@"); at >= 0 && strings.Contains(rest[:at], ":") {
			return raw[:i+3] + rest[:strings.Index(rest[:at], ":")] + ":***@" + rest[at+1:]
		}
	}
	return raw
}

func writeReport(stdout io.Writer, cf commonFlags, rep model.Report) {
	if cf.json {
		_ = report.WriteJSON(stdout, rep)
		return
	}
	report.WriteHuman(stdout, rep, report.ColorEnabled(stdout, cf.noColor))
}

func writeErr(stdout, stderr io.Writer, cf commonFlags, command, target string, err error) int {
	if cf.json {
		_ = report.WriteJSON(stdout, model.Report{
			Tool:     "git-supply-guard",
			Version:  version.Version,
			Command:  command,
			Target:   target,
			Result:   "error",
			ExitCode: 2,
			Findings: []model.Finding{},
			Error:    err.Error(),
		})
		return 2
	}
	fmt.Fprintln(stderr, "error: "+err.Error())
	return 2
}

func ignoreSet(ids []string) map[string]struct{} {
	if len(ids) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id != "" {
			out[id] = struct{}{}
		}
	}
	return out
}

type flagSet struct {
	bools  map[string]bool
	values map[string][]string
	help   bool
}

func commonFrom(flags flagSet) (commonFlags, error) {
	cf := commonFlags{
		json:        flags.bools["--json"],
		noColor:     flags.bools["--no-color"],
		quiet:       flags.bools["--quiet"],
		failOn:      lastOr(flags.values["--fail-on"], "high"),
		minSeverity: lastOr(flags.values["--min-severity"], "info"),
		exclude:     flags.values["--exclude"],
		ignore:      flags.values["--ignore"],
	}
	threshold, err := model.ParseSeverity(cf.failOn)
	if err != nil {
		return cf, err
	}
	minSev, err := model.ParseSeverity(cf.minSeverity)
	if err != nil {
		return cf, err
	}
	if cf.quiet {
		if threshold == model.None || minSev.Rank() < threshold.Rank() {
			if threshold == model.None {
				cf.minSeverity = string(model.High)
			} else {
				cf.minSeverity = string(threshold)
			}
		}
	}
	return cf, nil
}

func lastOr(v []string, fallback string) string {
	if len(v) == 0 {
		return fallback
	}
	return v[len(v)-1]
}

func parseFlags(args []string, valued map[string]bool) (flagSet, []string, error) {
	fs := flagSet{bools: map[string]bool{}, values: map[string][]string{}}
	var pos []string
	boolFlags := map[string]bool{
		"--json": true, "--no-color": true, "--quiet": true, "--apply": true,
		"--allow-local": true, "--allow-http": true, "--allow-git": true,
		"--no-checkout": true, "--help": true, "-h": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if a == "--help" || a == "-h" {
			fs.help = true
			continue
		}
		name, value, hasValue := a, "", false
		if eq := strings.IndexByte(a, '='); eq > 0 && strings.HasPrefix(a, "--") {
			name = a[:eq]
			value = a[eq+1:]
			hasValue = true
		}
		if boolFlags[name] && !hasValue {
			fs.bools[name] = true
			continue
		}
		if valued[name] {
			if !hasValue {
				i++
				if i >= len(args) {
					return fs, nil, fmt.Errorf("missing value for %s", name)
				}
				value = args[i]
			}
			fs.values[name] = append(fs.values[name], value)
			continue
		}
		if strings.HasPrefix(a, "-") {
			return fs, nil, fmt.Errorf("unknown flag %s", a)
		}
		pos = append(pos, a)
	}
	return fs, pos, nil
}
