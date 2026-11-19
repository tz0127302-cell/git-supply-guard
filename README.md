<p align="center">
  <img src="docs/mark.svg" width="96" alt="Shield mark">
</p>

# git-supply-guard

On 10 November 2026 the Git project shipped fixes for six vulnerabilities in recursive clones, reference handling, merges, binary patches, and imports. **git-supply-guard** (`gsg`) audits a checkout for the settings that make those classes of bug matter: submodule URLs, hook paths, smudge filters, and local config. It also clones without recursion, then tells you what a recursive clone would have fetched.

[![CI](https://github.com/tz0127302-cell/git-supply-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/tz0127302-cell/git-supply-guard/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/tz0127302-cell/git-supply-guard/blob/main/LICENSE)

> **Unofficial.** This project is not affiliated with the Git project, GitHub, or any vendor that ships Git. It is not a substitute for installing the patched Git release. Read the [official announcement](https://github.blog/open-source/git/git-security-vulnerabilities-announced-7/) and install Git 2.56.1, or the patched build on your maintenance line: 2.55.1, 2.54.1, 2.53.1, 2.52.1, 2.51.3, or 2.50.2.

## Install

```bash
go install github.com/tz0127302-cell/git-supply-guard/cmd/gsg@latest
```

Or build from a checkout. Clone this repository the same way the tool recommends cloning anything else:

```bash
git clone --no-recurse-submodules https://github.com/tz0127302-cell/git-supply-guard.git
cd git-supply-guard
go build -o gsg ./cmd/gsg
```

The module path is `github.com/tz0127302-cell/git-supply-guard`.

No API keys, network services, or extra daemons are required. `gsg scan` only needs a directory. `gsg clone` needs a local `git` binary.

## 30-second demo

`examples/risky-checkout` is a synthetic checkout. The URLs are not repositories, the hook only echoes a line, and the scan does not run it. The password in the fixture is redacted in the report.

```bash
go run ./cmd/gsg scan ./examples/risky-checkout --no-color
echo "exit: $?"
```

The process exits **1**. The summary line is:

```text
summary    4 critical, 5 high, 5 medium, 0 low, 1 info
threshold  high
result     FAIL
```

The preview lists every submodule a recursive clone would fetch, and does not fetch them:

```text
Submodules a recursive clone would fetch
These URLs were not fetched.
  vendor/left-pad
    path      vendor/left-pad
    url       ../left-pad.git
    protocol  relative
  vendor/ext-demo
    path      vendor/ext-demo
    url       ext::synthetic-transport
    protocol  ext
  vendor/file-demo
    path      ../../outside
    url       file:///tmp/gsg-fixture-not-a-repo
    protocol  file
  vendor/creds
    path      vendor/creds
    url       https://fixture-user:***@example.invalid/demo.git
    protocol  https
```

One of the critical findings:

```text
critical  GSG-SUB-003  Submodule URL uses an unexpected protocol
          .gitmodules:8
          Submodule "vendor/ext-demo" uses the ext transport helper (ext::synthetic-transport). A helper is an external program. This scan did not invoke it.
          fix: Replace the URL with an https or ssh URL you have reviewed. gsg does not invoke transport helpers.
```

The matching clean tree exits **0**:

```bash
go run ./cmd/gsg scan ./examples/clean-checkout --fail-on high
```

JSON goes to stdout and is the only output when you pass `--json`:

```bash
go run ./cmd/gsg scan ./examples/risky-checkout --json --fail-on none
```

## Why this week

A recursive clone does more than download the repository you named. It can initialize submodules, and those submodules carry their own URLs, filters, and hook configuration. Reference updates, merges, binary patches, and import streams have their own hygiene too. The durable fix is a patched Git. Until every laptop and runner is updated, teams still need a way to look at a tree before they trust it.

`gsg` is that look. It reports configuration smells. It does not try to decide whether your `git` binary already contains the fixes, and it does not describe how the bugs are triggered.

## What it checks

| Area | Examples |
| --- | --- |
| Submodules | `submodule.recurse`, relative URLs, unexpected protocols, embedded passwords, `update = !command`, paths that escape the worktree, `ignore = all` |
| Hooks | Tracked hook scripts, Husky entrypoints, `core.hooksPath` inside or outside the worktree, non-sample files in `.git/hooks` |
| Attributes | Custom `filter`, `merge`, and `diff` drivers; `export-ignore` on security policy, workflows, or `.gitmodules`; Git LFS called out separately |
| Symlinks and modes | Links that leave the worktree or point at `.git`; a `.git` symlink (not followed); unusual modes |
| Local config | Credential helpers, `protocol.file.allow=always`, fsck turned off, `safe.directory=*`, URL rewrites, filter and textconv commands, broad fetch refspecs, config includes |
| Automation | Workflows, Makefiles, and `scripts/*.sh` that mention a recursive clone |

The full ID list, with severity and remediation, is [docs/CHECKS.md](docs/CHECKS.md).

## What it does not do

- It does not patch Git, and it does not tell you that your build is safe because the version number is new or old. Maintenance lines were patched too.
- It does not execute hooks, smudge or clean filters, textconv commands, or submodule update commands.
- It does not fetch submodules. `gsg clone` previews the first level of `.gitmodules` and stops.
- It does not scan the network, a forge, or someone else's account.
- It does not include reproduction steps, and the fixtures are synthetic configuration, not a working trigger.
- It is not a complete malware scanner. A clean report means the settings it knows about looked fine.

## Commands

### `gsg scan [path]`

Read-only audit of a git checkout, or of a directory that merely looks like one (`.gitmodules`, `.gitattributes`, hook directories). Default path is `.`. Default fail threshold is `high`.

```bash
gsg scan .
gsg scan ./vendor/lib --fail-on medium --exclude third_party
gsg scan . --json --ignore GSG-SUB-010
```

`--exclude` and `--ignore` are repeatable. In-repo ignore files are not consulted, so a cloned project cannot hide its own findings.

### `gsg clone <url> <dir>`

Clone without submodule recursion, then audit the result.

```bash
gsg clone https://example.invalid/demo.git ./demo
gsg clone --allow-local /path/to/repo.git ./demo
gsg clone --no-checkout git@github.com:org/repo.git ./repo
```

Allowed by default: `https` and `ssh` (including `git@host:path` and `git+ssh`). Refused unless you opt in: `http` (`--allow-http`), `git://` (`--allow-git`), and local paths (`--allow-local`). Transport helpers such as `ext::` are always refused. URLs with an embedded password are refused and the password is not printed.

The clone runs with process-local overrides: hooks point at an empty directory, `submodule.recurse` is false, and checkout clears smudge filters named by `.gitattributes` (including Git LFS). Those overrides are not written into the new repository. A finding at the threshold still leaves the clone on disk so you can inspect it; the process exits 1.

### `gsg harden [path]`

Print safer local settings. The default is a dry-run. `--apply` writes only these keys, and only in the repository's local config:

| Key | Value |
| --- | --- |
| `submodule.recurse` | `false` |
| `fetch.fsckObjects` | `true` |
| `transfer.fsckObjects` | `true` |
| `receive.fsckObjects` | `true` |
| `protocol.file.allow` | `user` |

Credential helpers, `core.hooksPath`, and `safe.directory` are printed for review and are not changed. Global config is not touched.

```bash
gsg harden
gsg harden --apply
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command finished, and no finding met the threshold. |
| 1 | A finding met `--fail-on` (default `high`). |
| 2 | The command was refused or failed: bad flags, missing path, refused URL, or `--apply` outside a repository. |

`--fail-on none` always exits 0 when the command itself succeeded. `--quiet` hides findings below the threshold. `--min-severity` drops findings before the threshold is applied.

## GitHub Action

[action.yml](action.yml) is a composite action. It builds `gsg` from the action's own source, so the job needs Go. The example below tracks `main` on [tz0127302-cell/git-supply-guard](https://github.com/tz0127302-cell/git-supply-guard).

```yaml
permissions:
  contents: read

jobs:
  supply-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
          submodules: false
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
      - uses: tz0127302-cell/git-supply-guard@main
        with:
          path: .
          fail-on: high
          # exclude: examples
          # json: supply-guard.json
```

This repository's own CI scans `.` with `--exclude examples`, expects `examples/risky-checkout` to exit 1, and expects `examples/clean-checkout` to exit 0. The workflow is [.github/workflows/ci.yml](.github/workflows/ci.yml).

## How a run stays read-only

```mermaid
flowchart TD
  start[gsg scan or gsg clone] --> files[Read config, gitmodules, attributes, and the tree]
  files --> guard[Every git command sets an empty hooks path and disables fsmonitor]
  guard --> choice{clone?}
  choice -->|scan| report[Build findings]
  choice -->|clone| fetch[Clone without submodule recursion]
  fetch --> checkout[Checkout with smudge filters unset]
  checkout --> report
  report --> gate{Severity at or above threshold?}
  gate -->|yes| fail[exit 1]
  gate -->|no| pass[exit 0]
```

Includes that point outside the worktree, and symbolic links used as config files, are reported and not opened. `.git` itself is not followed when it is a symbolic link, and git is not invoked in that case.

## Development

```bash
go test ./...
go vet ./...
make demo
```

Go 1.22 or newer. See [CONTRIBUTING.md](CONTRIBUTING.md) for the fixture rules, and [SECURITY.md](SECURITY.md) for reports. Please do not send reproduction steps for the Git vulnerabilities.

## License

[MIT](LICENSE). Copyright 2026 git-supply-guard contributors.
