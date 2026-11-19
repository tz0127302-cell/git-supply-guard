# Contributing

Thanks for helping improve git-supply-guard. The project is a defensive audit
and a safer clone wrapper. It is not a place to publish attack procedures.

## Development

Go 1.22 or newer is required. From a checkout:

```bash
go test ./...
go vet ./...
gofmt -w .
```

`make check` runs formatting, `go vet`, and the tests. `make demo` scans the
synthetic fixture in `examples/risky-checkout`.

## What belongs here

- New checks for risky git settings: submodule URLs, hook paths, filters,
  attributes, symlinks, and local config.
- Tests that use synthetic fixtures. A fixture may contain a fake command
  name, a non-routable URL, or a symbolic link. It must not be a working
  attack, and tests must show that the scanner does not execute it.
- Documentation in `docs/CHECKS.md` for every new finding ID.

## What does not belong here

- Reproduction steps for git vulnerabilities.
- Sample repositories built to trigger a git bug.
- Changes that execute hooks, smudge filters, or submodule commands while
  scanning or cloning.
- Secrets, credentials, or real access tokens.

Use conventional commits (`feat`, `fix`, `docs`, `test`, `refactor`, `chore`).
Keep changes focused. The default fail threshold is `high`; do not weaken it
to hide a finding in this repository.

## Reporting issues

See `SECURITY.md`. Describe the git setting you observed and the finding you
expected. Do not include a working trigger.
