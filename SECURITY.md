# Security policy

git-supply-guard is an unofficial defensive audit. It does not replace a
patched Git release.

## Supported use

Scan checkouts you are allowed to read. Use `gsg clone` when you want a
non-recursive clone that does not run hooks or smudge filters. Review the
report before you initialize submodules yourself.

## Reporting a problem in this tool

Open an issue if a scan misses a risky setting, prints a secret, executes a
hook or filter, or fetches a submodule. Include the git version, the command
line, and a redacted copy of the config. Do not send a working reproduction
of a Git project vulnerability, and do not send credentials.

If the report itself contains a secret, redact it before filing the issue and
mention which finding ID printed it.

## Git itself

Install the patched Git release announced by the Git project. This repository
links to that announcement from the README and intentionally does not restate
trigger conditions.
