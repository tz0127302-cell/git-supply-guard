# Check catalog

`gsg scan` reads files and git metadata. It does not run hooks, filters, or
submodule commands. Severities are `critical`, `high`, `medium`, `low`, and
`info`. The default fail threshold is `high`.

| ID | Severity | What it means |
| --- | --- | --- |
| GSG-SUB-001 | high | `submodule.recurse` or `fetch.recurseSubmodules` can enter submodules on its own. `on-demand` is medium. |
| GSG-SUB-002 | high | A submodule URL is relative, so a recursive clone resolves it against the superproject remote. |
| GSG-SUB-003 | critical or high | A submodule URL uses a transport helper, a local path, or another protocol outside https and ssh. Cleartext `http` and unauthenticated `git://` are high. A missing URL is high. |
| GSG-SUB-004 | critical | A submodule URL contains a password. The password is not printed. |
| GSG-SUB-005 | critical | `submodule.<name>.update` is a command (`!...`). Git runs it when that submodule is updated. |
| GSG-SUB-006 | high | A submodule `path` is absolute, empty, or escapes the worktree. |
| GSG-SUB-007 | medium | The same submodule name or path is declared twice, or a `.gitmodules` file exists outside the worktree root. |
| GSG-SUB-008 | medium | `ignore = all` hides submodule drift from status. |
| GSG-SUB-009 | low | `update` is `merge` or `rebase`, so an update integrates history instead of checking out the gitlink. |
| GSG-SUB-010 | info | A submodule has no other finding. A recursive clone would still fetch it. |
| GSG-SUB-011 | low | `.gitmodules` declares a path that is not a gitlink in `HEAD`. |
| GSG-HOOK-001 | high | A hook-named script is stored in a committed hook directory such as `hooks/` or `.githooks/`. |
| GSG-HOOK-002 | medium | A Husky entrypoint is stored in the repository. It runs only after hooks are installed. |
| GSG-HOOK-003 | critical | `core.hooksPath` points inside the worktree, so committed scripts become hooks. |
| GSG-HOOK-004 | high | `core.hooksPath` points outside the worktree. |
| GSG-HOOK-005 | medium | A non-sample hook file is installed in `.git/hooks`. |
| GSG-CFG-001 | high | Local config sets `credential.helper`. |
| GSG-CFG-002 | high | `protocol.file.allow` is `always`. |
| GSG-CFG-003 | medium | `fetch.fsckObjects`, `transfer.fsckObjects`, or `receive.fsckObjects` is false. |
| GSG-CFG-004 | high | `safe.directory` is `*`. |
| GSG-CFG-005 | medium to critical | A local `url.<base>.insteadOf` rewrite is present. File and helper targets are critical. |
| GSG-CFG-006 | critical | A filter `smudge`, `clean`, or `process` command is set in local config. |
| GSG-CFG-007 | medium | A local alias shadows `clone`, `fetch`, `checkout`, `merge`, or a related command. |
| GSG-CFG-008 | high or medium | `core.fsmonitor` is a command (high) or `core.sshCommand` is set (medium). |
| GSG-CFG-009 | high | `protocol.allow` or a helper protocol allow-rule is `always`. |
| GSG-CFG-010 | medium | `http.extraHeader` is set. The value is not printed. |
| GSG-ATTR-001 | high | `.gitattributes` assigns a checkout filter other than `lfs`. |
| GSG-ATTR-002 | medium | `export-ignore` covers a security policy, code owners file, workflow, `.gitmodules`, or every path. |
| GSG-ATTR-003 | medium | A `merge=` attribute uses `ours` or another custom driver. |
| GSG-ATTR-004 | low | `.gitattributes` assigns `filter=lfs`. |
| GSG-ATTR-005 | medium | A `diff=` attribute names a custom driver. |
| GSG-LINK-001 | high | A symbolic link points outside the worktree. |
| GSG-LINK-002 | critical | A symbolic link points at git metadata, or a metadata file is not a regular file. The link is not followed. |
| GSG-LINK-003 | critical or medium | `.git` is a symbolic link (critical), or a nested `.git` entry is present (medium). A `.git` symlink is not followed. |
| GSG-MODE-001 | medium | The worktree or tree contains an unusual file mode. |
| GSG-MODE-002 | low | `.gitmodules`, `.gitattributes`, or `.gitconfig` is executable. |
| GSG-GITLINK-001 | high | The tree has a gitlink (mode `160000`) with no matching `.gitmodules` path. |
| GSG-PATH-001 | low | A path is unusually long. Review the tree before a recursive clone. |
| GSG-REF-001 | medium | A remote is a mirror, or its fetch refspec imports `refs/*` or replace refs. |
| GSG-MERGE-001 | high | Local config defines a merge driver command. |
| GSG-PATCH-001 | high | `diff.external`, a diff command, or a textconv command is set. |
| GSG-IMPORT-001 | medium | Local config includes another file. Files outside the worktree, and symbolic links, are not read. |
| GSG-IMPORT-002 | low | A `.gitconfig` file is committed at the worktree root. Git does not load it unless something includes it. |
| GSG-CLONE-001 | medium | A workflow, Makefile, or `scripts/*.sh` file mentions a recursive clone or a recursive submodule update. |
| GSG-REPO-001 | info | The directory has no `.git` directory or gitdir file. File checks still run. |
| GSG-REPO-002 | info | The checkout uses a gitdir file, which is normal for a submodule or a linked worktree. |
| GSG-LIMIT-001 | medium | A file was larger than 2 MiB, or the walk stopped after 50000 entries. |

`gsg clone` refuses transport helpers outright. `http`, `git://`, and local paths need an explicit allow flag. Submodule URLs found after the clone are reported with the IDs above and are not fetched.

`gsg harden` does not use these IDs. Its recommendation IDs are `H-GIT-UPDATE`, `H-CLONE-FLAGS`, `H-UNTRUSTED-INPUT`, `H-SUBMODULE-RECURSE`, `H-FETCH-FSCK`, `H-TRANSFER-FSCK`, `H-RECEIVE-FSCK`, `H-FILE-ALLOW`, `H-REVIEW-CREDENTIAL`, `H-REVIEW-HOOKS`, `H-REVIEW-SAFE`, and `H-REVIEW-FILTERS`.
