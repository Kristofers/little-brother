# Contributing to little-brother

Thanks for helping out. This is a small project with one job: `whats_up_bigbro.sh`
collects what an employer can see on a managed Mac, so a person can understand it.
Because the script is run with `sudo` on people's work machines, the bar for trust is
high. There is essentially one rule, and it is non-negotiable.

**No security or privacy by obscurity.** Intent is open here. The code is meant to be
read, the read-only rule is enforced in CI rather than asserted, and nothing should ever
behave differently from what the docs say. Keep every change explicit and inspectable.

## The golden rule: the script is read-only

When the audit runs, it must only **read** the machine. The single exception is the
**result directory** — the script may create and write files there, and nowhere else.

Concretely, the script must never:

- delete, move, rename or truncate files (`rm`, `mv`, `rmdir`, `truncate`, `dd`, ...)
- edit files in place (`sed -i`, `perl -i`, `tee`, `>`/`>>` to anything outside the result dir)
- change permissions or ownership outside the result dir (`chmod`, `chown`, `chflags`)
- change system state or policy (`defaults write`, `profiles install/remove`,
  `csrutil`/`spctl`/`fdesetup` mutations, `launchctl load/unload/...`, `scutil --set`,
  `systemsetup -set...`, `nvram`, `dscl -create/-delete/...`, `security add-/delete-/set-...`)
- run write queries against any database (`sqlite3 ... INSERT/UPDATE/DELETE/DROP/...`)
- make network calls or send data anywhere (`curl`, `wget`, `nc`, `ssh`, `scp`, ...)
- control processes (`kill`, `pkill`, `killall`, `shutdown`, `reboot`)

Writing to the result directory **is** allowed — that is the whole point. The result
directory is named by these variables, and a write is tolerated only when the line
references one of them:

```
AUDIT_ROOT  AUDIT_DIR  PROMPT_FILE
MDE_FILE  MGMT_FILE  TCC_FILE  PROF_FILE  XML_FILE  GSA_FILE  GSA2_FILE  HARD_FILE  AGENT_FILE
```

Most dual-use tools have a read-only mode — use it. For example `defaults read` (not
`write`), `profiles show`/`status` (not `install`), `csrutil status` (not `disable`),
`launchctl list` (not `load`), `dscl . -read`/`-list` (not `-create`), `sqlite3 ... SELECT`
(not `DELETE`). When adding a new collector, prefer the narrowest read-only invocation.

## The automated guard

[`tools/readonly-guard.py`](tools/readonly-guard.py) enforces the rule statically. It
scans the shell source and fails on anything that looks system-mutating, unless the line
targets the result directory. Run it locally before opening a PR:

```bash
python3 tools/readonly-guard.py whats_up_bigbro.sh
```

It runs in CI (the **read-only guard** workflow) on every push and pull request, on both
Linux (static scan + ShellCheck) and macOS (the scan plus a real run that asserts the
script populated only a temporary result directory and touched nothing else).

If the guard flags a line you believe is genuinely safe, the right fix is almost always
to rewrite it so it targets the result directory or uses a read-only subcommand. As a
last resort you can append `# guard:allow` to a reviewed line to suppress it, but expect
reviewers to push back — the justification has to be convincing.

## Local testing

Run it on a real Mac and read the output:

```bash
sudo bash whats_up_bigbro.sh
```

Then confirm the redaction did its job before sharing anything — see the
"Verifying the redaction" section in the [README](README.md). New output should be
scrubbed of identifiers just like the existing files.

## Conventions

- **English only** — comments, output, the prompt, docs. (This overrides the maintainer's
  usual Swedish-context preference; keep it English.)
- **Zero dependencies at runtime** — only bash and the macOS system tools that ship with
  the OS (plus `perl`/`python3`, which are already present). Do not add anything that has
  to be installed on the audited machine. `python3` is fine for dev/CI tooling only.
- **Structure** — the script is linear, one `{ ... } > "$FILE" 2>&1` block per output
  file. Keep that shape. Terminal status goes to **stderr** (the `step` function) so it
  never lands in the result files.
- **User-level paths** — use `$USER_HOME` (resolved via `dscl`), not `$HOME`, for anything
  touching the logged-in user's files; under `sudo`, `$HOME` is root's home.
- Update the version history in the script header for larger changes, and the file list in
  the README / `CLAUDE.md` if you add or rename an output file.

## Pull request checklist

- [ ] `python3 tools/readonly-guard.py whats_up_bigbro.sh` passes
- [ ] `bash -n whats_up_bigbro.sh` passes
- [ ] Ran it on a real Mac and reviewed the new output
- [ ] New collection is read-only and any writes target the result directory
- [ ] Docs updated (README / `CLAUDE.md` / header) if behavior or files changed
- [ ] CI is green
