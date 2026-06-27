# little-brother

[![read-only guard](https://github.com/Kristofers/little-brother/actions/workflows/readonly-guard.yml/badge.svg)](https://github.com/Kristofers/little-brother/actions/workflows/readonly-guard.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A single bash script, [`whats_up_bigbro.sh`](whats_up_bigbro.sh), that audits an Intune/MDM-managed macOS machine like a security review and maps what an employer can actually see on it.

It serves two goals, weighted equally:

- **Security.** Like inviting a security expert to look over the managed Mac, it surfaces what is protected, what is monitored, and the gaps to close. The report recommends what should be monitored under zero trust and flags protections that are deployed but not actually running (for example a Defender profile present while the engine is not running). That helps the employer and the security owner, it does not work against them.
- **Privacy.** Keep genuinely personal data — a personal password manager, personal notes — off the work machine, and understand what is visible. Work data and work activity remain the employer's to monitor.

The point is finding the right balance between the two. The script is **read-only**: it reads local status and writes nine files, it changes nothing on the machine. Upload the result to Claude and get back a plain-language report that answers two sets of questions at once, held in balance:

- **For a security owner:** Is what we deployed actually running, or only present as a profile? Is Defender's engine live, is the GSA tunnel carrying traffic, is FileVault escrowed? What is reasonable under zero trust, and what is missing to catch a compromised machine or protect company IP?
- **For an individual:** How do I keep my *personal* data off a work machine, and what can the employer see in the meantime — files, domains, page content? Is everything monitored, or only work traffic?

## Scope and ethics

This is a security-audit and personal-privacy tool, weighted equally toward both. On the security side it helps the employer or security owner see what is protected, what is monitored, and what should be monitored under zero trust, including protections that are deployed but not actually running. It works *for* the security owner, not against them. On the privacy side it helps a person understand what is visible and keep their genuinely *personal* data (a personal password manager, personal notes) off a work machine. It is read-only and changes nothing.

It is explicitly **not** for evading security controls, disabling monitoring, hiding misconduct, or tampering with a managed device — and it cannot do any of those things, because it only reads. Work data and work activity remain the employer's to monitor. The honest-employee premise serves both goals at once: build controls that catch a compromised machine, and respect the person's private life.

## Why

On a work machine you rarely know two things: whether the deployed controls are actually working, and what the employer actually sees. Is the Defender profile that was pushed backed by a running engine? Is all traffic tunneled, or only work traffic? Is TLS being inspected, and is it only which domains get browsed or the page content too? Are files readable? This script collects the actual settings so both can be answered with data instead of guesses, and so each gap can be named and closed.

The philosophy is zero trust with privacy: assume employees are honest, so the company should be able to detect a compromised machine but not monitor private activity. The same honest-employee, detect-the-attacker premise drives both halves of the report — the security gaps the owner should close, and the personal data the individual should keep off the machine.

## Principles — no security or privacy by obscurity

The intent of this tool is fully open, and that is the point. It is a single readable script that only reads the machine and changes nothing, and the read-only rule is **enforced** in CI ([`tools/readonly-guard.py`](tools/readonly-guard.py)), not asserted on trust. Run it, read it, check it.

The redaction exists for one reason: to scrub your **own** identifiers out of the files before you upload them. It never hides what the tool collects or does — every collection step is documented here and visible in the source. Security and privacy come from clear, inspectable policy and code, not from hiding things under the hood.

## Running

```bash
sudo bash whats_up_bigbro.sh
```

`sudo` is required to read the system TCC.db, Managed Preferences and the GSA logs. The script `chown`s the result back to your user, so the files can be opened without root afterwards.

During the run a step counter is printed to the terminal (`[3/9] ...`) with the expected time per step (short/medium/long) and total time at the end, so you can see something is happening. File 7 is the long step. The status goes to stderr and never ends up in the result files.

No dependencies beyond the macOS system tools. No build, no tests.

## Where the result goes

Default: `$HOME/bigbro_audit/audit_<TS>/`, one subfolder per run (`TS` = `YYYYMMDD_HHMM`). The folder is set to `700` so only your user can read it.

The home directory is the deliberate default: the files are easy to find in Finder and stay until you upload them. A tmp directory is not recommended as the default, partly because macOS clears `/private/tmp` periodically and may delete the files before you upload them, partly because they are harder to find. If you still want it ephemeral, point it elsewhere with `AUDIT_ROOT`:

```bash
AUDIT_ROOT=/tmp/bigbro_audit sudo -E bash whats_up_bigbro.sh
```

Wherever they land: the files describe your machine in detail. Delete them once you have uploaded them and are done (`rm -rf <folder>`). `.gitignore` makes sure they never end up in git.

## Configuration

The script auto-detects which `utun` interface actually carries traffic by looking at the route table, so normally you do not need to set anything.

Pass your **organisation/sensitive terms** (company name, project names) as arguments. They are used openly in two places: file 7 searches the system root CAs for them — so both the security owner and the user can see whether a company TLS-inspection CA is in place — and the redaction pass scrubs them from every result file.

```bash
sudo bash whats_up_bigbro.sh acme "Project Falcon"
```

Two optional environment variables exist for edge cases:

| Variable | Default | What it does |
| --- | --- | --- |
| `GSA_TUN_V4` | `10.10.10.10` | Optional confirmation: a utun matching this address is explicitly flagged as GSA |
| `GSA_TUN_V6` | `fd00::1` | Corresponding IPv6 address |

## Redaction

The result files leave the machine when you upload them, so by default they are scrubbed of *your own* identifiers first. This protects the operator before sharing with a third party; it never hides what the tool collects. Automatically masked: username and home path, computer name and local hostname, hardware serial and UUID, email/UPN addresses, GUIDs (tenant/org/device/profile IDs) and MAC addresses. RFC1918 local IPs are deliberately kept, since masking them would gut the tunnel and route output.

GUIDs are mapped to distinct placeholders (`[GUID-1]`, `[GUID-2]`, ...) consistently across all files, so the same id reads the same everywhere and correlation is preserved without exposing the real value.

What the script can't detect on its own — company name, project/codenames, internal hostnames — you supply as arguments (multi-word terms are preserved). These are the same terms file 7 greps for among the root CAs, so you pass them once:

```bash
sudo bash whats_up_bigbro.sh acme "Project Falcon"
```

Disable redaction entirely with `REDACT=off`. Redaction is best-effort, not a guarantee, so skim the files before uploading.

## Verifying the redaction

The run ends with two lines on the terminal that let you confirm it worked:

```
==> Masked: 12 emails, 7 distinct GUIDs, 3 MAC addresses, 41 literal-term hits.
==> Verification: no raw emails, GUIDs, MACs or known terms left in the output.
```

The first line shows what was caught (a count of zero where you expected hits is itself a signal — e.g. `0 literal-term hits` means your company name never appeared, or was misspelled in `REDACT`). The second line is a self-check: the script re-scans the masked files for anything that still looks like an email, GUID or MAC, or matches one of your literal terms. If something slipped through it prints `WARNING:` with the `file:line` of each leftover so you can look before uploading.

Beyond the built-in check, spot-check by hand in the audit folder — this is the most reliable way to confirm the identifiers you care about are gone. Run these one at a time (avoid trailing `# comments` — interactive zsh on macOS does not treat `#` as a comment and will pass it to the command).

Anything that still looks like an email / GUID / MAC:

```bash
cd ~/bigbro_audit/audit_<TS>
grep -rIE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' .
grep -rIE '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}' .
grep -rIE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' .
```

Your own identifiers — these should return nothing:

```bash
grep -rIiF "$(whoami)" .
grep -rIiF "$(scutil --get ComputerName)" .
grep -rIiF 'your-company-name' .
```

Count the placeholders to confirm the masking ran:

```bash
grep -rohE '\[(EMAIL|MAC|REDACTED|GUID-[0-9]+)\]' . | sort | uniq -c
```

Files 06 and 07 (GSA tunnel and config) are the richest in identifiers — account/UPN, tenant and device GUIDs in the logs and `policy.json` — so they are the ones most worth eyeballing. RFC1918 local IPs (192.168.x, 10.x) are intentionally kept, so seeing those is expected, not a leak.

## What is collected

Nine files, one per monitoring surface. Several of them are where the security gaps show up — a profile present but the engine not running, a protection that should be on and is not:

1. `01_mde_health` — Microsoft Defender (MDE): real-time protection, cloud/telemetry, sample submission, exclusions, definition freshness, and whether Defender is actually installed and running (app, daemon, launchd service, system extension) independent of the CLI binary. This is where a deployed-but-inert Defender shows up.
2. `02_managed_prefs` — Defender and Global Secure Access policy from `/Library/Managed Preferences/`.
3. `03_full_disk_access` — TCC, both system and user: Full Disk Access plus the monitoring-sensitive permissions (screen recording, Accessibility, input monitoring, camera/microphone). Note: MDM-forced permissions do not show here but in the profile XML (file 5).
4. `04_profiles_summary` — MDM enrollment status and Intune profiles, readable summary.
5. `05_profiles_full` — the same profiles as full XML (PPPC/TCC scope).
6. `06_gsa_tunnel` — Global Secure Access: is the client/process/system extension running, are there active tunnel interfaces, and is the client started and signed in (the user container's logs and `policy.json`).
7. `07_gsa_config_tls` — the decisive GSA block: dumps the full forwarding profile (`policy.json`), what is tunneled, whether the route table points at the tunnel, reads both the system and user logs, and checks whether TLS is broken open (non-Apple root CA suggesting MITM inspection).
8. `08_system_hardening` — SIP, Gatekeeper, FileVault and recovery key escrow to MDM, firewall, SSH/remote login, remote management/screen sharing, bootstrap token.
9. `09_agents_network` — all system extensions (content filters from any vendor), third-party LaunchDaemons/Agents, PrivilegedHelperTools, running non-Apple services, known EDR/MDM apps, DNS resolver, proxy/PAC, admin accounts.

## Analyzing the result

Upload all nine files to Claude. **Recommended model: Claude Opus 4.8.** The analysis requires the model to read several files at once, weigh them together and make a security assessment in plain language. It is a reasoning-heavy task, not a lookup, and Opus 4.8 is the most capable model for that kind of synthesis and judgment. The large context window takes all the files without trouble.

The prompt lives in [`whats_up_prompt.md`](whats_up_prompt.md) in the repo (edit it there). At runtime the script copies it into the audit folder and points to it at the end of the run. Open it, copy everything, and paste it into Claude together with the nine files. It asks for a factual, neutral report, written impersonally (no "you") and without value-laden phrasing, that works for several roles at once: developers, a tech and IP lead, a CISO and an infrastructure manager. Every conclusion is illustrated with concrete everyday examples so it can be compared against one's own behavior. The report is written in Markdown and may use Mermaid diagrams to show flows, e.g. how traffic is routed or where the boundary of visibility lies. The report covers three parts:

1. **What the employer can see today** and the consequences in practice (files, browsing, work vs private). Mostly for users and developers.
2. **The security posture under zero trust** — what is reasonable, what goes further than necessary, and what is missing to catch a compromised machine or protect IP. This is the gaps-and-fixes part: it flags any protective component that is deployed but not active. Mostly for CISO and infrastructure.
3. **How a user keeps personal data private** — practical advice for keeping genuinely personal data off the monitored surfaces in the first place, with a personal password manager (e.g. Bitwarden) and personal notes (e.g. Apple Notes) as examples, and the simplest option of keeping personal accounts on a personal device instead. This is about a person's own private data, not about hiding work activity, which remains the employer's to monitor. Mostly for users and developers.

## Caveats

- The script only reads, it writes nothing to the system and does not touch policy, profiles or the keychain.
- The result files can contain sensitive information about your machine and environment. Do not check them in, and consider where you upload them.
- The GSA tunnel is auto-detected via the route table (which utun interface carries traffic), not via hardcoded addresses. macOS exposes no clean mapping from interface to owning process, so routing is the reliable signal. File 7 lists all utun interfaces with address and routes, so the raw data is still there even if the auto-flagging misses.

## Contributing

The script is read-only by design and must only ever write to the result directory. That rule is enforced by a static guard ([`tools/readonly-guard.py`](tools/readonly-guard.py)) that runs in CI on every change. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

MIT, see [LICENSE](LICENSE).
