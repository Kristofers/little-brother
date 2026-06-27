# little-brother

A single bash script, [`whats_up_bigbro.sh`](whats_up_bigbro.sh), that maps what an employer can actually see and do on an Intune/MDM-managed macOS machine.

The script is **read-only**. It reads local status and writes nine files, it changes nothing on the machine. The idea is to upload the result to Claude and get it explained in plain language, plus an assessment of what should be monitored and how a user protects their own secrets.

## Why

On a work machine you rarely know what the employer actually sees. Is it only which domains you browse, or the page content too? Do they read files? Is all traffic tunneled, or only work traffic? This script collects the actual settings so the question can be answered with data instead of guesses.

The philosophy is zero trust with privacy: assume employees are honest, so the company should be able to detect a compromised machine but not snoop on private activity.

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

The script auto-detects which `utun` interface actually carries traffic by looking at the route table, so normally you do not need to set anything. The variables below are optional:

| Variable | Default | What it does |
| --- | --- | --- |
| `GSA_TUN_V4` | `10.10.10.10` | Optional confirmation: a utun matching this address is explicitly flagged as GSA |
| `GSA_TUN_V6` | `fd00::1` | Corresponding IPv6 address |
| `ORG_NAME` | empty | Optional company name to look for among the root CAs in the TLS block |

```bash
# Example: look for a company name among the root CAs
ORG_NAME=acme sudo -E bash whats_up_bigbro.sh
```

## Redaction

The result files leave the machine (you upload them), so by default they are scrubbed of identifiers before you do. Automatically masked: username and home path, computer name and local hostname, hardware serial and UUID, email/UPN addresses, GUIDs (tenant/org/device/profile IDs) and MAC addresses. RFC1918 local IPs are deliberately kept, since masking them would gut the tunnel and route output.

GUIDs are mapped to distinct placeholders (`[GUID-1]`, `[GUID-2]`, ...) consistently across all files, so the same id reads the same everywhere and correlation is preserved without exposing the real value.

What the script can't detect on its own — company name, project/codenames, internal hostnames — you supply as literal terms, either comma-separated in `REDACT` or as command-line arguments (multi-word terms are preserved):

```bash
sudo bash whats_up_bigbro.sh acme "Project Falcon"
# or
REDACT="acme,Project Falcon" sudo -E bash whats_up_bigbro.sh
```

Disable redaction entirely with `REDACT=off`. Redaction is best-effort, not a guarantee, so skim the files before uploading.

## Verifying the redaction

The run ends with two lines on the terminal that let you confirm it worked:

```
==> Masked: 12 emails, 7 distinct GUIDs, 3 MAC addresses, 41 literal-term hits.
==> Verification: no raw emails, GUIDs, MACs or known terms left in the output.
```

The first line shows what was caught (a count of zero where you expected hits is itself a signal — e.g. `0 literal-term hits` means your company name never appeared, or was misspelled in `REDACT`). The second line is a self-check: the script re-scans the masked files for anything that still looks like an email, GUID or MAC, or matches one of your literal terms. If something slipped through it prints `WARNING:` with the `file:line` of each leftover so you can look before uploading.

Beyond the built-in check, spot-check by hand in the audit folder — this is the most reliable way to confirm the things *you* care about are gone. Run these one at a time (avoid trailing `# comments` — interactive zsh on macOS does not treat `#` as a comment and will pass it to the command).

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

Nine files, one per monitoring surface:

1. `01_mde_health` — Microsoft Defender (MDE): real-time protection, cloud/telemetry, sample submission, exclusions, definition freshness, and whether Defender is actually installed and running (app, daemon, launchd service, system extension) independent of the CLI binary.
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
2. **The security posture under zero trust** — what is reasonable, what goes further than necessary, and what is missing to catch a compromised machine or protect IP. Mostly for CISO and infrastructure.
3. **How a user protects private secrets**, with a password manager (e.g. Bitwarden) and private notes (e.g. Apple Notes) as examples, so that Defender, GSA, any TLS inspection and Full Disk Access cannot reach the content. Mostly for users and developers.

## Security and scope

- The script only reads, it writes nothing to the system and does not touch policy, profiles or the keychain.
- The result files can contain sensitive information about your machine and environment. Do not check them in, and consider where you upload them.
- The GSA tunnel is auto-detected via the route table (which utun interface carries traffic), not via hardcoded addresses. macOS exposes no clean mapping from interface to owning process, so routing is the reliable signal. File 7 lists all utun interfaces with address and routes, so the raw data is still there even if the auto-flagging misses.

## License

MIT, see [LICENSE](LICENSE).
