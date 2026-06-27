# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single bash script, `whats_up_bigbro.sh`, that maps what an employer can actually see and do on an Intune-managed macOS machine. The script collects local status, it changes nothing. The output is meant to be uploaded to Claude and explained to a non-technical user. The analysis prompt lives in its own file, `whats_up_prompt.md`, next to the script (edit it there); at runtime the script copies it into the audit folder.

No build, no tests, no dependencies beyond the macOS system tools.

## Principle: no security or privacy by obscurity

The project's intent is open by design. The tool only reads the machine and changes nothing, and the read-only rule is enforced in CI (`tools/readonly-guard.py`), not asserted on trust. Redaction protects the operator's own identifiers before output is shared with a third party; it never hides what the tool collects or does. When editing any file (script, README, prompt, this file), keep intent explicit and inspectable — never add anything that behaves differently from what the docs say.

## Running

```bash
sudo bash whats_up_bigbro.sh
```

`sudo` is required to read the system TCC.db, Managed Preferences and the GSA logs. The script `chown`s the result back to `$SUDO_USER` so the files can be opened without root afterwards.

The result is written to `$AUDIT_ROOT/audit_<TS>/` (default `$HOME/bigbro_audit`, overridable with the `AUDIT_ROOT` environment variable), one subfolder per run (`TS` = `YYYYMMDD_HHMM`). The folder is set to `700`.

## Language

This project is in English: comments, output, the prompt, the instructions, and all docs. Keep it that way. (This overrides the general Swedish-context preference.)

## Structure

The script is linear, one block per output file. Each block is a `{ ... } > "$FILE" 2>&1` group so that all stdout and stderr is captured in the file. The nine files each cover one monitoring surface:

1. `01_mde_health` — Microsoft Defender (MDE): real-time protection, cloud/telemetry, sample submission, exclusions. Uses the `mdatp` binary, looked up in several known paths because it is not always in the sudo PATH. Also checks, independent of the binary, whether Defender is actually installed and running (app, support directory, `wdavdaemon` process, launchd services, system extension), so that "profile deployed but the engine is not running" can be told apart from a pure PATH problem.
2. `02_managed_prefs` — Defender and Global Secure Access policy from `/Library/Managed Preferences/`.
3. `03_full_disk_access` — TCC, both system and user `TCC.db`. Beyond Full Disk Access also the monitoring-sensitive services: screen recording, Accessibility, input monitoring (keystroke logging), camera/microphone, AppleEvents. Note: MDM-forced permissions do not show here, they live in the profile XML (file 5).
4. `04_profiles_summary` — MDM enrollment status (`profiles status -type enrollment`) and Intune profiles, readable summary (`profiles show -all`).
5. `05_profiles_full` — the same profiles as full XML (PPPC/TCC scope).
6. `06_gsa_tunnel` — Global Secure Access: is the client/process/system extension running, are there active utun interfaces, and is the client started and signed in (the user container's logs and `policy.json`).
7. `07_gsa_config_tls` — the decisive GSA block: is the forwarding profile loaded, what is tunneled, does the route table point at the tunnel, and is TLS broken open (looks for a non-Apple root CA suggesting MITM inspection). Dumps the full `policy.json` from the user container and reads both the system and user logs.
8. `08_system_hardening` — SIP, Gatekeeper, FileVault and recovery key escrow to MDM (searched in file 5's XML), firewall, SSH/remote login, remote management/screen sharing, bootstrap token.
9. `09_agents_network` — all system extensions (content filters from any vendor), third-party LaunchDaemons/Agents, PrivilegedHelperTools, running non-Apple services, known EDR/MDM apps, DNS resolver, proxy/PAC, `/etc/hosts`, admin accounts.

## Things to keep in mind when making changes

- The script is read-only against the machine. Do not add anything that changes policy, profiles or the keychain.
- The GSA tunnel is auto-detected in file 7 (Block D) by going through all `utun` interfaces and counting routes whose Netif column points at the interface. An interface with routes beyond its own link is a tunnel that actually carries traffic. macOS has no clean mapping from interface to owning process, so routing is the reliable signal. `GSA_TUN_V4` / `GSA_TUN_V6` are only optional confirmation addresses (they flag a utun as GSA if they match), not the primary detection. No company-specific values are hardcoded.
- Positional arguments are the user's sensitive/organisation terms, collected once into `TERMS`. They are used in two places: the file 7 root-CA grep (to spot a company TLS-inspection CA) and the redaction pass. There is no separate `ORG_NAME` — passing a term as an argument both searches for it and redacts it.
- Under `sudo` `$HOME` is root's directory. The script therefore resolves the real user's home in `USER_HOME` via `dscl` and uses it for user-level paths (TCC in file 3, GSA cache and container in files 6/7) and as the default for `AUDIT_ROOT`. Use `$USER_HOME`, not `$HOME`, for anything touching the logged-in user's files.
- GSA's user container (`~/Library/Containers/com.microsoft.globalsecureaccess/Data/Library/Logs`) holds `policy.json` (the forwarding profile) and the client logs. Pick the latest log via lexical name sorting on the client prefix (`com.microsoft.globalsecureaccess*.log`), not `ls -t`: the file names have ISO dates so name sorting is chronological, and `stat` on the container's files can hang on a cold TCC access without root.
- A step counter is printed to the terminal via stderr (the `step` function), so it stays out of the result files. Keep new terminal status on stderr.
- A redaction pass runs over the result files before `chown` (default on, `REDACT=off` to disable). It scrubs derived host identifiers (username, computer name, local hostname, hardware serial, hardware UUID) plus the user's `TERMS` (the positional arguments, preserved as-is), then masks emails, GUIDs and MAC addresses by regex. Run the regex patterns before the literal terms so tokens like emails redact cleanly to `[EMAIL]` instead of being broken up. It is a single `perl -i` process over `*.txt` and `*.xml` so the GUID map (`%g`) is shared across files: each distinct GUID becomes a distinct `[GUID-N]`, the same GUID maps the same everywhere. `whats_up_prompt.md` is excluded from the glob (and copied in after redaction) so the prompt stays intact. RFC1918 local IPs are intentionally not masked. After the pass, a verification step prints the masked counts and re-scans the output for residual emails/GUIDs/MACs/literal terms, warning with `file:line` of anything left.
- The script header describes what the script does and the surfaces it collects (not a changelog — git holds the history). Keep it in sync when you add or change a surface.
