#!/bin/bash
# whats_up_bigbro.sh — map what an employer can see on an Intune/MDM-managed Mac.
#
# What it does: runs a series of read-only checks and writes the results to a private
# folder, one file per monitoring surface, so a person can upload them to Claude and
# understand, in plain language, what the employer can and cannot see and do. It reads
# the machine only and changes nothing; the result files are redacted of personal
# identifiers before they leave the machine.
#
# Surfaces collected (one file each):
#   01 Microsoft Defender (MDE): protection state, telemetry, exclusions, definition
#      freshness, and whether the engine actually runs (not just the policy).
#   02 Managed Preferences: Defender and Global Secure Access (GSA) policy.
#   03 TCC: Full Disk Access plus screen/input/camera/mic permissions (system + user).
#   04 MDM enrollment status and Intune profiles (readable summary).
#   05 The same profiles as full XML (PPPC/TCC scope).
#   06 GSA tunnel: client/process/extension state, and whether it is signed in.
#   07 GSA forwarding policy (what is tunneled), routes, and a TLS-inspection check.
#   08 System hardening: SIP, Gatekeeper, FileVault + key escrow, firewall, remote
#      access, bootstrap token.
#   09 Other agents and network visibility: system extensions, launchd, DNS/proxy,
#      admin accounts.
#
# Transparency: this script is meant to be read. There are no hidden actions — security
# and privacy here come from clear policy and open, inspectable code, not from obscurity.
# It is read-only by design, and that is enforced in CI (tools/readonly-guard.py), not
# asserted on trust.
#
# Run with: sudo bash whats_up_bigbro.sh [term ...]
#   Root is required (most of what it reads needs it); it fails early otherwise.
#   Positional arguments are sensitive/organisation terms (company name, project names).
#   They are used openly in two places: file 07 searches the system root CAs for them
#   (to spot a company TLS-inspection CA), and the redaction pass scrubs them from every
#   result file. They are the one identifier class the script cannot derive, so with no
#   terms it warns that the company name and codenames stay in cleartext; set
#   ALLOW_NO_TERMS=1 to silence that on a personal machine. Disable redaction with REDACT=off.

# --- Require root ---
# Most of what this audits (system TCC.db, Managed Preferences, GSA logs) is only
# readable as root. Without it the privileged reads fall back to "(could not read ...)"
# and the run finishes with a confident but mostly empty result. Fail early instead.
if [ "$(id -u)" -ne 0 ]; then
  echo "This audit must run as root so it can read the system TCC.db, Managed" >&2
  echo "Preferences and the GSA logs. Re-run with: sudo bash $0 [term ...]" >&2
  exit 1
fi

# --- Configuration (optional) ---
# File 7 auto-detects which utun interface actually carries traffic via the route table,
# so these are normally NOT needed. They are only used as extra confirmation: if a utun
# matches them it is explicitly flagged as GSA. Find yours with: ifconfig | grep -A4 '^utun'
GSA_TUN_V4="${GSA_TUN_V4:-10.10.10.10}"
GSA_TUN_V6="${GSA_TUN_V6:-fd00::1}"

# Sensitive/organisation terms passed as arguments (company name, project names, ...).
# Used openly in two places: the file 07 root-CA grep and the redaction pass. They are
# the one class of identifier the script cannot derive on its own, so omitting them leaves
# the company name, internal domains and codenames in cleartext in the result files.
TERMS=("$@")

# Redaction of the result files is on by default; disable with REDACT=off.
# REDACT only takes on/off — organisation terms are passed as arguments, never via REDACT.
REDACT="${REDACT:-on}"

# With no terms the derived host identifiers, emails, GUIDs and MACs are still scrubbed,
# but the company name, internal domains and project/codenames are not (they cannot be
# derived). Warn loudly before the run; ALLOW_NO_TERMS=1 silences it for a personal
# machine with nothing org-specific to redact.
ALLOW_NO_TERMS="${ALLOW_NO_TERMS:-0}"
if [ "${#TERMS[@]}" -eq 0 ] && [ "$REDACT" != "off" ] && [ "$ALLOW_NO_TERMS" != "1" ]; then
  {
    echo "WARNING: no organisation terms given."
    echo "  Host identifiers, emails, GUIDs and MACs are still redacted, but the company"
    echo "  name, internal domains and project/codenames are NOT — they cannot be derived."
    echo "  They can appear in cleartext in profile names (files 04/05), GSA forwarding"
    echo "  rules (file 07) and root CA subjects (file 07)."
    echo "  Re-run with your terms, e.g.:  sudo bash $0 acme \"Project Falcon\""
    echo "  For a personal machine with nothing org-specific to redact, set ALLOW_NO_TERMS=1."
  } >&2
fi

# The logged-in user's home directory. Under sudo $HOME is often root's directory,
# so the real user's home is resolved via dscl. Used for user-level directories
# (TCC, GSA cache) and as the default for the result folder.
TARGET_USER="${SUDO_USER:-$USER}"
USER_HOME="$(dscl . -read /Users/"$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[ -z "$USER_HOME" ] && USER_HOME="$HOME"

# Where the result goes. Default is the user's home directory (easy to find, stays
# until the files are uploaded and deleted). To use a tmp directory that is cleared
# on reboot: run with AUDIT_ROOT=/tmp/bigbro_audit sudo -E bash whats_up_bigbro.sh
AUDIT_ROOT="${AUDIT_ROOT:-$USER_HOME/bigbro_audit}"
TS="$(date +%Y%m%d_%H%M)"
AUDIT_DIR="$AUDIT_ROOT/audit_$TS"   # one subfolder per run
# Only touch permissions/ownership on what this run creates. If AUDIT_ROOT was pointed at
# an existing directory, do not chmod/chown the operator's tree — only the per-run subdir
# (which we just created) is tightened. The 700 on AUDIT_DIR keeps the files private even
# if the parent is more open. AUDIT_ROOT should be a dedicated or non-existent path.
[ -d "$AUDIT_ROOT" ] && ROOT_PREEXISTED=1 || ROOT_PREEXISTED=0
mkdir -p "$AUDIT_DIR"
chmod 700 "$AUDIT_DIR" 2>/dev/null                                  # only your user can read it
[ "$ROOT_PREEXISTED" -eq 0 ] && chmod 700 "$AUDIT_ROOT" 2>/dev/null

# Find the mdatp binary (not always in the sudo PATH)
MDATP=""
for p in /usr/local/bin/mdatp /opt/microsoft/mdatp/bin/mdatp "$(command -v mdatp 2>/dev/null)"; do
  [ -x "$p" ] && MDATP="$p" && break
done

# Status output to the terminal (stderr, so it never ends up in the result files).
# Expected time per step: short = seconds, medium = up to ~30 s, long = can take minutes.
TOTAL_STEPS=9
SECONDS=0
step() { printf '[%d/%d] %-42s ~%s\n' "$1" "$TOTAL_STEPS" "$2" "$3" >&2; }

echo "==> Collecting audit into $AUDIT_DIR" >&2
echo "    Usually takes 1-3 minutes. File 7 is the long one (it searches the whole home directory)." >&2

# --- File 1: MDE health & sample policy ---
step 1 "Microsoft Defender (MDE) — status & definitions" "medium"
MDE_FILE="$AUDIT_DIR/01_mde_health_$TS.txt"
{
echo "=== MDE HEALTH $(date) ==="
echo "mdatp binary: ${MDATP:-(not found)}"
if [ -n "$MDATP" ]; then
  echo -e "\n### Health overview ###";                              "$MDATP" health
  echo -e "\n### Real-time protection ###";                         "$MDATP" health --field real_time_protection_enabled
  echo -e "\n### Cloud enabled (telemetry to MS) ###";              "$MDATP" health --field cloud_enabled
  echo -e "\n### Passive mode ###";                                 "$MDATP" health --field passive_mode_enabled
  echo -e "\n### Sample submission (uploads file content?) ###";    "$MDATP" health --field cloud_automatic_sample_submission_consent
  echo -e "\n### Tamper protection ###";                            "$MDATP" health --field tamper_protection
  echo -e "\n### Org/tenant id (which SOC) ###";                    "$MDATP" health --field org_id 2>/dev/null
  echo -e "\n### EDR tags ###";                                     "$MDATP" edr tag list 2>/dev/null
  echo -e "\n### Exclusions (NOT scanned) ###";                     "$MDATP" exclusion list 2>/dev/null
  echo -e "\n### Definitions up to date? (old engine = weaker protection) ###"
  echo -n "definitions_status:  "; "$MDATP" health --field definitions_status 2>/dev/null
  echo -n "definitions_updated: "; "$MDATP" health --field definitions_updated 2>/dev/null
  echo -n "definitions_version: "; "$MDATP" health --field definitions_version 2>/dev/null
  echo -n "engine_version:      "; "$MDATP" health --field engine_version 2>/dev/null
  echo -n "app_version:         "; "$MDATP" health --field app_version 2>/dev/null
else
  echo -e "\n(mdatp binary missing in known paths — checking below whether Defender is installed anyway)"
fi

# Independent of the CLI binary: is Defender actually installed and running?
# (If the binary is not found above, these checks decide whether the engine runs anyway.)
echo -e "\n### Is the Defender app installed (independent of the CLI binary)? ###"
ls -ld "/Applications/Microsoft Defender.app" 2>/dev/null \
  || ls -ld "/Applications/Microsoft Defender ATP.app" 2>/dev/null \
  || echo "(no Defender app in /Applications)"
echo -e "\n### Defender support files on disk ###"
ls -la "/Library/Application Support/Microsoft/Defender/" 2>/dev/null \
  || echo "(no /Library/Application Support/Microsoft/Defender directory)"
echo -e "\n### Defender processes running? (wdavdaemon = the engine itself) ###"
pgrep -fl "wdavdaemon|Microsoft Defender" 2>/dev/null \
  || echo "(no Defender processes running)"
echo -e "\n### Defender launchd services registered? ###"
launchctl list 2>/dev/null | grep -iE "wdav|defender" \
  || echo "(no wdav/Defender services in launchctl)"
echo -e "\n### Defender system/network extension active? ###"
systemextensionsctl list 2>/dev/null | grep -iE "wdav|defender" \
  || echo "(no Defender system extension)"
echo -e "\nINTERPRETATION: profile deployed but no app/daemon/process = the EDR"
echo "protection is not actually running, even though the policy exists. App + wdavdaemon running = engine is running."

echo -e "\n=== END ==="
} > "$MDE_FILE" 2>&1

# --- File 2: Managed preferences (wdav + GSA) ---
step 2 "Managed Preferences (Defender + GSA policy)" "medium"
MGMT_FILE="$AUDIT_DIR/02_managed_prefs_$TS.txt"
{
echo "=== MANAGED PREFERENCES $(date) ==="
echo -e "\n### Defender policy (com.microsoft.wdav) ###"
cat "/Library/Managed Preferences/com.microsoft.wdav.plist" 2>/dev/null \
  || echo "(no wdav plist — config lives in a mobileconfig, see file 04)"
echo -e "\n### Global Secure Access policy (com.microsoft.globalsecureaccess) ###"
cat "/Library/Managed Preferences/com.microsoft.globalsecureaccess.plist" 2>/dev/null \
  || echo "(no GSA plist in Managed Preferences)"
echo -e "\n### GSA via defaults read (fallback) ###"
defaults read "/Library/Managed Preferences/com.microsoft.globalsecureaccess" 2>/dev/null \
  || echo "(defaults read returned nothing)"
echo -e "\n### All GSA-related files under /Library ###"
find /Library -iname "*globalsecure*" -maxdepth 4 2>/dev/null
echo -e "\n### All managed preferences files ###"
ls -la "/Library/Managed Preferences/" 2>/dev/null
echo -e "\n=== END ==="
} > "$MGMT_FILE" 2>&1

# --- File 3: TCC / Full Disk Access ---
step 3 "TCC — Full Disk Access, screen, input, camera/mic" "short"
TCC_FILE="$AUDIT_DIR/03_full_disk_access_$TS.txt"
{
echo "=== FULL DISK ACCESS / TCC $(date) ==="
SYS_TCC="/Library/Application Support/com.apple.TCC/TCC.db"
USER_TCC="$USER_HOME/Library/Application Support/com.apple.TCC/TCC.db"
SENS="('kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent','kTCCServicePostEvent','kTCCServiceSystemPolicyAllFiles','kTCCServiceAppleEvents','kTCCServiceCamera','kTCCServiceMicrophone')"

echo -e "\n### Sensitive permissions — system TCC (auth_value 2=allow, 0=deny) ###"
echo "(ScreenCapture=screen recording, Accessibility=read/control everything on screen,"
echo " ListenEvent=keystrokes, PostEvent=synthesize input, AllFiles=full disk,"
echo " AppleEvents=automate other apps, Camera/Microphone=camera/microphone)"
sqlite3 "$SYS_TCC" \
  "SELECT service, client, auth_value FROM access WHERE service IN $SENS ORDER BY service;" 2>/dev/null \
  || echo "(could not read system TCC.db)"

echo -e "\n### Same sensitive permissions — the user's own TCC ###"
echo "(user-granted grants, e.g. an app that was given screen or input access)"
sqlite3 "$USER_TCC" \
  "SELECT service, client, auth_value FROM access WHERE service IN $SENS ORDER BY service;" 2>/dev/null \
  || echo "(no readable user TCC.db: $USER_TCC)"

echo -e "\n### All grants in system TCC (complete picture) ###"
sqlite3 "$SYS_TCC" "SELECT service, client, auth_value FROM access ORDER BY service;" 2>/dev/null

echo -e "\nNOTE: MDM-forced permissions (e.g. Defender FDA) are NOT in TCC.db."
echo "They are pushed via a PPPC profile and show up in the XML dump (file 05)."
echo -e "\n=== END ==="
} > "$TCC_FILE" 2>&1

# --- File 4: Profiles, readable summary ---
step 4 "MDM enrollment + Intune profiles (summary)" "medium"
PROF_FILE="$AUDIT_DIR/04_profiles_summary_$TS.txt"
{
echo "=== INTUNE PROFILES (summary) $(date) ==="
echo -e "### MDM enrollment status (what the machine reports about itself) ###"
profiles status -type enrollment 2>/dev/null || echo "(profiles status returned nothing)"
echo -e "\n### Installed profiles ###"
profiles show -all 2>/dev/null
echo -e "\n=== END ==="
} > "$PROF_FILE" 2>&1

# --- File 5: Profiles, full XML (PPPC/TCC scope) ---
step 5 "Profiles — full XML (PPPC/TCC scope)" "medium"
XML_FILE="$AUDIT_DIR/05_profiles_full_$TS.xml"
profiles show -all -output stdout-xml > "$XML_FILE" 2>&1

# --- File 6: GSA tunnel status (is it running for real right now?) ---
step 6 "Global Secure Access — tunnel, started & signed in?" "medium"
GSA_FILE="$AUDIT_DIR/06_gsa_tunnel_$TS.txt"
{
echo "=== GLOBAL SECURE ACCESS — TUNNEL STATUS $(date) ==="
echo -e "\n### Is the client app installed? ###"
ls -la "/Applications/GlobalSecureAccessClient/Global Secure Access Client.app" 2>/dev/null \
  || ls -la "/Applications/Global Secure Access Client.app" 2>/dev/null \
  || echo "(GSA app not found in /Applications)"
echo -e "\n### Is the process running? ###"
pgrep -fl "Global Secure Access" 2>/dev/null || echo "(no GSA process running)"
echo -e "\n### Network extension activated? ###"
systemextensionsctl list 2>/dev/null | grep -i "microsoft\|globalsecure" \
  || echo "(no MS system extension listed)"
echo -e "\n### Active tunnel interfaces (utun) — look for a routable inet address ###"
ifconfig | grep -A4 "^utun" 2>/dev/null
echo -e "\n### VPN/NC services ###"
scutil --nc list 2>/dev/null
echo -e "\n### Is the client started and signed in? (user container) ###"
echo "(The log directory and policy.json under the user's container are created only"
echo " when the client is started and signed in — if they exist it is in operation.)"
GSA_USER_LOGS="$USER_HOME/Library/Containers/com.microsoft.globalsecureaccess/Data/Library/Logs"
if [ -d "$GSA_USER_LOGS" ]; then
  echo "User container logs exist: $GSA_USER_LOGS"
  # The client log name has an ISO date, so a lexical sort = chronological (avoids the
  # stat hang). Match the prefix so diagnostic files (ifconfig_logs.log etc.) are not picked.
  ULATEST="$(ls -1 "$GSA_USER_LOGS"/com.microsoft.globalsecureaccess*.log 2>/dev/null | sort | tail -1)"
  [ -z "$ULATEST" ] && ULATEST="$(ls -1 "$GSA_USER_LOGS"/*.log 2>/dev/null | sort | tail -1)"
  echo "Latest user log: ${ULATEST:-(no .log)}"
  if [ -f "$GSA_USER_LOGS/policy.json" ]; then
    echo "policy.json exists — forwarding profile fetched, the client is signed in."
  else
    echo "(no policy.json — profile not fetched, the client may not be signed in)"
  fi
  echo "--- sign-in/connection lines (last 30) ---"
  grep -iaE "sign[- ]?in|signed in|logged in|account|authenticat|token|connected|tunnel up|registered|policy applied" \
    "$ULATEST" 2>/dev/null | tail -30 || echo "(no matching lines)"
else
  echo "(no user container log directory for $TARGET_USER — the client is probably not started/signed in)"
fi
echo -e "\n=== END ==="
} > "$GSA_FILE" 2>&1

# --- File 7: GSA forwarding profile, logs, TLS inspection, route table ---
# This is what was missing last time: the tunnel was up but we did not know
# WHETHER it captured anything, WHAT it captured, or whether TLS was broken open.
step 7 "GSA forwarding profile, logs, TLS, routes" "long"
GSA2_FILE="$AUDIT_DIR/07_gsa_config_tls_$TS.txt"
{
echo "=== GSA FORWARDING PROFILE + TLS INSPECTION $(date) ==="

echo -e "\n### A. The forwarding profile — what is actually tunneled? ###"
echo "(GSA caches its forwarding profile locally. Empty/missing = a client with no rules.)"
FP_FOUND=0
for d in \
  "/Library/Application Support/Microsoft/GlobalSecureAccess" \
  "/Library/Application Support/com.microsoft.globalsecureaccess" \
  "$USER_HOME/Library/Group Containers"/*globalsecure* \
  "$USER_HOME/Library/Application Support/Microsoft/GlobalSecureAccess" \
  "$USER_HOME/Library/Containers/com.microsoft.globalsecureaccess/Data/Library/Logs"; do
  if [ -d "$d" ]; then
    FP_FOUND=1
    echo "--- $d ---"
    find "$d" -type f \( -iname "*profile*" -o -iname "*forward*" -o -iname "*.json" -o -iname "*policy*" \) 2>/dev/null
  fi
done
[ "$FP_FOUND" -eq 0 ] && echo "(no local GSA support directory found)"

echo -e "\n### A2. The full GSA policy (policy.json) — the definitive list of what is tunneled ###"
GSA_POLICY="$USER_HOME/Library/Containers/com.microsoft.globalsecureaccess/Data/Library/Logs/policy.json"
if [ -f "$GSA_POLICY" ]; then
  echo "--- $GSA_POLICY ---"
  /usr/bin/python3 -m json.tool "$GSA_POLICY" 2>/dev/null || cat "$GSA_POLICY" 2>/dev/null
else
  echo "(no policy.json — the client may not be started/signed in, see file 06)"
fi

echo -e "\n### B. Contents of any profile/policy JSON (the rules that steer traffic) ###"
find /Library "$USER_HOME/Library" -ipath "*globalsecure*" -type f \
     \( -iname "*.json" -o -iname "*profile*" -o -iname "*policy*" \) 2>/dev/null \
  | while read -r f; do
      echo "--- $f ---"
      # Pull out the lines that reveal which channels/rules are on
      grep -iE "rule|fqdn|ipRange|port|protocol|action|channel|m365|internet|private|bypass|enabled" "$f" 2>/dev/null | head -60
      echo ""
    done

echo -e "\n### C. GSA logs — was the forwarding profile loaded, or did it error? ###"
for LOGDIR in \
  "/Library/Logs/Microsoft/globalsecureaccessclient" \
  "$USER_HOME/Library/Containers/com.microsoft.globalsecureaccess/Data/Library/Logs"; do
  if [ -d "$LOGDIR" ]; then
    echo "--- log directory: $LOGDIR ---"
    # The client log name has an ISO date, lexical sort = chronological (avoids the
    # stat hang). Prefix match so diagnostic files are not picked; fallback to all .log.
    LATEST="$(ls -1 "$LOGDIR"/com.microsoft.globalsecureaccess*.log 2>/dev/null | sort | tail -1)"
    [ -z "$LATEST" ] && LATEST="$(ls -1 "$LOGDIR"/*.log 2>/dev/null | sort | tail -1)"
    echo "Latest log: ${LATEST:-(no .log)}"
    echo "--- profile/policy/channel/error lines (last 80) ---"
    grep -iaE "forwarding|profile|policy|channel|tenant|enroll|error|fail|denied|fetch|download" \
      "$LATEST" 2>/dev/null | tail -80
  else
    echo "(no log directory: $LOGDIR)"
  fi
done

echo -e "\n### D. Which utun interfaces actually carry traffic? (auto-detection) ###"
echo "(All utun interfaces are listed with address and number of routes pointing to them."
echo " An interface with routes beyond its own link = a tunnel that really captures traffic,"
echo " and it is found without knowing the address in advance. GSA_TUN_* is only used"
echo " as extra confirmation if the address happens to match.)"
UTUNS="$(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^utun')"
[ -z "$UTUNS" ] && echo "(no utun interfaces at all)"
printf '%s\n' "$UTUNS" | while read -r u; do
  [ -z "$u" ] && continue
  echo "--- $u ---"
  ADDRS="$(ifconfig "$u" 2>/dev/null | grep -E 'inet |inet6 ' | grep -v 'inet6 fe80')"
  if [ -n "$ADDRS" ]; then
    printf '%s\n' "$ADDRS" | sed 's/^[[:space:]]*/  /'
  else
    echo "  (only link-local / no routable address)"
  fi
  printf '%s\n' "$ADDRS" | grep -qE "inet ${GSA_TUN_V4}( |$)|inet6 ${GSA_TUN_V6}( |$)" \
    && echo "  >> matches the configured GSA address ($GSA_TUN_V4 / $GSA_TUN_V6)"
  # Routes whose Netif column is exactly this interface (tolerates Expire column present/absent).
  # For IPv6, macOS installs a link-local default (default via fe80::%utunN), the interface's own
  # fe80::/64 link route and the multicast routes (ff00::/8, ff01::, ff02::) on EVERY utun, including
  # the idle system-reserved ones that carry no traffic. Those are not "routes beyond the link", so
  # exclude any route with a link-local/multicast field — otherwise every idle utun looks like a tunnel.
  R4="$(netstat -rn -f inet  2>/dev/null | awk -v ifc="$u" '{for(i=1;i<=NF;i++) if($i==ifc){print;break}}')"
  R6="$(netstat -rn -f inet6 2>/dev/null | awk -v ifc="$u" '
    { hit=0; noise=0
      for(i=1;i<=NF;i++){ if($i==ifc) hit=1; if($i ~ /^fe80/ || $i ~ /^ff0[0-9]/) noise=1 }
      if(hit && !noise) print }')"
  N4="$(printf '%s' "$R4" | grep -c .)"
  N6="$(printf '%s' "$R6" | grep -c .)"
  echo "  routes via $u: $N4 IPv4, $N6 IPv6 (link-local/multicast excluded)"
  [ "$N4" -gt 0 ] && printf '%s\n' "$R4" | head -20 | sed 's/^/    /'
  [ "$N6" -gt 0 ] && printf '%s\n' "$R6" | head -20 | sed 's/^/    /'
  netstat -rn -f inet  2>/dev/null | awk -v ifc="$u" '$1=="default"{for(i=1;i<=NF;i++) if($i==ifc){print "  *** default route (IPv4) goes through "ifc" — full tunnel ***";break}}'
  # Only a default route whose gateway is the interface itself (not a fe80 link-local gateway) is a
  # real full tunnel; the link-local default macOS puts on every utun is not.
  netstat -rn -f inet6 2>/dev/null | awk -v ifc="$u" '
    $1=="default"{ hit=0; ll=0
      for(i=1;i<=NF;i++){ if($i==ifc) hit=1; if($i ~ /^fe80/) ll=1 }
      if(hit && !ll) print "  *** default route (IPv6) goes through "ifc" — full tunnel ***" }'
done
echo "--- default route overall (where does normal outbound traffic go?) ---"
netstat -rn -f inet 2>/dev/null | awk '$1=="default"{print}'

echo -e "\n### E. TLS inspection — is the encryption broken open? ###"
echo "(Decides whether only the domain is visible, or page content too. Looks for"
echo " a non-Apple root CA in the system keychain — a MITM cert stands out.)"
# Two independent searches over the same dump: a fixed ERE of known inspection markers
# (this can never fail to compile), plus a separate fixed-string pass for the operator's
# org terms. The terms are NOT spliced into the regex: a term with regex metacharacters
# (e.g. "Acme (EU)") would otherwise make grep error out and the "|| echo" fallback would
# then report a false all-clear, masking a real MITM CA.
TLS_PAT="microsoft|secure access|proxy|inspect|tls"
TRUST_DUMP="$(security dump-trust-settings -d 2>/dev/null)"
{
  printf '%s\n' "$TRUST_DUMP" | grep -iE "$TLS_PAT"
  for t in "${TERMS[@]}"; do [ -n "$t" ] && printf '%s\n' "$TRUST_DUMP" | grep -iF -- "$t"; done
} | sort -u | grep . \
  || echo "(no obvious inspection CA in admin trust)"
echo "--- All non-Apple root CAs (review whether any looks like a proxy/MITM CA) ---"
security find-certificate -a -p /Library/Keychains/System.keychain 2>/dev/null \
  | openssl x509 -noout -subject 2>/dev/null \
  | grep -ivE "Apple|com.apple" | head -40
echo ""
echo "INTERPRETATION: GSA normally does NOT do TLS inspection (it is a network-level"
echo "SSE proxy, not a TLS-breaking gateway). If a company- or Microsoft-issued root CA"
echo "shows up above that does not belong to device/wifi auth, THEN page content can be"
echo "read. Otherwise: domain-level logging, not content."

echo -e "\n=== END ==="
} > "$GSA2_FILE" 2>&1

# --- File 8: System hardening & integrity ---
step 8 "System hardening (SIP, Gatekeeper, FileVault, remote)" "medium"
HARD_FILE="$AUDIT_DIR/08_system_hardening_$TS.txt"
{
echo "=== SYSTEM HARDENING & INTEGRITY $(date) ==="

echo -e "\n### System Integrity Protection (SIP) ###"
csrutil status 2>/dev/null || echo "(csrutil not available)"

echo -e "\n### Gatekeeper (app signing requirement) ###"
spctl --status 2>/dev/null || echo "(spctl not available)"

echo -e "\n### FileVault (disk encryption) ###"
fdesetup status 2>/dev/null || echo "(fdesetup not available)"
echo "--- Recovery key escrow to MDM? (searched in the profile XML, file 05) ---"
grep -iE "FDERecoveryKeyEscrow|EscrowKeysToServer|RecoveryKey" "$XML_FILE" 2>/dev/null | head -10 \
  || echo "(no escrow key reference in the profiles)"

echo -e "\n### Firewall (application firewall) ###"
FW=/usr/libexec/ApplicationFirewall/socketfilterfw
"$FW" --getglobalstate 2>/dev/null
"$FW" --getstealthmode 2>/dev/null
"$FW" --getblockall 2>/dev/null

echo -e "\n### SSH / remote login ###"
systemsetup -getremotelogin 2>/dev/null || echo "(could not read remote login)"

echo -e "\n### Remote management (ARD) / screen sharing ###"
echo "(The first column is the PID: a number = the service is running, '-' = only registered."
echo " These agents exist on every Mac; a number on RemoteManagement means it is running.)"
launchctl list 2>/dev/null | grep -iE "screensharing|remotemanagement|RemoteDesktop|ARDAgent" \
  || echo "(no screen-sharing/ARD services in launchctl)"
ls -la "/Library/Application Support/Apple/Remote Desktop/" 2>/dev/null

echo -e "\n### Bootstrap token escrowed to MDM? ###"
profiles status -type bootstraptoken 2>/dev/null || echo "(could not read bootstrap token status)"

echo -e "\nINTERPRETATION: SIP + Gatekeeper on and FileVault on is baseline hardening. Escrow of"
echo "the FileVault key and the bootstrap token means MDM can unlock, recover and run MDM"
echo "commands. SSH or screen sharing on are entry paths for remote access."
echo -e "\n=== END ==="
} > "$HARD_FILE" 2>&1

# --- File 9: Other agents & network visibility ---
step 9 "Agents, system extensions, DNS/proxy, accounts" "medium"
AGENT_FILE="$AUDIT_DIR/09_agents_network_$TS.txt"
{
echo "=== OTHER AGENTS & NETWORK VISIBILITY $(date) ==="

echo -e "\n### All system extensions (content filter/network from any vendor) ###"
echo "(A content-filter or network extension can see or filter traffic.)"
systemextensionsctl list 2>/dev/null || echo "(no system extensions)"

echo -e "\n### Third-party LaunchDaemons (/Library, i.e. not Apple-shipped) ###"
ls -1 /Library/LaunchDaemons/ 2>/dev/null || echo "(none)"
echo -e "\n### Third-party LaunchAgents (/Library) ###"
ls -1 /Library/LaunchAgents/ 2>/dev/null || echo "(none)"
echo -e "\n### PrivilegedHelperTools (helper tools that run as root) ###"
ls -la /Library/PrivilegedHelperTools/ 2>/dev/null || echo "(none)"

echo -e "\n### Loaded non-Apple launchd services (running agents) ###"
launchctl list 2>/dev/null | grep -ivE "com\.apple|^PID" | head -60 \
  || echo "(no non-Apple services)"

echo -e "\n### Known management/security apps in /Applications ###"
# Match app names against the known-vendor pattern via a glob loop (not ls | grep), so
# names with spaces are handled cleanly. nocasematch gives the case-insensitive match.
KNOWN_APPS="defender|intune|company portal|global secure|jamf|kandji|mosyle|crowdstrike|sentinelone|carbon black|cisco|umbrella|zscaler|netskope|cortex|tanium|qualys|nessus"
shopt -s nullglob nocasematch
KNOWN_FOUND=0
for app in /Applications/*; do
  name="${app##*/}"
  if [[ "$name" =~ $KNOWN_APPS ]]; then echo "$name"; KNOWN_FOUND=1; fi
done
shopt -u nullglob nocasematch
[ "$KNOWN_FOUND" -eq 0 ] && echo "(no known EDR/MDM apps in /Applications)"

echo -e "\n### DNS resolver (corporate resolver = domain visibility even without a tunnel) ###"
scutil --dns 2>/dev/null | grep -iE "nameserver|search domain|domain " | head -30 \
  || echo "(could not read DNS config)"

echo -e "\n### Proxy / PAC (system proxy = domain visibility for all traffic) ###"
scutil --proxy 2>/dev/null

echo -e "\n### /etc/hosts (custom redirects?) ###"
grep -vE "^#|^$" /etc/hosts 2>/dev/null | grep -vE "127\.0\.0\.1|::1|broadcasthost" \
  || echo "(no extra hosts entries)"
echo -e "\n### Custom DNS resolvers (/etc/resolver) ###"
ls -la /etc/resolver/ 2>/dev/null || echo "(no /etc/resolver)"

echo -e "\n### Admin accounts ###"
dscl . -read /Groups/admin GroupMembership 2>/dev/null
echo "--- All local user accounts (non-system) ---"
dscl . -list /Users 2>/dev/null | grep -vE "^_|^daemon$|^nobody$|^root$"

echo -e "\nINTERPRETATION: a content-filter extension or a system proxy/corporate resolver"
echo "gives domain visibility (which sites are visited) even without a GSA tunnel. Unknown"
echo "root agents or extra admin accounts are worth reviewing."
echo -e "\n=== END ==="
} > "$AGENT_FILE" 2>&1

# --- Redaction: scrub identifiers before the files leave the machine ---
if [ "$REDACT" != "off" ]; then
  CNAME="$(scutil --get ComputerName 2>/dev/null)"
  LHOST="$(scutil --get LocalHostName 2>/dev/null)"
  HWINFO="$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null)"
  SERIAL="$(printf '%s' "$HWINFO" | awk -F'"' '/IOPlatformSerialNumber/{print $4}')"
  HWUUID="$(printf '%s' "$HWINFO" | awk -F'"' '/IOPlatformUUID/{print $4}')"
  # The user's full name (the display-name form that shows up in GSA logs/policy.json and
  # is neither email-shaped nor derivable from the short username).
  REALNAME="$(dscl . -read /Users/"$TARGET_USER" RealName 2>/dev/null \
    | sed 's/^RealName: *//' | tr '\n' ' ' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  # Two literal-term lists. BOUNDED = auto-derived host identifiers, matched with word
  # boundaries so a short/generic name (a 2-3 char username, a ComputerName like "Air") does
  # not substring-mask unrelated text or the [GUID-N]/[MAC] placeholders. GREEDY = the long,
  # specific derived ids + the operator's own terms, matched as substrings by intent (a
  # company name should also match inside compound tokens). The placeholder words are dropped
  # from GREEDY so a term can never eat a placeholder. Trim, drop empties, dedupe.
  LIT_BOUNDED="$(
    printf '%s\n' "$TARGET_USER" "$REALNAME" "$CNAME" "$LHOST" \
      | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; /^$/d' | sort -u
  )"
  LIT_GREEDY="$(
    printf '%s\n' "$SERIAL" "$HWUUID" "${TERMS[@]}" \
      | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; /^$/d' \
      | grep -viE '^(GUID|EMAIL|MAC|JWT|REDACTED)$' | sort -u
  )"
  export LIT_BOUNDED LIT_GREEDY
  # One perl process over all files so the GUID map is shared: the same GUID becomes the same
  # [GUID-N] everywhere (cross-file correlation preserved), distinct GUIDs get distinct numbers.
  # The %g hash persists across files within the one process. Structured tokens are masked first
  # (so an email/JWT redacts whole before any literal term touches it), then the literal terms.
  perl -i -pe '
    BEGIN {
      @bnd = grep { length } split /\n/, $ENV{LIT_BOUNDED};
      @grd = grep { length } split /\n/, $ENV{LIT_GREEDY};
    }
    s/[A-Za-z0-9._%+-]+\@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/[EMAIL]/g;
    s/\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+/[JWT]/g;
    # GUIDs: dashed 8-4-4-4-12, underscore-separated (Intune SCEP ModelName/LogicalName) and
    # compact 32-hex all map into the SAME table (separators stripped in the key) so the same id
    # shares one [GUID-N] across forms and files. The dashed/underscore patterns guard with hex
    # lookarounds instead of \b: \b fails when the id is glued to a word char (e.g. AC_1de7ad45-…
    # or LogicalName_31bda227_…), which let those SCEP ids leak through unmasked.
    s/(?<![0-9a-fA-F-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9a-fA-F-])/ (my $k = lc $&) =~ s|-||g; $g{$k} ||= "[GUID-".(++$gc)."]" /ge;
    s/(?<![0-9a-fA-F])[0-9a-fA-F]{8}_[0-9a-fA-F]{4}_[0-9a-fA-F]{4}_[0-9a-fA-F]{4}_[0-9a-fA-F]{12}(?![0-9a-fA-F])/ (my $k = lc $&) =~ s|_||g; $g{$k} ||= "[GUID-".(++$gc)."]" /ge;
    s/\b[0-9a-fA-F]{32}\b/ $g{lc $&} ||= "[GUID-".(++$gc)."]" /ge;
    s/\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b/[MAC]/g;
    for my $t (@bnd) { s/\b\Q$t\E\b/[REDACTED]/gi; }
    for my $t (@grd) { s/\Q$t\E/[REDACTED]/gi; }
  ' "$AUDIT_DIR"/*.txt "$AUDIT_DIR"/*.xml 2>/dev/null
  echo "==> Redacted username, full name, hostname, serial, hardware UUID, emails, JWTs, GUIDs and MAC addresses." >&2
  [ -z "$SERIAL" ] && echo "==> Note: hardware serial lookup returned empty — any serial in the logs is not masked." >&2
  [ -z "$HWUUID" ] && echo "==> Note: hardware UUID lookup returned empty — not masked." >&2

  # Verification: report what was masked, then scan for anything that still looks
  # like an identifier (pattern miss) or a known literal term (a file the pass missed).
  ME="$(grep -hoE '\[EMAIL\]' "$AUDIT_DIR"/*.txt "$AUDIT_DIR"/*.xml 2>/dev/null | wc -l | tr -d ' ')"
  MJ="$(grep -hoE '\[JWT\]' "$AUDIT_DIR"/*.txt "$AUDIT_DIR"/*.xml 2>/dev/null | wc -l | tr -d ' ')"
  MG="$(grep -hoE '\[GUID-[0-9]+\]' "$AUDIT_DIR"/*.txt "$AUDIT_DIR"/*.xml 2>/dev/null | sort -u | wc -l | tr -d ' ')"
  MM="$(grep -hoE '\[MAC\]' "$AUDIT_DIR"/*.txt "$AUDIT_DIR"/*.xml 2>/dev/null | wc -l | tr -d ' ')"
  MT="$(grep -hoE '\[REDACTED\]' "$AUDIT_DIR"/*.txt "$AUDIT_DIR"/*.xml 2>/dev/null | wc -l | tr -d ' ')"
  echo "==> Masked: $ME emails, $MJ JWTs, $MG distinct GUIDs, $MM MAC addresses, $MT literal-term hits." >&2
  RESID="$(
    { grep -nIoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$AUDIT_DIR"/*.txt "$AUDIT_DIR"/*.xml
      grep -nIoE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' "$AUDIT_DIR"/*.txt "$AUDIT_DIR"/*.xml
      grep -nIoE '[0-9a-fA-F]{8}_[0-9a-fA-F]{4}_[0-9a-fA-F]{4}_[0-9a-fA-F]{4}_[0-9a-fA-F]{12}' "$AUDIT_DIR"/*.txt "$AUDIT_DIR"/*.xml
      grep -nIoE '\b[0-9a-fA-F]{32}\b' "$AUDIT_DIR"/*.txt "$AUDIT_DIR"/*.xml
      grep -nIoE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' "$AUDIT_DIR"/*.txt "$AUDIT_DIR"/*.xml
      printf '%s\n' "$LIT_BOUNDED" "$LIT_GREEDY" | while IFS= read -r t; do
        [ -n "$t" ] && grep -nIoiF -- "$t" "$AUDIT_DIR"/*.txt "$AUDIT_DIR"/*.xml
      done
    } 2>/dev/null
  )"
  if [ -n "$RESID" ]; then
    echo "==> WARNING: these still look like identifiers — review before uploading:" >&2
    printf '%s\n' "$RESID" | head -40 | sed 's/^/    /' >&2
  else
    echo "==> Verification: no raw emails, JWTs, GUIDs, MACs or known terms left in the output." >&2
  fi
else
  echo "==> Redaction OFF (REDACT=off) — files contain raw identifiers." >&2
fi

# --- Provide the analysis prompt next to the data ---
# The prompt lives in whats_up_prompt.md next to this script (easy to edit on its own).
# Copy it into the audit folder; if the script was run detached from the repo, write
# a short pointer instead so the run still tells the user where to get it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
SRC_PROMPT="$SCRIPT_DIR/whats_up_prompt.md"
PROMPT_FILE="$AUDIT_DIR/whats_up_prompt.md"
if [ -f "$SRC_PROMPT" ]; then
  cp "$SRC_PROMPT" "$PROMPT_FILE"
else
  printf '%s\n' \
    "# Audit analysis prompt" "" \
    "The full prompt ships as whats_up_prompt.md next to whats_up_bigbro.sh in the" \
    "little-brother repo, but it was not found there (the script was run detached" \
    "from the repo). Get whats_up_prompt.md from the repo and paste it into Claude" \
    "together with the nine audit files in this folder." > "$PROMPT_FILE"
fi

# Make everything readable for your normal user (otherwise root owns the files). Scope this
# to what the run created: the per-run subdir always, and AUDIT_ROOT only if we created it,
# so pointing AUDIT_ROOT at an existing directory never recursively re-owns the operator's tree.
chown -R "$SUDO_USER" "$AUDIT_DIR" 2>/dev/null
[ "$ROOT_PREEXISTED" -eq 0 ] && chown "$SUDO_USER" "$AUDIT_ROOT" 2>/dev/null
echo "==> All $TOTAL_STEPS steps done in ${SECONDS}s." >&2

# --- Instructions ---
cat <<EOF

============================================================
 DONE (in ${SECONDS}s). Files written to: $AUDIT_DIR
============================================================

 01_mde_health_$TS.txt        MDE status, definitions, whether the engine runs
 02_managed_prefs_$TS.txt     Defender + GSA config (plist)
 03_full_disk_access_$TS.txt  TCC: FDA, screen, input, camera/mic (system + user)
 04_profiles_summary_$TS.txt  MDM enrollment + Intune profiles (readable)
 05_profiles_full_$TS.xml     Full profile XML (PPPC/TCC scope)
 06_gsa_tunnel_$TS.txt        GSA — is the tunnel running for real right now
 07_gsa_config_tls_$TS.txt    GSA forwarding profile, logs, TLS inspection, routes
 08_system_hardening_$TS.txt  SIP, Gatekeeper, FileVault+escrow, firewall, remote access
 09_agents_network_$TS.txt    System extensions, agents, DNS/proxy, admin accounts

------------------------------------------------------------
 UPLOAD THESE TO CLAUDE (recommended model: Claude Opus 4.8):
------------------------------------------------------------
 All nine files in $AUDIT_DIR

 (Shortcut: in Finder, press Cmd+Shift+G and paste:
  $AUDIT_DIR )

 Why Opus 4.8: the analysis requires the model to read nine files
 at once, weigh them together and make a security assessment in plain
 language. It is a reasoning-heavy task, not a lookup. Opus 4.8 is the
 most capable model for that kind of synthesis and judgment, and its
 large context window takes all the files without trouble.

------------------------------------------------------------
 THE PROMPT (already written to a file for you):
------------------------------------------------------------
 $PROMPT_FILE

 Open it, copy everything, and paste it into Claude together with the
 nine files above. It asks for a neutral, plain-language Markdown report
 (with Mermaid diagrams) covering three parts: what the employer can see,
 the zero trust posture, and how to protect private secrets.
============================================================

 Note: identifiers are redacted by default (username, full name, hostname,
 serial, hardware UUID, emails, JWTs, GUIDs, MAC addresses). Company and
 project names cannot be derived — pass them as arguments to redact them:
 sudo bash $0 acme "Project Falcon". REDACT only takes on/off (REDACT=off
 disables redaction entirely). IP addresses (v4 and v6) are intentionally
 kept so the tunnel/route output stays meaningful. Still skim the files
 before uploading — redaction is best-effort, not a guarantee, and account
 or display names in the GSA logs (files 06/07) may need adding as terms.

 Tip: the files describe your machine in detail. Delete them once you
 have uploaded them and are done:  rm -rf "$AUDIT_DIR"
============================================================

EOF
