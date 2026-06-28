#!/usr/bin/env python3
"""Read-only guard for whats_up_bigbro.sh.

The audit script must never modify the machine it runs on. The only writes allowed
are the ones that land in the result directory (the AUDIT_ROOT / AUDIT_DIR / *_FILE
variables). Everything else must be read-only: no delete, no move, no in-place edit,
no permission/policy change on the system, no network calls.

This guard scans the shell source statically and fails (exit 1) on anything that
looks like a system-mutating command. It is a safety net for pull requests, not a
sandbox — human review still applies.

Usage:
    python3 tools/readonly-guard.py [script.sh ...]   # default: whats_up_bigbro.sh

Escape hatch: append "# guard:allow" to a line you have reviewed and consider safe.
"""

import re
import sys

# Variables that name the result directory or files inside it. A mutating command is
# tolerated only when the line references one of these (i.e. it writes to the output).
RESULT_VARS = (r'(?:AUDIT_ROOT|AUDIT_DIR|PROMPT_FILE|MDE_FILE|MGMT_FILE|TCC_FILE|'
               r'PROF_FILE|XML_FILE|GSA_FILE|GSA2_FILE|HARD_FILE|AGENT_FILE)')
RESULT_REF = re.compile(r'\$\{?' + RESULT_VARS + r'\b')

# Command position: start of a logical line, after a shell separator, or after a
# wrapper that runs another command (sudo, env, xargs, ...). The trailing optional path
# prefix lets a command invoked by absolute/relative path still be recognised, e.g.
# /usr/libexec/PlistBuddy, /bin/rm or ./tool.
CP = (r'(?:^|[;&|]|&&|\|\||\{|\(|'
      r'\bthen\b|\bdo\b|\bsudo\b|\bcommand\b|\bexec\b|\benv\b|\bnice\b|\bxargs\b|'
      r'\btime\b|\bbuiltin\b)\s*(?:[\w.-]*/)*')

# Commands with no read-only use here — flagged wherever they appear at command position.
# 'eval' is included because it runs an arbitrary string the static scan cannot see; 'chsh'
# changes a login shell.
ALWAYS = re.compile(
    CP + r'(dd|mkfifo|mknod|touch|truncate|chflags|chgrp|chsh|install|tee|eval|'
    r'nvram|diskutil|kextload|kextunload|pmset|networksetup|softwareupdate|mdutil|'
    r'killall|pkill|kill|shutdown|reboot|halt|'
    r'curl|wget|nc|ncat|netcat|telnet|ssh|scp|sftp|ftp|rsync|'
    r'osascript|open|mail|sendmail|route|pfctl|iptables|crontab)\b')

# File-mutating commands that ARE allowed, but only against the result directory.
UNLESS_RESULT = re.compile(CP + r'(rm|rmdir|mv|cp|mkdir|chmod|chown|ln)\b')
INPLACE = re.compile(CP + r'(?:perl|sed)\b[^\n]*?\s-i(?:\b|\.)')  # perl -i / sed -i

# Dual-use tools: read-only by default, dangerous with certain subcommands/flags.
# (label, tool-at-command-position, mutating-pattern-anywhere-on-line)
DUAL = [
    ('dscl write',            re.compile(CP + r'dscl\b'),
     re.compile(r'\s-?(?:create|delete|change|append|merge|passwd)\b')),
    ('defaults write',        re.compile(CP + r'defaults\b'),
     re.compile(r'\bdefaults\s+(?:write|delete|rename|import)\b')),
    ('launchctl mutate',      re.compile(CP + r'launchctl\b'),
     re.compile(r'\blaunchctl\s+(?:load|unload|bootstrap|bootout|enable|disable|'
                r'kickstart|remove|setenv|unsetenv|start|stop|kill|reboot)\b')),
    ('profiles mutate',       re.compile(CP + r'profiles\b'),
     re.compile(r'\bprofiles\s+(?:install|remove|renew)\b|\bprofiles\b[^\n]*\s-[IR]\b')),
    ('csrutil mutate',        re.compile(CP + r'csrutil\b'),
     re.compile(r'\bcsrutil\s+(?:enable|disable|clear|authenticated-root)\b')),
    ('spctl mutate',          re.compile(CP + r'spctl\b'),
     re.compile(r'\bspctl\s+--(?:master-disable|master-enable|add|remove|enable|disable|reset)\b')),
    ('fdesetup mutate',       re.compile(CP + r'fdesetup\b'),
     re.compile(r'\bfdesetup\s+(?:enable|disable|add|remove|changerecovery|sync|authrestart)\b')),
    ('systemsetup set',       re.compile(CP + r'systemsetup\b'),
     re.compile(r'\bsystemsetup\s+-set')),
    ('systemextensionsctl mutate', re.compile(CP + r'systemextensionsctl\b'),
     re.compile(r'\bsystemextensionsctl\s+(?:reset|uninstall)\b')),
    ('security mutate',       re.compile(CP + r'security\b'),
     re.compile(r'\bsecurity\s+(?:add-|delete-|set-|import|export|'
                r'unlock-keychain|lock-keychain|create-keychain|default-keychain|set-keychain)')),
    ('scutil set',            re.compile(CP + r'scutil\b'),
     re.compile(r'\bscutil\b[^\n]*--set\b')),
    ('ifconfig mutate',       re.compile(CP + r'ifconfig\b'),
     re.compile(r'\bifconfig\s+\S+\s+(?:up|down|inet6?|add|delete|alias|-alias|create|destroy|mtu|ether)\b')),
    ('find mutate',           re.compile(CP + r'find\b'),
     re.compile(r'\s-(?:delete|exec|execdir|ok|okdir|fprint|fprintf|fputc)\b')),
    ('sqlite3 write',         re.compile(CP + r'sqlite3\b'),
     re.compile(r'\b(?:INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|REPLACE|TRUNCATE|VACUUM|ATTACH|REINDEX)\b', re.I)),
    ('plutil mutate',         re.compile(CP + r'plutil\b'),
     re.compile(r'\bplutil\b[^\n]*\s-(?:replace|insert|remove|convert|extract)\b')),
    ('PlistBuddy mutate',     re.compile(CP + r'PlistBuddy\b'),
     re.compile(r'\b(?:Set|Add|Delete|Merge|Import|Copy)\b')),
    ('shell -c',              re.compile(CP + r'(?:bash|sh|zsh|dash|ksh)\b'),
     re.compile(r'\s-c\b')),
    # Interpreters used as file writers (open(...,'w'/'a'/'x'/'>'/'+'), os.remove, shutil,
    # File.write, fs.writeFileSync, system(), unlink, ...). The script's own python3/perl use
    # (json.tool, the perl -i redaction) contains none of these primitives, so it stays clean.
    ('interpreter write',     re.compile(CP + r'(?:python3?|perl|ruby|node|php)\b'),
     re.compile(r'(?:os\.(?:remove|unlink|rename|rmdir|mkdir|makedirs|chmod|chown|truncate)\b|'
                r'shutil\.(?:rmtree|move|copy\w*)|'
                r'open\s*\([^)]*[\'"][^\'")]*[wax>+]|'
                r'File\.(?:write|delete|open|new|rename|unlink)|IO\.write|FileUtils\.|'
                r'\.(?:write|writeFile|writeFileSync|appendFile\w*|unlink\w*|rm|rmSync|'
                r'rmdir\w*|truncate\w*)\s*\(|'
                r'\bunlink\b|\bsystem\s*\()')),
]

DEV_OK = re.compile(r'^(?:/dev/(?:null|stdout|stderr|tty)|&\d+|&-)$')
REDIR = re.compile(r'(\d*)>{1,2}\s*(&?[^\s;|&()<>]+|&\d+|&-)')


def open_quote(s):
    """Return True if s ends inside an unclosed single- or double-quoted string."""
    i, q = 0, None
    while i < len(s):
        c = s[i]
        if q == "'":
            if c == "'":
                q = None
        elif q == '"':
            if c == '\\':
                i += 1
            elif c == '"':
                q = None
        else:
            if c == "'":
                q = "'"
            elif c == '"':
                q = '"'
            elif c == '\\':
                i += 1
        i += 1
    return q is not None


def logical_lines(text):
    """Yield (start_lineno, joined_line) skipping comments and heredoc bodies,
    joining backslash continuations and quotes that span multiple lines."""
    raw = text.split('\n')
    out = []
    i = 0
    n = len(raw)
    heredoc_re = re.compile(r'<<-?\s*[\'"]?([A-Za-z_][A-Za-z0-9_]*)[\'"]?')
    while i < n:
        line = raw[i]
        stripped = line.lstrip()
        # Full-line comment or blank
        if stripped == '' or stripped.startswith('#'):
            i += 1
            continue
        start = i + 1
        # Heredoc: scan its start line. If the heredoc feeds an interpreter or a shell, the
        # body is code, not data, so scan it too — a mutating payload routed through
        # 'python3 <<EOF' or 'bash <<EOF' would otherwise be invisible. For an interpreter,
        # each body line is prefixed with the interpreter name so the 'interpreter write'
        # rule (tool + write-primitive on one line) fires. For a shell, body lines are scanned
        # as-is so 'rm ...' / '> /etc/...' are caught. Plain data heredocs (cat, the final
        # instructions block) are skipped as before.
        m = heredoc_re.search(line)
        if m:
            delim = m.group(1)
            lead = stripped.split('<<', 1)[0]
            interp = re.search(r'\b(?:python3?|perl|ruby|node|php)\b', lead)
            shell = re.search(r'\b(?:bash|sh|zsh|dash|ksh)\b', lead)
            out.append((start, line))
            i += 1
            while i < n and raw[i].strip() != delim:
                if interp:
                    out.append((i + 1, interp.group(0) + ' ' + raw[i]))
                elif shell:
                    out.append((i + 1, raw[i]))
                i += 1
            i += 1  # consume the delimiter line
            continue
        # Join backslash continuations and unterminated quoted strings.
        buf = line
        while i + 1 < n and (buf.rstrip().endswith('\\') or open_quote(buf)):
            if buf.rstrip().endswith('\\'):
                buf = buf.rstrip()[:-1] + ' ' + raw[i + 1]
            else:
                buf = buf + '\n' + raw[i + 1]
            i += 1
        i += 1
        out.append((start, buf))
    return out


def tokenize(line):
    """Replace quoted strings with QRES (contains a result-dir ref) or QSTR tokens,
    so that '>' inside strings is not mistaken for a redirection."""
    line = re.sub(r"'[^']*'", ' QSTR ', line)              # single quotes: literal
    def repl(m):
        return ' QRES ' if RESULT_REF.search(m.group(0)) else ' QSTR '
    line = re.sub(r'"(?:[^"\\]|\\.)*"', repl, line)        # double quotes
    return line


def check_line(line):
    """Return a list of reasons this line mutates something it should not."""
    if 'guard:allow' in line:
        return []
    reasons = []
    has_result = bool(RESULT_REF.search(line))

    if ALWAYS.search(line):
        reasons.append('disallowed command (write/delete/network/etc.)')
    if UNLESS_RESULT.search(line) and not has_result:
        reasons.append('file-mutating command not targeting the result directory')
    if INPLACE.search(line) and not has_result:
        reasons.append('in-place edit (perl -i / sed -i) not targeting the result directory')
    for label, tool, mutate in DUAL:
        if tool.search(line) and mutate.search(line):
            reasons.append(label)

    tok = tokenize(line)
    for mm in REDIR.finditer(tok):
        target = mm.group(2)
        if DEV_OK.match(target) or target == 'QRES' or target.startswith('&'):
            continue
        reasons.append('redirect writes to a non-result target: %s' % target)
    return reasons


def scan(path):
    with open(path, encoding='utf-8') as fh:
        text = fh.read()
    findings = []
    for lineno, line in logical_lines(text):
        for reason in check_line(line):
            findings.append((lineno, reason, line.strip()))
    return findings


def main(argv):
    targets = argv[1:] or ['whats_up_bigbro.sh']
    total = 0
    for path in targets:
        try:
            findings = scan(path)
        except OSError as e:
            print('error: cannot read %s: %s' % (path, e), file=sys.stderr)
            return 2
        for lineno, reason, snippet in findings:
            snippet = snippet if len(snippet) <= 120 else snippet[:117] + '...'
            print('%s:%d: %s\n    %s' % (path, lineno, reason, snippet))
        total += len(findings)
    if total:
        print('\nread-only guard: %d finding(s). The audit script must only write to '
              'the result directory.' % total, file=sys.stderr)
        return 1
    print('read-only guard: OK — no system-mutating commands found.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
