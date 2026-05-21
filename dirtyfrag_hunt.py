#!/usr/bin/env python3
"""
dirtyfrag_hunt.py — DirtyFrag Exposure & Hunting Tool
CVE-2026-43284 (xfrm-ESP) + CVE-2026-43500 (RxRPC)

Purpose : Purple team / detection engineering.
          Checks system exposure and hunts for exploitation indicators.
          No external dependencies beyond Python 3.6+ stdlib.

Author  : blacksunCUBE 
Date    : 2026-05-10
Repo    : https://github.com/blacksunCUBE/Dirty-Frag-hunting

Usage:
    python3 dirtyfrag_hunt.py              # basic check (no root needed)
    sudo python3 dirtyfrag_hunt.py         # full check including auditd hunt
    sudo python3 dirtyfrag_hunt.py -v      # verbose: show evidence per finding
    sudo python3 dirtyfrag_hunt.py --json results.json
    python3 dirtyfrag_hunt.py --print-auditd-rules
"""

import argparse
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Python / OS guard ──────────────────────────────

if sys.version_info < (3, 6):
    sys.exit("[!] Python 3.6 or newer required.")
if sys.platform != "linux":
    sys.exit("[!] Linux only.")

# ── ANSI colours──────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"


def col(colour, text):
    return f"{colour}{text}{RESET}"


# ── Finding dataclass (manual, no external deps) ──────────────────────────────

class Finding:
    __slots__ = ("check_id", "cve", "status", "title", "detail",
                 "evidence", "remediation")

    def __init__(self, check_id, cve, status, title, detail,
                 evidence=None, remediation=""):
        self.check_id    = check_id
        self.cve         = cve
        self.status      = status      # VULN | MITIGATED | INFO | UNKNOWN
        self.title       = title
        self.detail      = detail
        self.evidence    = list(evidence) if evidence else []
        self.remediation = remediation

    def to_dict(self):
        return {
            "check_id":    self.check_id,
            "cve":         self.cve,
            "status":      self.status,
            "title":       self.title,
            "detail":      self.detail,
            "evidence":    self.evidence,
            "remediation": self.remediation,
        }


# ── Low-level helpers ──────────────────────────────

def run_cmd(cmd, timeout=5):
    """Run command list; return stdout string or '' on any error."""
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return result.stdout.decode(errors="replace").strip()
    except Exception:
        return ""


def read_file(path):
    """Return file content as string, or '' on error."""
    try:
        return Path(path).read_text(errors="replace").strip()
    except Exception:
        return ""


def read_int(path):
    """Return integer from a sysctl file, or None on error."""
    val = read_file(path)
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


# ── Module state ──────────────────────────────

def get_loaded_modules():
    """
    Parse /proc/modules.
    Returns dict: { module_name: {"size": str, "refcount": str} }
    Module names use underscores (e.g. 'esp4', 'rxrpc').
    """
    modules = {}
    for line in read_file("/proc/modules").splitlines():
        parts = line.split()
        if len(parts) >= 3:
            modules[parts[0]] = {"size": parts[1], "refcount": parts[2]}
    return modules


def is_module_blacklisted(name):
    """
    Search modprobe.d directories for 'install <name> /bin/false|/bin/true'.
    Covers /etc/modprobe.d, /lib/modprobe.d, /run/modprobe.d.
    """
    for directory in ("/etc/modprobe.d", "/lib/modprobe.d", "/run/modprobe.d"):
        d = Path(directory)
        if not d.is_dir():
            continue
        for conf in d.glob("*.conf"):
            try:
                text = conf.read_text(errors="replace")
            except Exception:
                continue
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("#"):
                    continue
                parts = line.split()
                if (len(parts) >= 3
                        and parts[0] == "install"
                        and parts[1] == name
                        and parts[2] in ("/bin/false", "/bin/true")):
                    return True
    return False


# ── Checks ──────────────────────────────

def check_kernel_version():
    """
    Approximate check of kernel version against vulnerable commit windows.

    xfrm  (CVE-2026-43284): cac2661c53f3 landed ~4.9  → patch f4c50a4034e6 (~6.15)
    rxrpc (CVE-2026-43500): 2dc334f1a63a landed ~6.4  → no patch anywhere

    Distro backports cannot be detected from version alone — treat as informational.
    """
    kver  = platform.release()
    parts = kver.split("-")[0].split(".")
    try:
        major, minor = int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return Finding(
            "kernel-version", "BOTH", "UNKNOWN",
            f"Cannot parse kernel version: {kver}",
            "Version string does not match expected X.Y.Z format.",
            evidence=[f"uname -r: {kver}"],
        )

    ev = [f"kernel release: {kver}"]

    if (major, minor) < (4, 9):
        return Finding(
            "kernel-version", "BOTH", "UNKNOWN",
            f"Kernel {kver} — predates known vulnerability windows",
            "Older than cac2661c53f3 (~4.9). Unlikely to be affected.",
            evidence=ev,
        )

    if (major, minor) < (6, 4):
        return Finding(
            "kernel-version", "CVE-2026-43284", "VULN",
            f"Kernel {kver} — within xfrm CVE-2026-43284 window",
            "xfrm-ESP window open since cac2661c53f3 (~4.9). "
            "rxrpc not yet introduced at this version.",
            evidence=ev,
        )

    if (major, minor) < (6, 15):
        return Finding(
            "kernel-version", "BOTH", "VULN",
            f"Kernel {kver} — within both CVE windows",
            "xfrm: cac2661c53f3 → patch f4c50a4034e6 not yet in this version. "
            "rxrpc: 2dc334f1a63a (~6.4) → no patch in any tree.",
            evidence=ev,
        )

    # 6.15+: xfrm mainline patch may be present, rxrpc still unpatched
    return Finding(
        "kernel-version", "BOTH", "INFO",
        f"Kernel {kver} — xfrm patch may be included; rxrpc still unpatched",
        "Kernel ≥6.15 may contain f4c50a4034e6 (xfrm). "
        "CVE-2026-43500 (rxrpc) has no patch anywhere — verify module state.",
        evidence=ev,
    )


def check_esp_modules(loaded):
    """CVE-2026-43284 — esp4 and esp6 module state."""
    evidence  = []
    vuln_mods = []

    for mod in ("esp4", "esp6"):
        if is_module_blacklisted(mod):
            evidence.append(f"{mod}: blacklisted in modprobe.d ✓")
        elif mod in loaded:
            info = loaded[mod]
            vuln_mods.append(mod)
            evidence.append(
                f"{mod}: LOADED  size={info['size']}  refcount={info['refcount']}"
            )
        else:
            evidence.append(f"{mod}: not loaded")

    if vuln_mods:
        return Finding(
            "esp-module", "CVE-2026-43284", "VULN",
            f"{', '.join(vuln_mods)} loaded and not blacklisted",
            "A process with CLONE_NEWUSER access can trigger the xfrm-ESP "
            "page-cache write primitive (CVE-2026-43284).",
            evidence=evidence,
            remediation=(
                "printf 'install esp4 /bin/false\\ninstall esp6 /bin/false\\n'"
                " >> /etc/modprobe.d/dirtyfrag.conf"
                " && rmmod esp4 esp6 2>/dev/null; true"
            ),
        )

    return Finding(
        "esp-module", "CVE-2026-43284", "MITIGATED",
        "esp4 and esp6 are not active or are blacklisted",
        "xfrm-ESP path is not accessible.",
        evidence=evidence,
    )


def check_rxrpc_module(loaded):
    """CVE-2026-43500 — rxrpc module state."""
    blacklisted = is_module_blacklisted("rxrpc")
    is_loaded   = "rxrpc" in loaded

    if blacklisted:
        return Finding(
            "rxrpc-module", "CVE-2026-43500", "MITIGATED",
            "rxrpc blacklisted in modprobe.d",
            "rxrpc.ko is prevented from loading.",
            evidence=["rxrpc: blacklisted ✓"],
        )

    if is_loaded:
        info = loaded["rxrpc"]
        return Finding(
            "rxrpc-module", "CVE-2026-43500", "VULN",
            "rxrpc.ko is LOADED — no namespace privilege required",
            "Any local unprivileged user can trigger CVE-2026-43500. "
            "No patch exists in any kernel tree as of 2026-05-10.",
            evidence=[
                f"rxrpc: LOADED  size={info['size']}  refcount={info['refcount']}"
            ],
            remediation=(
                "printf 'install rxrpc /bin/false\\n'"
                " >> /etc/modprobe.d/dirtyfrag.conf"
                " && rmmod rxrpc 2>/dev/null; true"
            ),
        )

    return Finding(
        "rxrpc-module", "CVE-2026-43500", "MITIGATED",
        "rxrpc.ko not loaded",
        "RxRPC path is not accessible.",
        evidence=["rxrpc: absent from /proc/modules"],
    )


def check_user_namespaces():
    """
    CVE-2026-43284 — check if unprivileged CLONE_NEWUSER is reachable.
    Two independent controls: max_user_namespaces sysctl and AppArmor restriction.
    """
    ns_path = "/proc/sys/user/max_user_namespaces"
    aa_path = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"

    max_ns = read_int(ns_path)
    aa_val = read_int(aa_path)   # 1 = AppArmor restricts; None = key absent

    evidence = [
        f"max_user_namespaces                    = "
        f"{max_ns if max_ns is not None else 'unreadable'}",
        f"apparmor_restrict_unprivileged_userns   = "
        f"{aa_val if aa_val is not None else 'not present (key absent)'}",
    ]

    if max_ns == 0:
        return Finding(
            "userns", "CVE-2026-43284", "MITIGATED",
            "User namespaces disabled (max_user_namespaces=0)",
            "CLONE_NEWUSER unavailable to unprivileged processes — xfrm path blocked.",
            evidence=evidence,
        )

    if aa_val == 1:
        return Finding(
            "userns", "CVE-2026-43284", "MITIGATED",
            "AppArmor restricts unprivileged user namespace creation",
            "CLONE_NEWUSER blocked by AppArmor — xfrm path (CVE-2026-43284) mitigated. "
            "Note: rxrpc (CVE-2026-43500) does NOT require namespace creation; "
            "check that module separately.",
            evidence=evidence,
        )

    return Finding(
        "userns", "CVE-2026-43284", "VULN",
        "Unprivileged user namespace creation permitted",
        "Any local user can call unshare(CLONE_NEWUSER) and configure an IPsec SA, "
        "enabling the xfrm-ESP page-cache write primitive.",
        evidence=evidence,
        remediation=(
            "# Option A — disable user namespaces:\n"
            "sysctl -w user.max_user_namespaces=0\n"
            "echo 'user.max_user_namespaces=0' >> /etc/sysctl.d/99-dirtyfrag.conf\n"
            "# Option B — AppArmor restriction (Ubuntu 23.10+):\n"
            "sysctl -w kernel.apparmor_restrict_unprivileged_userns=1"
        ),
    )


def check_modprobe_config():
    """Verify /etc/modprobe.d/dirtyfrag.conf is present and blacklists all three modules."""
    conf     = Path("/etc/modprobe.d/dirtyfrag.conf")
    required = {"esp4", "esp6", "rxrpc"}
    found    = set()
    evidence = []

    if conf.exists():
        try:
            for line in conf.read_text(errors="replace").splitlines():
                s = line.strip()
                if s.startswith("#"):
                    continue
                parts = s.split()
                if (len(parts) >= 3
                        and parts[0] == "install"
                        and parts[1] in required):
                    found.add(parts[1])
                    evidence.append(f"  ✓ {s}")
        except Exception as exc:
            evidence.append(f"  read error: {exc}")
    else:
        evidence.append("/etc/modprobe.d/dirtyfrag.conf: NOT FOUND")

    missing = required - found

    if not missing:
        return Finding(
            "modprobe-config", "BOTH", "MITIGATED",
            "dirtyfrag.conf present and complete — all three modules blacklisted",
            "esp4, esp6, rxrpc all have 'install /bin/false' entries.",
            evidence=evidence,
        )

    status = "VULN" if not found else "UNKNOWN"
    return Finding(
        "modprobe-config", "BOTH", status,
        f"dirtyfrag.conf missing or incomplete "
        f"— not blacklisted: {', '.join(sorted(missing))}",
        "Un-blacklisted modules can be loaded on-demand. "
        "The official mitigation is incomplete.",
        evidence=evidence,
        remediation=(
            'sh -c "printf \'install esp4 /bin/false\\n'
            'install esp6 /bin/false\\n'
            'install rxrpc /bin/false\\n\' '
            '> /etc/modprobe.d/dirtyfrag.conf; '
            'rmmod esp4 esp6 rxrpc 2>/dev/null; true"'
        ),
    )


# ── /proc hunting ──────────────────────────────

def hunt_proc():
    """
    Inspect /proc for live xfrm or rxrpc activity:
      - /proc/net/xfrm_stat     non-zero error counters
      - /proc/net/protocols     rxrpc registered
      - ip xfrm policy list     active IPsec policies
    """
    evidence = []

    # xfrm_stat — counters worth watching
    watch = {
        "XfrmInError", "XfrmInStateProtoError",
        "XfrmInTmplMismatch", "XfrmAcquireError",
    }
    for line in read_file("/proc/net/xfrm_stat").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in watch:
            try:
                if int(parts[1]) > 0:
                    evidence.append(f"xfrm_stat: {parts[0]} = {parts[1]}")
            except ValueError:
                pass

    # /proc/net/protocols — rxrpc registered?
    for line in read_file("/proc/net/protocols").splitlines():
        if "RXRPC" in line.upper():
            evidence.append(f"RXRPC in /proc/net/protocols: {line.strip()}")

    # ip xfrm policy list
    ip_out = run_cmd(["ip", "xfrm", "policy", "list"], timeout=5)
    if ip_out:
        if "Operation not permitted" in ip_out:
            evidence.append("ip xfrm policy: permission denied (run as root for full output)")
        else:
            count = ip_out.count("src ")
            if count:
                evidence.append(f"ip xfrm policy: {count} active policies found")
                evidence.append(ip_out[:400] + ("..." if len(ip_out) > 400 else ""))
            else:
                evidence.append("ip xfrm policy: no active policies")

    active = any(
        "xfrm_stat:" in e or "RXRPC" in e.upper() or "policies found" in e
        for e in evidence
    )

    if active:
        return Finding(
            "proc-hunt", "BOTH", "INFO",
            "xfrm or rxrpc activity detected in /proc — review recommended",
            "Active xfrm policies or rxrpc sockets present. "
            "Correlate with process context and uid changes to distinguish "
            "legitimate VPN/AFS from exploitation.",
            evidence=evidence,
        )

    return Finding(
        "proc-hunt", "BOTH", "INFO",
        "No suspicious xfrm/rxrpc activity in /proc",
        "All xfrm_stat counters at zero, rxrpc absent from protocols, "
        "no active xfrm policies.",
        evidence=evidence if evidence else ["xfrm_stat: all counters zero"],
    )


# ── auditd hunting ──────────────────────────────

def hunt_auditd():
    """
    Search recent auditd logs for DirtyFrag-relevant events via ausearch.
    Requires root for complete results.
    """
    if not run_cmd(["which", "ausearch"]):
        return Finding(
            "auditd-hunt", "BOTH", "INFO",
            "ausearch not available — auditd hunting skipped",
            "Install auditd to enable syscall-level hunting. "
            "See --print-auditd-rules for the recommended rule set.",
            evidence=["ausearch: not found in PATH"],
        )

    evidence = []

    # unshare(CLONE_NEWUSER) — precondition for CVE-2026-43284
    out = run_cmd(
        ["ausearch", "-sc", "unshare", "--start", "recent", "--interpret"],
        timeout=10,
    )
    if out and "no matches" not in out.lower() and "nothing to do" not in out.lower():
        relevant = [l for l in out.splitlines()
                    if any(k in l for k in ("SYSCALL", "comm=", "uid=", "auid="))]
        if relevant:
            evidence.append(f"[unshare] {len(relevant)} audit records:")
            evidence.extend(f"  {l}" for l in relevant[:5])

    # Named DirtyFrag audit keys (loaded if --print-auditd-rules rules are active)
    for key in ("dirtyfrag_userns", "dirtyfrag_afkey",
                "dirtyfrag_rxrpc", "dirtyfrag_passwd_write"):
        out = run_cmd(["ausearch", "-k", key, "--start", "recent"], timeout=10)
        if out and "no matches" not in out.lower() and "nothing to do" not in out.lower():
            count = out.count("type=SYSCALL") + out.count("type=PATH")
            evidence.append(f"[{key}] {count} matching events")

    # /etc/passwd write events
    out = run_cmd(
        ["ausearch", "-f", "/etc/passwd", "--start", "recent", "--interpret"],
        timeout=10,
    )
    if out and "no matches" not in out.lower() and "nothing to do" not in out.lower():
        evidence.append("/etc/passwd: recent access events found:")
        evidence.extend(f"  {l}" for l in out.splitlines()[:6])

    if not evidence:
        return Finding(
            "auditd-hunt", "BOTH", "INFO",
            "No DirtyFrag-relevant events in recent audit log",
            "No unshare, AF_KEY, AF_RXRPC, or /etc/passwd write events detected. "
            "Load the dirtyfrag auditd rule set first — see --print-auditd-rules.",
            evidence=["ausearch: no relevant recent events"],
        )

    return Finding(
        "auditd-hunt", "BOTH", "INFO",
        "DirtyFrag-relevant audit events found — manual review required",
        "Events consistent with exploitation preconditions detected. "
        "Correlate with uid/euid changes and /etc/passwd modification timestamps.",
        evidence=evidence,
    )


# ── auditd rules ──────────────────────────────

AUDITD_RULES = """\
# ── DirtyFrag auditd rules ──────────────────────────────
# Add to : /etc/audit/rules.d/dirtyfrag.rules
# Apply  : augenrules --load
# ──────────────────────────────

# Unprivileged user namespace creation — CVE-2026-43284 precondition
# CLONE_NEWUSER flag = 0x10000000
-a always,exit -F arch=b64 -S unshare -F a0&0x10000000 -F auid>=1000 -F auid!=-1 -k dirtyfrag_userns
-a always,exit -F arch=b32 -S unshare -F a0&0x10000000 -F auid>=1000 -F auid!=-1 -k dirtyfrag_userns

# AF_KEY socket creation — xfrm SA setup (AF_KEY = 15 decimal)
-a always,exit -F arch=b64 -S socket -F a0=15 -F auid>=1000 -F auid!=-1 -k dirtyfrag_afkey
-a always,exit -F arch=b32 -S socket -F a0=15 -F auid>=1000 -F auid!=-1 -k dirtyfrag_afkey

# AF_RXRPC socket creation — CVE-2026-43500 trigger (AF_RXRPC = 35 decimal)
-a always,exit -F arch=b64 -S socket -F a0=35 -F auid>=1000 -F auid!=-1 -k dirtyfrag_rxrpc
-a always,exit -F arch=b32 -S socket -F a0=35 -F auid>=1000 -F auid!=-1 -k dirtyfrag_rxrpc

# Write to /etc/passwd and /etc/shadow — post-exploitation indicator
-w /etc/passwd -p w -k dirtyfrag_passwd_write
-w /etc/shadow -p w -k dirtyfrag_shadow_write

# Module load attempts for blocked modules — mitigation tamper indicator
-w /sbin/modprobe -p x -k dirtyfrag_modload
-w /sbin/insmod   -p x -k dirtyfrag_modload
"""


# ── Report printer ──────────────────────────────

STATUS_PREFIX = {
    "VULN":      col(RED + BOLD,   "[VULN]    "),
    "MITIGATED": col(GREEN,        "[MITIG]   "),
    "INFO":      col(CYAN,         "[INFO]    "),
    "UNKNOWN":   col(YELLOW,       "[UNKNOWN] "),
}


def print_report(findings, hostname, kver, distro, verbose=False):
    w = 72
    print()
    print(col(BOLD, "═" * w))
    print(col(BOLD, "  blacksunCUBE — DirtyFrag Exposure & Hunting Tool"))
    print(col(DIM,  "  CVE-2026-43284 · CVE-2026-43500"))
    print(col(BOLD, "─" * w))
    print(col(DIM,  f"  Host   : {hostname}"))
    print(col(DIM,  f"  Kernel : {kver}"))
    print(col(DIM,  f"  Distro : {distro}"))
    print(col(BOLD, "─" * w))
    print()

    for f in findings:
        prefix = STATUS_PREFIX.get(f.status, "[?]      ")
        print(f"  {prefix}{col(CYAN, '[' + f.cve + ']')}")
        print(f"  {col(BOLD, f.title)}")
        print(col(DIM, f"  {f.detail}"))
        if verbose and f.evidence:
            for item in f.evidence:
                for line in item.splitlines():
                    print(col(DIM, f"    · {line}"))
        if f.status == "VULN" and f.remediation:
            print(col(YELLOW, "  → Remediation:"))
            for line in f.remediation.splitlines():
                print(col(YELLOW, f"    {line}"))
        print()

    vuln_n = sum(1 for f in findings if f.status == "VULN")
    unk_n  = sum(1 for f in findings if f.status == "UNKNOWN")
    print(col(BOLD, "─" * w))
    if vuln_n:
        print(col(RED + BOLD, f"  RESULT : EXPOSED — {vuln_n} check(s) VULNERABLE"))
    elif unk_n:
        print(col(YELLOW + BOLD,
            f"  RESULT : UNCERTAIN — {unk_n} check(s) UNKNOWN, review above"))
    else:
        print(col(GREEN + BOLD, "  RESULT : MITIGATED — no active exposure detected"))
    print(col(BOLD, "═" * w))
    print()


def get_distro():
    lsb = run_cmd(["lsb_release", "-ds"])
    if lsb:
        return lsb
    for path in ("/etc/os-release", "/etc/redhat-release", "/etc/debian_version"):
        text = read_file(path)
        if not text:
            continue
        for line in text.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
        return text.splitlines()[0]
    return "unknown"


# ── CLI ──────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog="dirtyfrag_hunt.py",
        description="DirtyFrag exposure checker — blacksunCUBE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print evidence lines for each finding")
    p.add_argument("--json", metavar="FILE",
                   help="Write findings as JSON to FILE")
    p.add_argument("--no-hunt", action="store_true",
                   help="Skip /proc and auditd hunting (no root required)")
    p.add_argument("--print-auditd-rules", action="store_true",
                   help="Print recommended auditd rules and exit")
    return p.parse_args()


def main():
    args    = parse_args()

    if args.print_auditd_rules:
        print(AUDITD_RULES)
        sys.exit(0)

    kver     = platform.release()
    distro   = get_distro()
    hostname = platform.node()
    is_root  = (os.geteuid() == 0)

    if not is_root:
        print(col(YELLOW,
            "[*] Not running as root — some checks will be limited. "
            "Re-run with sudo for full results.\n"))

    loaded = get_loaded_modules()

    findings = [
        check_kernel_version(),
        check_esp_modules(loaded),
        check_rxrpc_module(loaded),
        check_user_namespaces(),
        check_modprobe_config(),
    ]

    if not args.no_hunt:
        findings.append(hunt_proc())
        if is_root:
            findings.append(hunt_auditd())
        else:
            findings.append(Finding(
                "auditd-hunt", "BOTH", "INFO",
                "auditd hunt skipped — requires root",
                "Re-run with sudo to enable ausearch results.",
            ))

    print_report(findings, hostname, kver, distro, verbose=args.verbose)

    if args.json:
        ts   = datetime.now(timezone.utc).isoformat()
        vuln = sum(1 for f in findings if f.status == "VULN")
        data = {
            "tool":      "dirtyfrag_hunt",
            "version":   "1.1",
            "timestamp": ts,
            "hostname":  hostname,
            "kernel":    kver,
            "distro":    distro,
            "overall":   "EXPOSED" if vuln else "OK",
            "vuln_count": vuln,
            "findings":  [f.to_dict() for f in findings],
        }
        try:
            Path(args.json).write_text(json.dumps(data, indent=2))
            print(col(GREEN, f"[+] Report written to {args.json}"))
        except Exception as exc:
            print(col(RED, f"[!] Could not write JSON: {exc}"))

    sys.exit(1 if any(f.status == "VULN" for f in findings) else 0)


if __name__ == "__main__":
    main()
