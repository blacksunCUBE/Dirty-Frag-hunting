# Dirty-Frag-hunting# Dirty-Frag-hunting

Detection and hunting tools for **CVE-2026-43284** (xfrm-ESP) and **CVE-2026-43500** (RxRPC) the DirtyFrag Linux LPE vulnerability class.

> **Scope:** Purple team / detection engineering. These tools check exposure and hunt for exploitation indicators. They do not exploit anything.

Original research: [Hyunwoo Kim (@v4bel)](https://github.com/V4bel/dirtyfrag)  
Technical write-up: [blacksunCUBE](https://0xallow.github.io/public/dirtyfrag-news.html)

---

## Files

| File | Purpose |
|---|---|
| `dirtyfrag_hunt.py` | Exposure checker + `/proc` inspection + auditd hunting |
| `dirtyfrag.yml` | Sigma rules (6 rules) for auditd / SIEM |
| `dirtyfrag.yar` | YARA rules (5 rules) source, binary, memory, tamper detection |

---

## Quick start

```bash
# Basic exposure check (no root needed)
python3 dirtyfrag_hunt.py

# Full check with auditd hunting
sudo python3 dirtyfrag_hunt.py -v

# Export findings as JSON
sudo python3 dirtyfrag_hunt.py --json findings.json

# Print and apply auditd rules
python3 dirtyfrag_hunt.py --print-auditd-rules > /etc/audit/rules.d/dirtyfrag.rules
augenrules --load

# Sigma rule conversion
sigma convert -t splunk dirtyfrag.yml
sigma convert -t elastic dirtyfrag.yml

# YARA scan
yara -r dirtyfrag.yar /tmp /home /dev/shm
yara dirtyfrag.yar /proc/<pid>/mem
```

---

## CVE summary

| CVE | Subsystem | Primitive | Priv req. | Patch |
|---|---|---|---|---|
| CVE-2026-43284 | xfrm (IPsec ESP) | 4-byte write into page cache | CLONE_NEWUSER | mainline: `f4c50a4034e6` no distro backport |
| CVE-2026-43500 | RxRPC (AFS transport) | page-cache write | none | **no patch anywhere** |

Both are deterministic logic bugs no race condition, no kernel panic on failure.

**xfrm window:** `cac2661c53f3` (2017-01-17) → unpatched on all distros  
**rxrpc window:** `2dc334f1a63a` (2023-06) → unpatched everywhere (2026-05-10)

---

## Exploitation chain (CVE-2026-43284)

```
unshare(CLONE_NEWUSER)
  → socket(AF_KEY, ...)          # configure IPsec SA + policy
  → send crafted ESP packet
    → xfrm_input()
      → esp_input_done2()
        → sk_buff frag → page-cache page of /etc/passwd
          → decryption output written to frag
            → page cache of /etc/passwd modified
              → su root ✓
```

**CVE-2026-43500** same sink, no namespace required.  
Triggers via `rxrpc_recvmsg()` if `rxrpc.ko` is loaded (Ubuntu default).

---

## Official mitigation

```bash
sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' \
  > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc 2>/dev/null; true"
```

Side effects: disables IPsec ESP transport (esp4/esp6) and AFS/RxRPC (rxrpc).

---

## dirtyfrag_hunt.py checks

| Check | CVE | What it detects |
|---|---|---|
| `kernel-version` | BOTH | Version vs vulnerable commit windows (4.9 / 6.4 / 6.15) |
| `esp-module` | CVE-2026-43284 | esp4/esp6 loaded and not blacklisted |
| `rxrpc-module` | CVE-2026-43500 | rxrpc.ko loaded and not blacklisted |
| `userns` | CVE-2026-43284 | Unprivileged namespace open / AppArmor restriction state |
| `modprobe-config` | BOTH | `/etc/modprobe.d/dirtyfrag.conf` presence and completeness |
| `proc-hunt` | BOTH | Active xfrm policies, rxrpc in `/proc/net/protocols`, xfrm_stat counters |
| `auditd-hunt` | BOTH | Recent unshare / AF_KEY socket / `/etc/passwd` write events (root) |

Exit code `1` if any finding is `VULN` suitable for monitoring pipelines.

---

## dirtyfrag.yml Sigma rules

| Rule | Title | Level |
|---|---|---|
| `dirtyfrag0001` | Unprivileged user namespace creation (`unshare`) | medium |
| `dirtyfrag0002` | `AF_KEY` socket created by non-root process | high |
| `dirtyfrag0003` | `AF_RXRPC` socket created (unexpected) | high |
| `dirtyfrag0004` | Write to `/etc/passwd` or `/etc/shadow` by non-root | critical |
| `dirtyfrag0005` | Full exploitation chain correlation (SIEM temporal) | critical |
| `dirtyfrag0006` | Vulnerable module loaded at runtime | high |

---

## dirtyfrag.yar YARA rules

| Rule | Scope | What it matches |
|---|---|---|
| `DirtyFrag_PoC_Source_V4bel` | file | Original `exp.c` source on disk |
| `DirtyFrag_PoC_Compiled_ELF` | file | Compiled ELF binary built from PoC |
| `DirtyFrag_PoC_InMemory` | memory | PoC strings in process address space |
| `Linux_PageCache_Write_Exploit_Generic` | file/memory | Broader page-cache write class (DirtyFrag / Copy Fail / Dirty Pipe) |
| `DirtyFrag_Mitigation_Tamper` | file | Scripts removing `dirtyfrag.conf` or force-loading blocked modules |

---

## References

- [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag) original PoC and write-up
- [oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/05/07/8) 2026-05-07
- CVE-2026-43284 xfrm-ESP · patch: `f4c50a4034e6` (mainline only)
- CVE-2026-43500 RxRPC · reserved · no patch (2026-05-10)
- [Dirty Pipe (CVE-2022-0847)](https://dirtypipe.cm4all.com/) bug class ancestor
- [Copy Fail](https://copy.fail/) same xfrm sink, earlier variant
- xfrm vulnerable commit: `cac2661c53f3` (2017-01-17)
- rxrpc vulnerable commit: `2dc334f1a63a` (2023-06)
