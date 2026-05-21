/*
 * dirtyfrag.yar — YARA Detection Rules
 * CVE-2026-43284 (xfrm-ESP) + CVE-2026-43500 (RxRPC)
 *
 * Author  : blacksunCUBE 
 * Date    : 2026-05-10
 * Repo    : https://github.com/blacksunCUBE/Dirty-Frag-hunting
 * Ref     : https://github.com/V4bel/dirtyfrag
 *
 * Usage:
 *   yara -r dirtyfrag.yar /tmp /home /dev/shm
 *   yara -r dirtyfrag.yar /proc/<pid>/exe   (memory scanning)
 *   yara dirtyfrag.yar suspicious_binary
 */


/* ─────────────────────────────────────────────────────────────────────────────
 * Rule 1: V4bel/dirtyfrag original PoC source (exp.c on disk)
 *
 * Matches the original C exploit source from the public repository.
 * Looks for function names and string literals unique to that file.
 * High specificity — very low FP rate.
 * ───────────────────────────────────────────────────────────────────────────*/
rule DirtyFrag_PoC_Source_V4bel
{
    meta:
        description    = "Detects V4bel/dirtyfrag original PoC source code (exp.c)"
        author         = "blacksunCUBE"
        date           = "2026-05-10"
        reference      = "https://github.com/V4bel/dirtyfrag"
        cve            = "CVE-2026-43284, CVE-2026-43500"
        severity       = "critical"
        tlp            = "white"

    strings:
        /* Function names unique to the PoC */
        $fn1 = "setup_xfrm_sa"          ascii
        $fn2 = "trigger_esp_write"       ascii
        $fn3 = "setup_rxrpc_socket"      ascii
        $fn4 = "trigger_rxrpc_write"     ascii
        $fn5 = "overwrite_passwd"        ascii

        /* String literals from the PoC */
        $s1  = "dirtyfrag"              ascii wide
        $s2  = "CVE-2026-43284"         ascii
        $s3  = "CVE-2026-43500"         ascii
        $s4  = "esp_input_done2"        ascii
        $s5  = "rxrpc_recvmsg"          ascii

        /* xfrm-specific constants/paths used in the exploit */
        $x1  = "AF_KEY"                 ascii
        $x2  = "XFRM_MODE_TRANSPORT"    ascii
        $x3  = "IPPROTO_ESP"            ascii

        /* rxrpc-specific */
        $r1  = "AF_RXRPC"              ascii
        $r2  = "SOCK_SEQPACKET"        ascii

        /* Comment strings from the original PoC */
        $c1  = "page cache write"       ascii nocase
        $c2  = "sk_buff"               ascii
        $c3  = "skb_frag"              ascii

    condition:
        /* Source file: any 3 function names, or 2 CVE strings + 2 xfrm/rxrpc strings */
        (3 of ($fn*))
        or (2 of ($s1, $s2, $s3) and 2 of ($x*, $r*))
        or (all of ($s2, $s3) and any of ($fn*))
}


/* ─────────────────────────────────────────────────────────────────────────────
 * Rule 2: DirtyFrag compiled binary (ELF)
 *
 * Matches a compiled Linux ELF binary built from the PoC source.
 * Targets remnant strings that survive compilation.
 * ───────────────────────────────────────────────────────────────────────────*/
rule DirtyFrag_PoC_Compiled_ELF
{
    meta:
        description = "Detects compiled DirtyFrag PoC ELF binary"
        author      = "blacksunCUBE"
        date        = "2026-05-10"
        reference   = "https://github.com/V4bel/dirtyfrag"
        cve         = "CVE-2026-43284, CVE-2026-43500"
        severity    = "critical"

    strings:
        /* ELF magic */
        $elf = { 7F 45 4C 46 }

        /* Strings that survive compilation into the binary */
        $b1 = "dirtyfrag"          ascii
        $b2 = "esp_input_done2"    ascii
        $b3 = "rxrpc_recvmsg"      ascii
        $b4 = "CVE-2026-43284"     ascii
        $b5 = "CVE-2026-43500"     ascii
        $b6 = "/etc/passwd"        ascii
        $b7 = "XFRM_MODE"         ascii
        $b8 = "AF_RXRPC"          ascii

        /* xfrm SA structure markers that end up in binary data sections */
        $b9  = "IPPROTO_ESP"      ascii
        $b10 = "AF_KEY"           ascii

    condition:
        $elf at 0
        and filesize < 5MB
        and (
            ($b1 and any of ($b2, $b3))
            or ($b4 and $b5)
            or (2 of ($b2, $b3, $b7, $b8, $b9) and $b6)
        )
}


/* ─────────────────────────────────────────────────────────────────────────────
 * Rule 3: DirtyFrag PoC in memory (process memory scan)
 *
 * For use with: yara dirtyfrag.yar /proc/<pid>/mem
 * or via a memory forensics framework (Volatility, AVML dump).
 * Detects the PoC running in process address space.
 * ───────────────────────────────────────────────────────────────────────────*/
rule DirtyFrag_PoC_InMemory
{
    meta:
        description = "Detects DirtyFrag PoC strings in process memory"
        author      = "blacksunCUBE"
        date        = "2026-05-10"
        cve         = "CVE-2026-43284, CVE-2026-43500"
        severity    = "critical"
        scope       = "memory"

    strings:
        $m1 = "dirtyfrag"         ascii wide
        $m2 = "esp_input_done2"   ascii
        $m3 = "rxrpc_recvmsg"     ascii
        $m4 = "CVE-2026-43284"    ascii
        $m5 = "CVE-2026-43500"    ascii
        $m6 = "/etc/passwd"       ascii

        /* xfrm SA setup syscall sequence markers */
        $m7 = "XFRM_MSG_NEWSA"   ascii
        $m8 = "XFRM_MSG_NEWPOLICY" ascii

    condition:
        ($m1 and any of ($m2, $m3))
        or ($m4 and $m5)
        or (any of ($m7, $m8) and $m6 and any of ($m1, $m4, $m5))
}


/* ─────────────────────────────────────────────────────────────────────────────
 * Rule 4: Generic page-cache write exploit pattern
 *
 * Broader rule targeting the page-cache write bug class:
 * DirtyFrag, Copy Fail, Dirty Pipe variants.
 * Higher FP rate — use for hunting, not alerting.
 * ───────────────────────────────────────────────────────────────────────────*/
rule Linux_PageCache_Write_Exploit_Generic
{
    meta:
        description = "Generic detection for Linux page-cache write exploit class (DirtyFrag / Copy Fail / Dirty Pipe variants)"
        author      = "blacksunCUBE"
        date        = "2026-05-10"
        cve         = "CVE-2026-43284, CVE-2026-43500, CVE-2022-0847"
        severity    = "high"
        fp_rate     = "medium — tune for environment"

    strings:
        /* Common to all variants */
        $p1 = "page cache"         ascii nocase
        $p2 = "sk_buff"           ascii
        $p3 = "skb_frag"          ascii
        $p4 = "dirty pipe"        ascii nocase
        $p5 = "copy fail"         ascii nocase

        /* Privilege escalation markers */
        $e1 = "/etc/passwd"       ascii
        $e2 = "/etc/shadow"       ascii
        $e3 = "su root"           ascii
        $e4 = "overwrite"         ascii nocase

        /* xfrm / rxrpc subsystem strings */
        $k1 = "xfrm_input"       ascii
        $k2 = "esp_input"        ascii
        $k3 = "rxrpc"            ascii
        $k4 = "CLONE_NEWUSER"    ascii
        $k5 = "unshare"          ascii

    condition:
        /* Exploit source: subsystem string + passwd target */
        (any of ($k*) and any of ($e1, $e2))
        /* Or: page-cache write class + LPE indicators */
        or (any of ($p1, $p2, $p3) and any of ($p4, $p5) and any of ($e*))
        /* Or: all three exploitation components together */
        or (any of ($k1, $k2, $k3) and $k4 and $e1)
}


/* ─────────────────────────────────────────────────────────────────────────────
 * Rule 5: DirtyFrag mitigation tampering
 *
 * Detects scripts or configs that remove the dirtyfrag.conf blacklist
 * or explicitly load the blocked modules.
 * ───────────────────────────────────────────────────────────────────────────*/
rule DirtyFrag_Mitigation_Tamper
{
    meta:
        description = "Detects attempts to remove the DirtyFrag modprobe.d mitigation or force-load blocked modules"
        author      = "blacksunCUBE"
        date        = "2026-05-10"
        cve         = "CVE-2026-43284, CVE-2026-43500"
        severity    = "high"

    strings:
        $conf = "dirtyfrag.conf"  ascii

        /* rm or overwrite of the config */
        $rm1 = "rm " ascii
        $rm2 = "unlink" ascii
        $rm3 = "> /etc/modprobe.d/dirtyfrag.conf" ascii

        /* Force-loading blocked modules */
        $fl1 = "modprobe -f esp4"   ascii
        $fl2 = "modprobe -f esp6"   ascii
        $fl3 = "modprobe -f rxrpc"  ascii
        $fl4 = "insmod esp4"        ascii
        $fl5 = "insmod esp6"        ascii
        $fl6 = "insmod rxrpc"       ascii

        /* Editing the blacklist to remove entries */
        $ed1 = "sed" ascii
        $ed2 = "/bin/false" ascii

    condition:
        ($conf and any of ($rm1, $rm2, $rm3))
        or any of ($fl1, $fl2, $fl3, $fl4, $fl5, $fl6)
        or ($conf and $ed1 and $ed2)
}
