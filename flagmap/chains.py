"""
chains.py — correlates the findings from a single scan into likely attack
chains.

A flat list of findings tells you "this line is a bug." Under CTF time
pressure the real question is usually "which two of these bugs next to each
other are actually the intended path to the flag" — reasoning a player
normally has to do by eye after reading the report. Every rule here is a
plain co-occurrence check over the Finding objects a scan already produced;
nothing in this module does new scanning, parsing, or taint tracking, so it's
only as good as the findings feeding it — treat a chain the same way you'd
treat any other "possible" flagmap finding: a strong hint of where to look
first, not a guarantee the path is real.
"""

from dataclasses import dataclass
from typing import List

from .scanner import Finding


@dataclass
class Chain:
    name: str
    severity: str
    steps: str
    why: str
    findings: List[Finding]  # one representative finding per matched group


def _find(findings: List[Finding], *name_substrings: str) -> List[Finding]:
    """Findings whose vuln_name contains any of the given substrings (case-insensitive)."""
    out = []
    for f in findings:
        name = f.vuln_name.lower()
        if any(s.lower() in name for s in name_substrings):
            out.append(f)
    return out


def find_chains(findings: List[Finding]) -> List[Chain]:
    chains: List[Chain] = []

    def add(name, severity, steps, why, *finding_groups):
        picked = []
        for group in finding_groups:
            if not group:
                return  # a required ingredient is missing; this chain doesn't apply here
            picked.append(group[0])
        chains.append(Chain(name=name, severity=severity, steps=steps, why=why, findings=picked))

    upload = _find(findings, "Unrestricted File Upload")
    addtype = _find(findings, "Dangerous AddType")
    root_container = _find(findings, "Container Runs as Root")
    cmd_exec = _find(findings, "Command Injection", "Command Injection / RCE")
    deser = _find(findings, "Unsafe Deserialization")
    ssti = _find(findings, "Server-Side Template Injection")
    sqli = _find(findings, "SQL Injection")
    weak_crypto = _find(findings, "Weak Cryptography")
    lfi = _find(findings, "Path Traversal / LFI", "Zip Slip")
    rfi_cfg = _find(findings, "Remote File Inclusion Enabled")
    ssrf = _find(findings, "SSRF")
    redis_open = _find(findings, "Redis Protected Mode Disabled", "Redis Bound to All Interfaces",
                        "Redis Has No Authentication")
    secret_cfg = _find(findings, "Hardcoded Secret in Compose File", "Hardcoded Secret in Dockerfile",
                        "Hardcoded Secret in .env")
    docker_socket = _find(findings, "Docker Socket Mounted")
    jwt_weak = _find(findings, "JWT / Auth Token Weakness")
    mass_assign = _find(findings, "Mass Assignment")
    session_tok = _find(findings, "Insecure Session Token")
    proto_poll = _find(findings, "Prototype Pollution")
    csrf = _find(findings, "Missing CSRF Protection")
    ftp_write = _find(findings, "Anonymous FTP With Write Access")

    add(
        "Upload -> Apache AddType -> RCE", "high",
        "Upload a file with the flagged extension -> Apache executes it as PHP -> shell",
        "The upload endpoint accepts files with no server-side execution restriction, and the Apache config "
        "will run that extension as PHP. Together these aren't two separate issues — they're a direct path "
        "to RCE.",
        upload, addtype,
    )

    add(
        "Command Exec -> Root Container -> Full Container Control", "high",
        "Trigger the command/RCE bug -> you're already root inside the container",
        "A command-execution bug combined with a container that runs as root means any RCE here lands as "
        "root immediately — no local privilege-escalation step needed before pivoting further (mounted "
        "volumes, the Docker socket, etc.).",
        cmd_exec, root_container,
    )

    add(
        "Deserialization RCE -> Root Container", "high",
        "Trigger the deserialization gadget chain -> RCE lands as root",
        "Same reasoning as the command-exec chain, specifically for the deserialization bug: once the "
        "gadget chain executes, there's no privilege-escalation step left to do.",
        deser, root_container,
    )

    add(
        "SSTI -> Root Container", "high",
        "Trigger the template injection -> RCE lands as root",
        "A template-injection RCE in a container that already runs as root skips straight to full container "
        "control.",
        ssti, root_container,
    )

    add(
        "SQLi -> Dump Weak-Hashed Credentials -> Crack Offline", "medium",
        "Use the SQLi to dump the users table -> crack the weak hashes -> log in as that user",
        "The SQL injection gives you the password-hash column; the weak-hashing finding means those hashes "
        "(MD5/SHA-1) are cheap to crack offline rather than needing a second bug to get credentials.",
        sqli, weak_crypto,
    )

    add(
        "LFI -> allow_url_include -> RFI/RCE", "high",
        "Use the traversal bug to include a remote URL instead of a local file -> RCE",
        "A local file include is normally 'just' a read primitive, but php.ini's allow_url_include turns the "
        "exact same bug into remote code execution by including an attacker-hosted PHP payload instead of a "
        "local path.",
        lfi, rfi_cfg,
    )

    add(
        "SSRF -> Open Redis -> Internal Compromise", "high",
        "Point the SSRF at the Redis port -> speak to it directly (e.g. via gopher://) -> write a webshell "
        "or cron job through Redis",
        "SSRF alone just reaches internal services; an unauthenticated/under-protected Redis instance behind "
        "that SSRF is itself a well-known RCE primitive (CONFIG SET dir/dbfilename + a crafted value).",
        ssrf, redis_open,
    )

    add(
        "SSRF -> Leak Baked-In Secrets", "medium",
        "Point the SSRF at the app's own internals (or a cloud metadata endpoint, if hosted) -> recover the "
        "hardcoded credential",
        "Combine the SSRF with the hardcoded secret found in the Dockerfile/compose/.env — an SSRF that can "
        "reach the app's own config surface may be able to read or escalate using that same secret.",
        ssrf, secret_cfg,
    )

    add(
        "Docker Socket Mounted -> Any Code Execution -> Full Host Takeover", "high",
        "Trigger any code-execution primitive -> use the mounted Docker socket to spin up a privileged "
        "container -> host escape",
        "A mounted Docker socket turns ANY code-execution bug in this app into full host compromise — no "
        "container-escape CVE needed, just a privileged `docker run` through the socket.",
        docker_socket, cmd_exec,
    )

    add(
        "Weak JWT -> Mass Assignment -> Privilege Escalation", "high",
        "Forge/bypass the JWT to authenticate as any user -> use mass assignment to set an admin/role field "
        "on your own account",
        "The JWT weakness gets you an authenticated session as anyone; the mass-assignment bug then lets "
        "that session upgrade itself by sending an extra field (e.g. `role`/`admin`) the app shouldn't have "
        "trusted.",
        jwt_weak, mass_assign,
    )

    add(
        "Forged Session Token -> Mass Assignment -> Privilege Escalation", "high",
        "Forge a session for any username (base64-only token) -> mass-assign a privileged field",
        "Same escalation path as the JWT chain above, via the insecure-session-token finding instead.",
        session_tok, mass_assign,
    )

    add(
        "Prototype Pollution -> Command Exec / Deserialization Gadget -> RCE", "high",
        "Pollute Object.prototype with a property the app's command/deserialization path reads -> escalate "
        "to RCE",
        "Prototype pollution is rarely the end of the chain by itself — paired with a reachable command-exec "
        "or deserialization sink elsewhere in the app, a polluted property can escalate it to full RCE.",
        proto_poll, cmd_exec,
    )

    add(
        "Anonymous Writable FTP -> Drop a Webshell", "high",
        "Upload a webshell over anonymous FTP -> if the FTP root overlaps the web root, browse to it",
        "Anonymous FTP with write access is a direct file-write primitive; combined with other evidence this "
        "app serves uploaded content, the FTP root may double as (or overlap) the web root.",
        ftp_write, upload,
    )

    add(
        "Missing CSRF -> Weak Auth -> Cross-Site Account Takeover", "medium",
        "Host an auto-submitting form targeting a state-changing endpoint -> the forgeable auth scheme makes "
        "riding the victim's session easy",
        "Missing CSRF protection is low-value alone when auth is solid, but combined with a weak/forgeable "
        "auth scheme it becomes a practical account-takeover path, not just a theoretical gap.",
        csrf, jwt_weak,
    )

    return chains
