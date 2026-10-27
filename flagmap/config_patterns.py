"""
config_patterns.py — misconfiguration pattern database for flagmap's config
scanner (Dockerfiles, docker-compose, nginx/apache, .env, vsftpd.conf,
redis.conf, my.cnf, php.ini, sshd_config, Kubernetes manifests).

Each category maps to a list of (name, severity, regex, why, fix, confidence)
tuples, matched line-by-line — same shape as the source-code patterns, but
for config files instead of code.
"""

import re

# name, severity, raw_regex, why, fix, confidence
LINE_CHECKS_RAW = {

    "dockerfile": [
        (
            "Container Downloads-and-Executes Remote Script",
            "high",
            r"""curl[^|]*\|\s*(?:sh|bash)|wget[^|]*\|\s*(?:sh|bash)""",
            "A remote script is piped straight into a shell during the build — if that URL/host is ever "
            "compromised or MITM'd, it's arbitrary code execution in the image.",
            "Download the script, pin it by checksum, review it, then COPY + RUN it instead of piping directly.",
            "likely",
        ),
        (
            "ADD Used to Fetch a Remote URL",
            "low",
            r"""^\s*ADD\s+https?://""",
            "ADD can fetch and auto-extract a remote URL — prefer COPY for local files and explicit curl/wget "
            "(with checksum verification) for remote ones, so the build is auditable.",
            "Replace with a pinned, checksum-verified download step, or COPY a vetted local file.",
            "possible",
        ),
        (
            "Hardcoded Secret in Dockerfile",
            "high",
            r"""^\s*ENV\s+\w*(?:PASSWORD|SECRET|API_?KEY|TOKEN|PRIVATE_?KEY)\w*[=\s]\s*(?!\$)\S+""",
            "A credential/secret is baked into the image via ENV — it persists in the image layers and "
            "`docker history`, readable by anyone with image access.",
            "Pass secrets at runtime (--env-file, Docker/K8s secrets) instead of baking them into the image.",
            "likely",
        ),
        (
            "World-Writable Permissions in Build",
            "medium",
            r"""chmod\s+(?:-R\s+)?777""",
            "chmod 777 makes files/directories world-writable — if this path is reachable (e.g. via an "
            "upload or included in a volume), any process/user can tamper with it.",
            "Use the narrowest permission that works (e.g. 755 for dirs, 644 for files).",
            "possible",
        ),
        (
            "Unpinned Base Image Tag",
            "low",
            r"""^\s*FROM\s+[\w./-]+(?::latest)?\s*$""",
            "Base image has no pinned version (or uses :latest) — the build isn't reproducible and may "
            "silently pick up a different (possibly vulnerable) image over time.",
            "Pin to a specific tag or digest, e.g. `FROM python:3.12.4-slim@sha256:...`.",
            "possible",
        ),
    ],

    "compose": [
        (
            "Privileged Container",
            "high",
            r"""privileged\s*:\s*true""",
            "This container runs with --privileged, giving it near-full access to the host (devices, kernel "
            "capabilities) — a container escape here is a host compromise.",
            "Drop privileged mode; grant only the specific capabilities actually needed via cap_add.",
            "likely",
        ),
        (
            "Docker Socket Mounted Into Container",
            "high",
            r"""[\"']?/var/run/docker\.sock[\"']?\s*:""",
            "The host's Docker socket is mounted into the container — code execution inside this container "
            "can usually spin up a new privileged container and fully escape to the host.",
            "Avoid mounting the Docker socket; use a dedicated, access-controlled Docker API proxy if the "
            "container genuinely needs to manage containers.",
            "likely",
        ),
        (
            "Host Network Mode",
            "medium",
            r"""network_mode\s*:\s*[\"']?host""",
            "The container shares the host's network namespace, bypassing normal container network isolation.",
            "Use a dedicated bridge network and explicit port mappings instead of host networking.",
            "likely",
        ),
        (
            "Dangerous Linux Capability Added",
            "high",
            r"""cap_add\s*:\s*\[?\s*[\"']?(?:ALL|SYS_ADMIN|SYS_PTRACE|SYS_MODULE)[\"']?""",
            "A powerful Linux capability is added to the container — several of these (SYS_ADMIN especially) "
            "are well-known container-escape primitives.",
            "Only add the minimum capability actually required, never ALL/SYS_ADMIN unless unavoidable.",
            "likely",
        ),
        (
            "Database/Admin Port Published Publicly",
            "medium",
            r"""^\s*-\s*[\"']?(?:0\.0\.0\.0:)?(?:3306|5432|6379|27017|9200|5984|2375|2376):\d+[\"']?""",
            "An internal service port (DB, Redis, Docker API, etc.) is published to the host's network "
            "interface rather than kept internal to the compose network.",
            "Remove the published ports mapping (or bind to 127.0.0.1 only) and let services talk over the "
            "internal compose network.",
            "possible",
        ),
        (
            "Hardcoded Secret in Compose File",
            "medium",
            r"""(?:PASSWORD|SECRET|API_?KEY|TOKEN|PRIVATE_?KEY)\s*[:=]\s*(?!\$\{|["']?\s*$)\S+""",
            "A credential appears to be hardcoded directly in the compose file rather than sourced from an "
            "env file or secret manager.",
            "Reference secrets via `${VAR}` interpolation + a .env file (kept out of git), or Docker secrets.",
            "possible",
        ),
    ],

    "nginx": [
        (
            "Directory Listing Enabled",
            "medium",
            r"""autoindex\s+on""",
            "autoindex is on — any directory without an index file will list its full contents to visitors, "
            "potentially exposing source files, backups, or uploaded content.",
            "Remove `autoindex on;` (it's off by default) unless directory listing is genuinely intended.",
            "likely",
        ),
        (
            "Server Version Disclosure",
            "low",
            r"""server_tokens\s+on""",
            "Nginx will include its exact version in the Server header and default error pages, helping an "
            "attacker fingerprint known CVEs for that version.",
            "Set `server_tokens off;`.",
            "likely",
        ),
        (
            "Alias Misconfiguration Risk",
            "low",
            r"""^\s*alias\s+\S+""",
            "`alias` directives are a common source of path traversal bugs when the matching `location` "
            "block's trailing slash doesn't line up with the alias path — double check this pairing.",
            "Confirm the location block ends in '/' matching the alias path, or use `root` instead where possible.",
            "possible",
        ),
        (
            "Serving From Filesystem Root",
            "medium",
            r"""^\s*root\s+/\s*;""",
            "Document root is set to '/' — this can expose the entire filesystem to path traversal if any "
            "location block's path isn't fully constrained.",
            "Point root at a dedicated web directory, never '/'.",
            "possible",
        ),
    ],

    "apache": [
        (
            "Directory Listing Enabled",
            "medium",
            r"""Options\s+(?:[+]?Indexes|.*\bIndexes\b)""",
            "Options Indexes is set — directories without an index file will list their full contents.",
            "Remove 'Indexes' from the Options directive (use '-Indexes' to explicitly disable).",
            "likely",
        ),
        (
            "AllowOverride All",
            "low",
            r"""AllowOverride\s+All""",
            "AllowOverride All lets any .htaccess file in the tree override server config — if an attacker "
            "can write a file into this tree (e.g. via upload), they may be able to reconfigure request handling.",
            "Set AllowOverride to only the specific directive types actually needed (e.g. 'AuthConfig').",
            "possible",
        ),
        (
            "Unrestricted Access Granted",
            "low",
            r"""Require\s+all\s+granted""",
            "This block grants unrestricted access — confirm this directory is meant to be fully public.",
            "Scope access with IP/auth restrictions if this directory shouldn't be world-readable.",
            "possible",
        ),
        (
            "Dangerous AddType in Apache Config",
            "high",
            r"""AddType\s+application/x-httpd-php\s+\.(?:jpg|jpeg|png|gif|txt|svg)\b""",
            "Apache is configured to execute uploaded image/text files as PHP — combined with any image/file "
            "upload feature (even one with a correct extension allowlist), this is a direct path to RCE.",
            "Remove the AddType line; serve uploads from a directory with PHP execution disabled "
            "(`php_flag engine off` or a separate static-only vhost).",
            "likely",
        ),
    ],

    "env": [
        (
            "Hardcoded Secret in .env",
            "high",
            r"""^(?!.*(?:EXPIRE|EXPIRY|MINUTES|TTL|DURATION|TIMEOUT))\s*(?:export\s+)?\w*(?:PASSWORD|SECRET|API_?KEY|TOKEN|PRIVATE_?KEY|CREDENTIAL)\w*\s*=\s*\S+""",
            ".env files are frequently committed by accident — if this repo/image ships with this file, the "
            "credential is exposed to anyone with access to it.",
            "Confirm .env is git-ignored and never baked into a shipped image; rotate this credential if exposed.",
            "likely",
        ),
        (
            "Debug Mode Enabled",
            "medium",
            r"""^\s*(?:export\s+)?(?:APP_DEBUG|DEBUG|FLASK_DEBUG)\s*=\s*["']?(?:true|1|on)["']?\s*$""",
            "Debug mode is enabled via environment variable — this typically leaks stack traces and internal "
            "paths, and for Flask specifically can expose the interactive debugger (RCE risk).",
            "Set debug mode off in any environment reachable by untrusted users.",
            "likely",
        ),
        (
            "Wildcard Allowed Hosts/Origins",
            "medium",
            r"""^\s*(?:export\s+)?(?:ALLOWED_HOSTS|CORS_ORIGIN)\s*=\s*["']?\*?["']?\s*$""",
            "Allowed hosts/origins is wildcarded — combined with credentialed requests this can enable "
            "cross-origin attacks or host header based cache poisoning.",
            "Set this to an explicit allowlist of real hostnames/origins.",
            "possible",
        ),
    ],

    "ftp": [
        (
            "Anonymous FTP Login Enabled",
            "medium",
            r"""^\s*anonymous_enable\s*=\s*YES""",
            "Anonymous FTP logins are allowed — combined with write access or a readable sensitive "
            "directory, this is a common way for a flag/file to be reachable without any credentials.",
            "Disable anonymous_enable unless public anonymous access is genuinely intended.",
            "likely",
        ),
    ],

    "redis": [
        (
            "Redis Bound to All Interfaces",
            "medium",
            r"""^\s*bind\s+0\.0\.0\.0""",
            "Redis is listening on all network interfaces rather than just localhost — if this instance has "
            "no auth, it's reachable from anywhere on the network.",
            "Bind to 127.0.0.1 unless remote access is genuinely required, and always set a requirepass.",
            "likely",
        ),
        (
            "Redis Protected Mode Disabled",
            "high",
            r"""^\s*protected-mode\s+no""",
            "Protected mode is explicitly disabled — Redis will accept connections from any reachable host "
            "even with no authentication configured.",
            "Re-enable protected-mode, or better, set a strong requirepass and bind to localhost.",
            "likely",
        ),
    ],

    "mysql": [
        (
            "MySQL Authentication Bypass Flag Set",
            "high",
            r"""^\s*skip-grant-tables""",
            "skip-grant-tables disables MySQL's privilege system entirely — any connection can act as root "
            "with no password.",
            "Remove this flag outside of a one-time password-reset procedure; never leave it set in a running service.",
            "likely",
        ),
        (
            "MySQL Bound to All Interfaces",
            "medium",
            r"""^\s*bind-address\s*=\s*0\.0\.0\.0""",
            "MySQL is listening on all network interfaces — confirm this is intended and that strong "
            "credentials are enforced.",
            "Bind to 127.0.0.1 or a specific internal interface unless remote access is required.",
            "possible",
        ),
    ],

    "php_ini": [
        (
            "Remote File Inclusion Enabled",
            "high",
            r"""^\s*allow_url_include\s*=\s*On""",
            "allow_url_include lets include()/require() load a REMOTE URL as PHP code — combined with any "
            "LFI, this upgrades straight to Remote Code Execution.",
            "If an LFI exists elsewhere, try include-ing a remote PHP payload via http(s):// or data://.",
            "likely",
        ),
        (
            "Remote URL fopen Wrappers Enabled",
            "low",
            r"""^\s*allow_url_fopen\s*=\s*On""",
            "allow_url_fopen lets file functions (fopen, file_get_contents, include) treat a URL as a file — "
            "widens the blast radius of any LFI/SSRF-adjacent bug.",
            "Disable unless the app genuinely needs to fetch remote resources this way.",
            "possible",
        ),
        (
            "Error Display Enabled",
            "medium",
            r"""^\s*display_errors\s*=\s*On""",
            "PHP errors/warnings (often containing file paths, query fragments, or stack traces) are printed "
            "straight into responses.",
            "Trigger a PHP error/warning with bad input and read the leaked path/query info.",
            "possible",
        ),
        (
            "PHP Version Disclosure",
            "low",
            r"""^\s*expose_php\s*=\s*On""",
            "PHP adds an X-Powered-By header revealing its exact version, helping fingerprint known CVEs.",
            "Set expose_php = Off.",
            "possible",
        ),
        (
            "register_globals Enabled (legacy, severe)",
            "high",
            r"""^\s*register_globals\s*=\s*On""",
            "register_globals auto-creates variables from request parameters — ancient PHP behavior that "
            "enables trivial variable-overwrite and auth-bypass attacks across the whole app.",
            "This should never be on in any modern deployment; if found, assume the whole app's variable "
            "handling is suspect.",
            "likely",
        ),
    ],

    "sshd": [
        (
            "Root Login Permitted Over SSH",
            "medium",
            r"""^\s*PermitRootLogin\s+yes""",
            "Root login over SSH is allowed — removes a layer of defense (requiring privilege escalation "
            "after an initial foothold) if root credentials or keys are ever compromised.",
            "Set PermitRootLogin to 'no' or 'prohibit-password', and use sudo for privileged actions.",
            "possible",
        ),
        (
            "Empty Passwords Permitted",
            "high",
            r"""^\s*PermitEmptyPasswords\s+yes""",
            "SSH will accept an empty password for any account configured with one — trivial unauthenticated access.",
            "Set PermitEmptyPasswords to 'no'.",
            "likely",
        ),
    ],

    "k8s": [
        (
            "Privileged Pod/Container",
            "high",
            r"""privileged\s*:\s*true""",
            "This pod/container runs privileged, with near-full access to the host node — a compromise here "
            "likely means a node (and possibly cluster) compromise.",
            "Remove privileged: true; grant only the specific capabilities actually needed.",
            "likely",
        ),
        (
            "Host Network/PID Namespace Shared",
            "medium",
            r"""host(?:Network|PID)\s*:\s*true""",
            "The pod shares the host's network or PID namespace, breaking container isolation from the node.",
            "Remove hostNetwork/hostPID unless there's a specific, reviewed reason to share the host namespace.",
            "likely",
        ),
        (
            "Privilege Escalation Allowed",
            "medium",
            r"""allowPrivilegeEscalation\s*:\s*true""",
            "The container can gain more privileges than its parent process (e.g. via setuid binaries).",
            "Set allowPrivilegeEscalation: false unless a specific workload requires it.",
            "possible",
        ),
        (
            "Docker Socket Mounted as hostPath",
            "high",
            r"""path\s*:\s*[\"']?/var/run/docker\.sock[\"']?""",
            "The host's Docker socket is mounted into the pod — typically allows full container/host escape.",
            "Avoid mounting the Docker socket into workloads; use a scoped, access-controlled alternative if needed.",
            "likely",
        ),
    ],

    # Shell scripts used to provision/launch infra (entrypoints, bootstrap scripts).
    # Not "source code" in the app-logic sense, but the kind of dev/debug flag
    # that ends up shipped to a real deployment by accident.
    "shell_script": [
        (
            "Vault Running in Dev Mode",
            "high",
            r"""vault\s+server\s+(?:[^\n]*\s)?-dev\b""",
            "HashiCorp Vault's -dev mode auto-unseals and uses a well-known, logged root token meant only for "
            "local testing — anyone who can read the startup logs (or knows the default dev root token "
            "format) gets full admin access to every secret in this Vault instance.",
            "Never run `vault server -dev` outside of local development; use a real storage backend with "
            "proper unseal keys and an auth method other than the dev root token.",
            "likely",
        ),
        (
            "Service Started in Debug/Insecure Mode",
            "medium",
            r"""redis-server[^\n]*--protected-mode\s+no|mongod[^\n]*--noauth""",
            "A backing service is explicitly started with its protection/auth disabled via a startup flag.",
            "Remove the flag; set up real authentication for this service instead.",
            "possible",
        ),
    ],
}


def compiled_line_checks():
    """Return LINE_CHECKS_RAW with regexes compiled."""
    compiled = {}
    for category, rules in LINE_CHECKS_RAW.items():
        compiled[category] = [
            {
                "name": name,
                "severity": severity,
                "regex": re.compile(pattern, re.IGNORECASE),
                "why": why,
                "fix": fix,
                "confidence": confidence,
            }
            for name, severity, pattern, why, fix, confidence in rules
        ]
    return compiled
