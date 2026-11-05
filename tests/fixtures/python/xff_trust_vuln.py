"""
Fixture for xff_trust_guard.py (v1.36.0), Python side. Mirrors
DownUnderCTF 2025's real "sodium" rpc_service allowlist check: the client
IP comes from the forwarding header and is checked for membership in an
allowlist of IPs.
"""

AUTHORIZED_IPS = ["127.0.0.1"]


def handle_request(headers):
    forwarded_for = headers.get("x-forwarded-for", "").strip()  # ruleid: Weak Auth Logic
    if forwarded_for not in AUTHORIZED_IPS:
        return 403
    return 200
