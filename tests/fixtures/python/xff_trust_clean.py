"""
Safe counterpart to xff_trust_vuln.py: the allowlist decision is made on
the real socket peer address, and a dict that SETS the forwarding header
(an outbound HTTP client building its own request) is not a read of it.
"""

TRUSTED_IPS = ["127.0.0.1"]


def check_peer(remote_addr):
    return remote_addr in TRUSTED_IPS


def build_outbound_headers(ip_address):
    return {"X-Forwarded-For": ip_address}  # safe: Weak Auth Logic
