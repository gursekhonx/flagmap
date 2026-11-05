"""
Python class pollution (v1.29.0) — a standalone fixture rather than an
addition to vuln_sinks.py/clean_sinks.py, because class_pollution_guard.py
collects its two signals across the WHOLE file's text, not one line:
a dict-iteration loop binding two names, and an attribute-setting call
later in the file using those exact two names as the attribute name and
value. Mirrors the real DownUnderCTF 2024 "co2"/"co2v2" web challenges'
shared merge helper almost verbatim — a hand-rolled recursive merge with
no denylist on dunder attribute names, letting a payload walk through
the destination object's own class and its constructor's globals to
overwrite an unrelated module-level variable.
"""


def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)  # ruleid: Prototype Pollution
