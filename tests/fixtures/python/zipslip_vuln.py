"""
Zip Slip (v1.27.0) — a standalone fixture rather than an addition to
vuln_sinks.py/clean_sinks.py, because zipslip_guard.py's signals (zip
member filename var, os.path.join with it, a write sink, absence of a
real containment check) are collected across the WHOLE file's text, not
one line — mixing this into a file already full of other open()/
os.path.join() calls and sanitizer-sounding comments would make the
fixture's pass/fail depend on unrelated content elsewhere in that same
file. Mirrors the real CyberSci nationals-2024-25 "history-stealer" web
challenge's webapp/app.py /file_upload route almost verbatim, including
its exact bug: the ".." check exists but computes an alternate absolute
path instead of actually rejecting the entry.
"""

import os
import shutil
import zipfile


def extract_uploaded_zip(zip_path, unzip_path):
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        for member in zip_ref.infolist():
            raw_name = member.filename
            if member.is_dir() or raw_name.endswith("/"):
                continue

            if raw_name.startswith("/") or ".." in raw_name:
                # BUG: looks like a traversal check, but normalizes to an
                # absolute path and writes there anyway instead of
                # rejecting the entry — this is the real motivating bug.
                dest_path = os.path.normpath(os.path.join("/", raw_name))  # ruleid: Path Traversal / Zip Slip
            else:
                dest_path = os.path.join(unzip_path, raw_name)

            parent_dir = os.path.dirname(dest_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)

            with zip_ref.open(member) as src, open(dest_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
