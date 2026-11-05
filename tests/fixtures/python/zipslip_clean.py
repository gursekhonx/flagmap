"""
Zip Slip — safe counterpart to zipslip_vuln.py. Same shape (iterate zip
members, build a destination path from each entry's own filename via
os.path.join, write it to disk) but with a real containment check:
resolve the computed path and confirm it's still inside the extraction
root before writing, instead of trusting a bare ".."-substring test.
This is exactly the kind of fix zipslip_guard.py's _SAFE_CONTAINMENT_RE
is meant to recognize — same os.path.join(..., raw_name) shape that
fires in zipslip_vuln.py, suppressed here only because this file also
proves the final path with .resolve()...relative_to(...).
"""

import os
import pathlib
import shutil
import zipfile


def extract_uploaded_zip_safe(zip_path, unzip_path):
    base = pathlib.Path(unzip_path).resolve()
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        for member in zip_ref.infolist():
            raw_name = member.filename
            if member.is_dir() or raw_name.endswith("/"):
                continue

            dest_path = os.path.join(unzip_path, raw_name)  # safe: Path Traversal / Zip Slip
            resolved = pathlib.Path(dest_path).resolve()
            resolved.relative_to(base)  # raises ValueError if it escaped the base dir

            resolved.parent.mkdir(parents=True, exist_ok=True)
            with zip_ref.open(member) as src, open(resolved, "wb") as dst:
                shutil.copyfileobj(src, dst)
