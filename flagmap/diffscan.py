"""
diffscan.py — restricts a scan's findings to only the files that changed
between two directory snapshots.

The CTF use case this is for: an organizer ships a patched update mid-
competition ("v2 of the challenge is up, the old bug is fixed") — and the
question a player actually wants answered isn't "scan v2 from scratch and
read the whole report again," it's "what did they actually touch, and is
there anything NEW in exactly those files" (a patch is itself a common
place for a *second* bug to get introduced). Re-reading a full report to
spot that by eye defeats the point of having a scanner at all.

Deliberately diffs two plain directory SNAPSHOTS, not two git refs: a CTF
challenge handout is essentially never its own git repository (that's
loot.py's ".git directory present" finding's whole reason to exist — if
one WERE shipped, it would be a loot/recon finding on its own, see
"Loot / Recon"), so a `git diff <ref>` baseline would need the player to
have been diligently committing on their own throughout the competition,
which isn't a reasonable thing to assume. Comparing "the old handout I
already have on disk" to "the new handout I just downloaded" needs no
such setup — it's just two folders.

"Changed" means: a file exists in the new snapshot whose relative path
either doesn't exist at all in the old snapshot (added), or does exist
but with different byte content (modified). A file only in the OLD
snapshot (removed) can't produce a finding in the new scan anyway, so it's
tracked only for the summary count, not filtered against.
"""

import hashlib
import os
from typing import Set, Tuple

from .patterns import SKIP_DIRS


def _iter_relative_files(root: str):
    """Yields every file's path relative to root, applying the same
    noise-directory skip list as the rest of flagmap's own walks, so a
    vendored dependency directory re-copied verbatim between snapshots
    doesn't get diffed line-by-line for no reason."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root)
            yield rel, full


def _file_hash(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            # Read in chunks rather than one read() — a handout can
            # legitimately contain a large bundled asset (a vendored .js
            # file, a sample DB dump) and this only needs to detect
            # byte-for-byte difference, not hold the whole file in memory
            # to do it.
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""  # unreadable file: treat as "no stable content to compare" below
    return h.hexdigest()


def find_changed_files(old_root: str, new_root: str) -> Tuple[Set[str], int, int]:
    """Returns (changed_relative_paths, n_new_total, n_old_total).

    changed_relative_paths: every file (by path relative to new_root)
    that's new or whose content differs from the same relative path in
    old_root. An unreadable file in EITHER snapshot is conservatively
    treated as changed (an empty hash never equals another empty hash,
    including another unreadable file's) — "can't prove it's the same"
    defaults to "show it," not the other way around, since the cost of a
    missed-but-shown finding is lower than a missed-and-hidden one.
    """
    old_hashes = {rel: _file_hash(full) for rel, full in _iter_relative_files(old_root)}
    new_files = list(_iter_relative_files(new_root))

    changed = set()
    for rel, full in new_files:
        old_hash = old_hashes.get(rel)
        if old_hash is None:
            changed.add(rel)  # genuinely new file
            continue
        new_hash = _file_hash(full)
        if new_hash != old_hash:
            changed.add(rel)

    return changed, len(new_files), len(old_hashes)
