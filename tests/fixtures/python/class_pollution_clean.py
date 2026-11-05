"""
Safe counterparts to class_pollution_vuln.py.
"""


class Config:
    pass


def set_fixed_attrs(obj):
    # Ordinary setattr() with a literal attribute name - completely
    # normal Python, must never be flagged just because setattr() is
    # called somewhere in a file that also happens to have a dict loop
    # elsewhere.
    setattr(obj, "name", "fixed")  # safe: Prototype Pollution


def merge_into_dict_only(src, dst):
    # Same dict-iteration shape class_pollution_guard.py looks for, but
    # there is no attribute-setting call anywhere in this file using
    # those same two loop variable names - this function only ever
    # assigns into a plain dict subscript, never onto object attributes
    # by name, so the detector's second signal never fires.
    for k, v in src.items():  # safe: Prototype Pollution
        if k.startswith("__"):
            continue
        dst[k] = v
