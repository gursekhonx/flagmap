"""
vendor_guard.py — best-effort suppression of flagmap's two broadest,
least context-aware regex rules (a bare call to the eval builtin anywhere,
a bare `.innerHTML = ...` assignment) when the file being scanned is
almost certainly a vendored/third-party library, not code the challenge
author actually wrote. (Careful: don't spell either trigger shape out
literally in this file's own prose, parens and all, or this module would
self-match the very rules it exists to suppress — exactly the trap
loot.py's docstring and xxe_guard.py's test fixtures fell into earlier;
see scanner.py's self-scan during development, which is what caught this
draft doing exactly that.)

Found by stress-testing flagmap against RailsGoat — a real, Rails-era
vulnerable-by-design app — rather than anticipated ahead of time. Rails'
pre-Webpacker asset pipeline convention checks third-party JS straight
into app/assets/javascripts/ with no vendor/ or node_modules/ directory to
exclude by path (scanner.SKIP_DIRS already handles those two names, but
that's no help here): a jQuery DataTables plugin, the HTML5 Shiv
polyfill, Google's AJAX API loader, and an IcoMoon icon-font's IE7/8 shim
all ended up sitting directly alongside RailsGoat's own hand-written
controllers and views, and each one tripped the two rules this module
suppresses — the broadest, least taint-aware ones in patterns.py — purely
because these libraries do plenty of legitimate, unexploitable use of
both shapes (feature detection, templating, DOM shims) that has nothing
to do with whatever bug the challenge author actually planted.

Four independent, deliberately conservative signals, ANY of which is
enough to call a file vendored. False negatives here just mean the noise
isn't suppressed — same cost as not having this check at all — but a
false positive would hide a real finding, so each signal is chosen to
almost never fire on hand-written, intentionally-vulnerable CTF code:

  1. Filename follows the jQuery-plugin naming convention
     (`jquery.<name>(.min)?.js` / `jquery-<name>(.min)?.js`) — the de
     facto ecosystem-wide way to name a jQuery plugin file, specifically
     so it visibly reads as "not my code."
  2. Filename ends in `.min.js` / `.min.css` — hand-written,
     intentionally-vulnerable CTF source is never deliberately minified;
     only build output of someone else's library is.
  3. Filename is one of a small curated list of extremely well-known,
     always-vendored-verbatim library/polyfill filenames (html5shiv,
     modernizr, respond.js, Google's own `jsapi.js` AJAX loader, ...) —
     see _KNOWN_VENDOR_BASENAMES. Deliberately short and literal, not a
     fuzzy match: a longer list risks matching an app's own
     similarly-named file.
  4. The file sits in a directory whose sibling files include a webfont
     (.eot/.woff/.woff2/.ttf) — the IcoMoon/Font-Awesome packaging
     convention of shipping an IE7/8 shim script right next to the font
     files it patches in. Deliberately excludes .svg (too commonly a
     plain image, not a font, to be a safe signal on its own).

A fifth, broader fallback — a license/version banner comment
(`/*! Library vX.Y.Z | ... License */`-shaped) within the first ~800
characters of the file — catches anything signals 1-4 miss that still
announces itself as vendored (this is what actually catches the DataTables
plugin and the HTML5 Shiv file in the motivating RailsGoat case, even
though both also happen to match signal 1/2 respectively).
"""

import os
import re
from typing import List

_JQUERY_PLUGIN_RE = re.compile(r"""^jquery[.\-].*\.js$""", re.IGNORECASE)
_MIN_SUFFIX_RE = re.compile(r"""\.min\.(?:js|css)$""", re.IGNORECASE)

# Short and literal on purpose — see module docstring's point 3.
_KNOWN_VENDOR_BASENAMES = {
    "jsapi.js",  # Google's AJAX API Loader — unambiguous, Google-owned name
    "html5.js",
    "html5shiv.js",
    "modernizr.js",
    "respond.js",
    "selectivizer.js",
    "es5-shim.js",
    "json2.js",
    "json3.js",
    "normalize.css",
}

# Font formats only — never a plain image format, so a directory
# containing one of these is reliably "this folder ships a webfont",
# unlike .svg which is just as often an ordinary icon/image.
_WEBFONT_EXTENSIONS = {".eot", ".woff", ".woff2", ".ttf"}

# Bounded (.{0,300}) deliberately, even under re.DOTALL, so this can never
# become a catastrophic-backtracking risk the way an unbounded .* would be
# — see scanner.MAX_LINE_LEN's comment for the same concern elsewhere.
_LICENSE_BANNER_RE = re.compile(
    r"""/\*!?.{0,300}?\b(?:license|licensed|copyright)\b""",
    re.IGNORECASE | re.DOTALL,
)

# How much of the file's own text (not line count — a minified vendor file
# may have its whole license banner on what scanner.py treats as "line 1")
# the banner check looks at. Comfortably past any realistic banner comment,
# nowhere near long enough to cost anything on a multi-megabyte file.
_BANNER_SCAN_CHARS = 800

# Pattern payload-texts that are the broadest, least context-aware rules
# in patterns.py — each matches on call/assignment SHAPE alone, with no
# taint check at all, so they're exactly as noisy in a vendored library's
# perfectly legitimate use of both shapes as they'd be in a real bug.
# scanner.py suppresses matches of these specific rules when the file
# looks vendored (see is_vendor_file() above).
NOISY_IN_VENDOR_FILES = {
    # "Command Injection / RCE" / generic `\beval\s*\(` rule
    "Try passing OS/module access, e.g. for PHP: system('id'); for Python: __import__('os').system('id')",
    # "Cross-Site Scripting (XSS) — DOM-based" / `.innerHTML\s*=` rule
    "Try injecting via the page's URL/hash/query param that feeds this value: <img src=x onerror=alert(1)>",
}


def _has_webfont_sibling(path: str) -> bool:
    try:
        siblings = os.listdir(os.path.dirname(path) or ".")
    except OSError:
        return False
    return any(os.path.splitext(s)[1].lower() in _WEBFONT_EXTENSIONS for s in siblings)


def is_vendor_file(path: str, full_text: str) -> bool:
    """Best-effort check: is this almost certainly a vendored/third-party
    library file rather than something the challenge author wrote? See the
    module docstring for the five signals this combines."""
    base = os.path.basename(path)

    if _JQUERY_PLUGIN_RE.match(base):
        return True
    if _MIN_SUFFIX_RE.search(base):
        return True
    if base.lower() in _KNOWN_VENDOR_BASENAMES:
        return True
    if _has_webfont_sibling(path):
        return True
    if _LICENSE_BANNER_RE.search(full_text[:_BANNER_SCAN_CHARS]):
        return True
    return False
