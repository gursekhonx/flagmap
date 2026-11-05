r"""
orm_where_guard.py — a whole request object (`req.query` / `req.body` /
`req.params`) used as the `where` filter of a Prisma or Sequelize query.

The JS counterpart of the Python "ORM Injection / Filter Leak" rule
(v1.39.0, Django filter() fed a double-star-unpacked request dict). Found in UofTCTF 2025's
public "prismatic-blogs" web challenge (index.js):

    let query = <the whole parsed query string>;
    query.published = true;
    let posts = await prisma.post.findMany({where: query});

Express's default query parser (qs) turns `?author[password][gte]=M`
into nested objects, so the client writes Prisma filter syntax directly:
relation traversal (`author`) plus an operator (`gte`) on a field the API
never returns. The solve reads each user's password one character at a
time from whether any posts come back, logs in, and finds the flag in a
draft post. (Forcing `published = true` afterwards doesn't help — the
attacker's keys sit alongside it.)

(Paraphrased above so this docstring doesn't match its own signal.)

Two whole-file signals: (1) a variable bound to an entire request object —
`const|let|var X = req.query|req.body|req.params` with nothing after it
but `;` (a single field, `req.query.id`, is a value, not a filter); (2) a
`where: X` (or `where: req.query` etc. directly) inside a call to a
Prisma/Sequelize query method: findMany, findFirst, findUnique,
findFirstOrThrow, findUniqueOrThrow, findAll, findOne, findAndCountAll,
count, aggregate, groupBy, updateMany, deleteMany, destroy, update.
Fires on the call line.

Known blind spots: the object spread into a bigger filter
(`where: { ...req.query, published: true }`) isn't matched; nor is a
filter built across several lines before the call.
"""

import re
from typing import List

ORM_WHERE_LANGUAGES = {"js"}

_WHOLE_REQ = r"req\.(?:query|body|params)"
_ASSIGN_RE = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*" + _WHOLE_REQ + r"\s*;?\s*(?://.*)?$")
_METHODS = (r"(?:findMany|findFirst|findUnique|findFirstOrThrow|findUniqueOrThrow|findAll|findOne|"
            r"findAndCountAll|count|aggregate|groupBy|updateMany|deleteMany|destroy|update)")


class _OrmWhereFinding:
    __slots__ = ("file", "line_no", "line_text")

    def __init__(self, file, line_no, line_text):
        self.file = file
        self.line_no = line_no
        self.line_text = line_text


def find_orm_where_injection(path: str, language: str, lines: List[str]) -> List[_OrmWhereFinding]:
    if language not in ORM_WHERE_LANGUAGES:
        return []
    full_text = "".join(lines)
    if "where" not in full_text:
        return []
    names = {m.group(1) for line in lines for m in [_ASSIGN_RE.search(line.strip())] if m}
    value_alt = [_WHOLE_REQ + r"(?![\w.\[])"] + [re.escape(n) + r"(?![\w.\[])" for n in names]
    call_re = re.compile(
        r"\." + _METHODS + r"\s*\(\s*\{[^}]*\bwhere\s*:\s*(?:" + "|".join(value_alt) + r")"
    )
    findings: List[_OrmWhereFinding] = []
    for idx, line in enumerate(lines):
        if call_re.search(line):
            findings.append(_OrmWhereFinding(path, idx + 1, line.strip()[:200]))
    return findings
