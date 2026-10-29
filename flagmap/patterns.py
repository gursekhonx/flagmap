"""
patterns.py — vulnerability pattern database for flagmap.

Each pattern is a dict:
    name:        short vuln class label
    language:    "php" | "python" | "js" | "generic"
    regex:       compiled regex, matched line-by-line
    severity:    "high" | "medium" | "low"
    why:         one-line explanation of why this is dangerous
    payload:     a suggested starting payload / exploitation idea
    confidence:  "likely" | "possible"  (possible = flag but may be a false positive)
"""

import re

# Each entry: (name, language, pattern, severity, why, payload, confidence)
RAW_PATTERNS = [

    # ---------------- SQL INJECTION ----------------
    (
        "SQL Injection",
        "php",
        r"""(?:mysqli?_query|->query|->exec|->prepare)\s*\(\s*["'].*\$\w+""",
        "high",
        "SQL query built with direct string interpolation of a variable — classic injectable query.",
        "' OR '1'='1' -- -",
        "likely",
    ),
    (
        "SQL Injection",
        "php",
        r"""\$(?:sql|query)\s*=\s*["'].*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)""",
        "high",
        "SQL string concatenated directly with user-controlled input ($_GET/$_POST/etc).",
        "' UNION SELECT 1,2,3-- -",
        "likely",
    ),
    (
        "SQL Injection",
        "python",
        r"""(?:execute|executemany)\s*\(\s*(?:f["']|["'].*%s.*["']\s*%|["'].*\+)""",
        "high",
        "Query uses an f-string, % formatting, or string concatenation instead of parameterized placeholders.",
        "' OR 1=1 -- ",
        "likely",
    ),
    (
        "SQL Injection",
        "python",
        r"""(?:execute)\s*\(\s*["'].*\{.*\}.*["']\.format\(""",
        "high",
        "Query built with .format() string interpolation — user input likely flows into SQL unescaped.",
        "' OR 1=1 -- ",
        "likely",
    ),
    (
        "SQL Injection",
        "js",
        r"""(?:query|execute)\s*\(\s*[`"'].*\$\{.*\}""",
        "high",
        "Template literal interpolated directly into a SQL query string (Node.js).",
        "' OR '1'='1",
        "likely",
    ),
    (
        "SQL Injection",
        "python",
        r"""f["'][^"']*\b(?:SELECT\b[^"']*\bFROM|INSERT\b[^"']*\bINTO|UPDATE\b[^"']*\bSET|DELETE\b[^"']*\bFROM)\b[^"']*\{[\w.]+\}""",
        "high",
        "An f-string containing SQL structure (SELECT...FROM, INSERT...INTO, etc.) and an interpolated "
        "{variable} is being built — this catches the query at its construction site even when it's "
        "assigned to a variable and executed several lines later (e.g. `sql = f\"SELECT...{x}\"` then "
        "`conn.execute(sql)` further down), which a single-call pattern can't see across lines.",
        "' OR 1=1 -- ",
        "likely",
    ),
    (
        "SQL Injection",
        "js",
        r"""`[^`]*\b(?:SELECT\b[^`]*\bFROM|INSERT\b[^`]*\bINTO|UPDATE\b[^`]*\bSET|DELETE\b[^`]*\bFROM)\b[^`]*\$\{[\w.]+\}""",
        "high",
        "A template literal containing SQL structure (SELECT...FROM, INSERT...INTO, etc.) and an "
        "interpolated ${variable} is being built — catches the query at its construction site even if "
        "it's assigned to a variable and executed elsewhere.",
        "' OR 1=1 -- ",
        "likely",
    ),
    (
        "SQL Injection",
        "csharp",
        r"""\$["'][^"']*\b(?:SELECT\b[^"']*\bFROM|INSERT\b[^"']*\bINTO|UPDATE\b[^"']*\bSET|DELETE\b[^"']*\bFROM)\b[^"']*\{[\w.]+\}""",
        "high",
        "A C# interpolated string ($\"...\") containing SQL structure (SELECT...FROM, INSERT...INTO, etc.) "
        "and an interpolated {variable} is being built — catches the query at its construction site even "
        "if it's assigned to a variable and executed elsewhere (e.g. via SqlCommand/Dapper).",
        "' OR 1=1 -- ",
        "likely",
    ),

    # ---------------- COMMAND INJECTION ----------------
    (
        "Command Injection",
        "php",
        r"""\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*.*\$""",
        "high",
        "Shell command execution function called with a variable — check if that variable traces to user input.",
        "; cat /flag* ; ",
        "likely",
    ),
    (
        "Command Injection",
        "php",
        r"""`.*\$_(?:GET|POST|REQUEST|COOKIE).*`""",
        "high",
        "Backtick shell execution operator used with raw user input embedded in it.",
        "; id ; ",
        "likely",
    ),
    (
        "Command Injection",
        "python",
        r"""os\.system\s*\(\s*(?:f["']|.*\+|.*%\s)""",
        "high",
        "os.system() called with interpolated/concatenated input — arbitrary shell command execution risk.",
        "; cat flag.txt #",
        "likely",
    ),
    (
        "Command Injection",
        "python",
        r"""subprocess\.(?:call|run|Popen|check_output)\s*\(.*?shell\s*=\s*True""",
        "high",
        "subprocess invoked with shell=True — if any argument includes user input, it's shell-injectable.",
        "; cat flag.txt #",
        "likely",
    ),
    (
        "Command Injection",
        "js",
        r"""(?:child_process\.)?(?:exec|execSync)\s*\(\s*[`"'].*\$\{""",
        "high",
        "Node child_process.exec called with a template literal — user input can break out into shell commands.",
        "; cat flag.txt #",
        "likely",
    ),
    (
        "Command Injection / RCE",
        "generic",
        r"""\beval\s*\(""",
        "high",
        "eval() executes a string as code. If any part of the string comes from user input, this is full RCE.",
        "Try passing OS/module access, e.g. for PHP: system('id'); for Python: __import__('os').system('id')",
        "possible",
    ),

    # ---------------- UNSAFE DESERIALIZATION ----------------
    (
        "Unsafe Deserialization",
        "python",
        r"""pickle\.loads?\s*\(""",
        "high",
        "pickle.loads() on untrusted data allows arbitrary code execution via a crafted pickle payload.",
        "Craft a pickle with __reduce__ returning os.system('cat flag.txt')",
        "likely",
    ),
    (
        "Unsafe Deserialization",
        "python",
        r"""yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)""",
        "medium",
        "yaml.load() without SafeLoader can instantiate arbitrary Python objects from the YAML document.",
        "!!python/object/apply:os.system ['cat flag.txt']",
        "possible",
    ),
    (
        "Unsafe Deserialization",
        "php",
        r"""\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)""",
        "high",
        "unserialize() called directly on user input — classic PHP Object Injection (POP chain) target.",
        "Look for a __destruct/__wakeup gadget chain in the codebase to build a POP chain.",
        "likely",
    ),
    (
        "Unsafe Deserialization",
        "php",
        r"""\bunserialize\s*\(""",
        "medium",
        "unserialize() called — confirm whether the input traces back to user-controlled data.",
        "Look for a __destruct/__wakeup gadget chain in the codebase to build a POP chain.",
        "possible",
    ),
    (
        "Unsafe Deserialization",
        "js",
        r"""node-serialize|serialize-javascript.*unserialize""",
        "high",
        "node-serialize's unserialize can execute arbitrary code via an IIFE embedded in the payload.",
        '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'cat flag.txt\', ...)}()"}',
        "possible",
    ),

    # ---------------- PATH TRAVERSAL / LFI ----------------
    (
        "Path Traversal / LFI",
        "php",
        r"""(?:include|include_once|require|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)""",
        "high",
        "File include/require with direct user input — classic Local File Inclusion, possibly RCE via log/session poisoning.",
        "?page=php://filter/convert.base64-encode/resource=index",
        "likely",
    ),
    (
        "Path Traversal / LFI",
        "php",
        r"""fopen\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)""",
        "high",
        "fopen() on raw user input allows reading arbitrary files via path traversal.",
        "../../../../etc/passwd",
        "likely",
    ),
    (
        "Path Traversal / LFI",
        "python",
        r"""open\s*\(\s*(?:os\.path\.join\s*\(.*?request\.|request\.(?:args|form|values)\[)""",
        "high",
        "File opened using a path built from a request parameter — traversal likely possible if not sanitized.",
        "../../../../etc/passwd",
        "likely",
    ),
    (
        "Path Traversal / LFI",
        "python",
        r"""send_file\s*\(\s*(?:os\.path\.join\s*\(.*?request\.|request\.)""",
        "high",
        "Flask send_file() fed a path derived from the request — check for traversal sanitization.",
        "../../../../etc/passwd",
        "likely",
    ),
    (
        "Path Traversal / LFI",
        "js",
        r"""(?:fs\.(?:readFile|readFileSync|createReadStream)|res\.sendFile)\s*\(.*?req\.(?:query|params|body)""",
        "high",
        "File read/send operation built directly from request data — classic Node.js path traversal.",
        "../../../../etc/passwd",
        "likely",
    ),

    # ---------------- SSTI ----------------
    (
        "Server-Side Template Injection (SSTI)",
        "python",
        r"""render_template_string\s*\(\s*(?:f["']|.*\+|.*%\s|.*\.format\()""",
        "high",
        "Flask render_template_string() called with interpolated/concatenated input — user input is parsed as a Jinja2 template.",
        "{{7*7}}  then escalate: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read() }}",
        "likely",
    ),
    (
        "Server-Side Template Injection (SSTI)",
        "js",
        r"""(?:ejs\.render|handlebars\.compile|pug\.render|nunjucks\.renderString)\s*\(.*?req\.(?:query|params|body)""",
        "high",
        "Template engine render call fed directly from request data — likely SSTI.",
        "Try {{7*7}} (Handlebars/Nunjucks) or <%= 7*7 %> (EJS) to confirm, then escalate to RCE helpers.",
        "likely",
    ),
    (
        "Server-Side Template Injection (SSTI)",
        "generic",
        r"""Template\s*\(\s*.*\$|new\s+Function\s*\(""",
        "medium",
        "Dynamic template/function construction from a string — check if any part is user-controlled.",
        "{{7*7}} or ${7*7} depending on engine",
        "possible",
    ),

    # ---------------- REPORTLAB PARAGRAPH INJECTION ----------------
    # Same-line case only: reportlab.platypus.Paragraph(text, style) where
    # `text` is request data fed straight in on this one line. The far more
    # common shape in real PDF-generator CTF challenges — `title =
    # request.form.get(...)` on one line, `Paragraph(title, ...)` several
    # lines later — needs real cross-line taint tracking to catch, which is
    # what the AST engine's SINKS["python"]["Paragraph"] entry is for (see
    # ast_engine.py); this regex only covers the inline variant as a
    # same-line backstop for when tree-sitter-python isn't installed.
    (
        "ReportLab Paragraph Injection (CVE-2023-33733)",
        "python",
        r"""\bParagraph\s*\(\s*request\.(?:args|form|values|json)\b""",
        "high",
        "reportlab.platypus.Paragraph() called directly with request data. Paragraph() parses its text as "
        "ReportLab's own mini-markup (<font color=\"...\">, <a>, <img>, ...), and reportlab<=3.6.12 lets a "
        "crafted `color` attribute escape the rl_safe_eval() sandbox for RCE (CVE-2023-33733).",
        "<font color=\"&lt;payload&gt;\">x</font> — see github.com/c53elyas/CVE-2023-33733 for the full "
        "sandbox-escape expression to put in the color attribute.",
        "likely",
    ),

    # ---------------- UNRESTRICTED FILE UPLOAD ----------------
    (
        "Unrestricted File Upload",
        "php",
        r"""move_uploaded_file\s*\(""",
        "high",
        "File upload saved with move_uploaded_file() — check the surrounding code for an extension/MIME "
        "allowlist and whether the destination is web-accessible. Missing checks let you upload a webshell.",
        "Upload a file named shell.php containing: <?php system($_GET['cmd']); ?>  then request it directly.",
        "possible",
    ),
    (
        "Unrestricted File Upload",
        "python",
        r"""\.save\s*\(\s*(?:os\.path\.join\s*\(.*?(?:secure_filename|filename)|request\.)""",
        "medium",
        "Flask/Werkzeug file upload saved using the raw filename — check for an extension allowlist "
        "(secure_filename() alone does NOT block dangerous extensions like .php/.phtml).",
        "Upload a file named shell.php (or shell.phtml) containing a webshell, then request it directly.",
        "possible",
    ),
    (
        "Unrestricted File Upload",
        "js",
        r"""multer\s*\(\s*\{(?![^}]*fileFilter)""",
        "low",
        "multer() configured without a visible fileFilter — confirm uploads aren't restricted by extension/type elsewhere.",
        "Upload a file with a server-side-executable extension matching the stack in use.",
        "possible",
    ),

    # ---------------- SSRF (Server-Side Request Forgery) ----------------
    (
        "SSRF (Server-Side Request Forgery)",
        "python",
        r"""(?:requests\.(?:get|post|put|delete|patch|head|request)|urlopen|urllib2?\.(?:urlopen|request\.urlopen))\s*\(.*?request\.""",
        "high",
        "An outbound HTTP request is made to a URL built from the incoming request — the server can be "
        "made to fetch internal/cloud-metadata URLs or scan the internal network on the attacker's behalf.",
        "Try http://127.0.0.1:PORT/, http://169.254.169.254/latest/meta-data/ (cloud metadata), or an internal service hostname.",
        "likely",
    ),
    (
        "SSRF (Server-Side Request Forgery)",
        "python",
        r"""setopt\s*\(\s*pycurl\.URL\s*,.*?request\.""",
        "high",
        "pycurl is set up to fetch a URL built from the incoming request. If there's a protocol blacklist "
        "nearby, check it for case-sensitivity or bypassable scheme bugs (e.g. 'File://', 'gopher://').",
        "Try case variation on blacklisted schemes (File://), or an unblocked scheme like gopher:// or dict:// pointed at an internal service.",
        "likely",
    ),
    (
        "SSRF (Server-Side Request Forgery)",
        "js",
        r"""(?:axios\.(?:get|post|put|delete)|fetch|http\.get|https\.get)\s*\(.*?req\.(?:query|params|body)""",
        "high",
        "An outbound HTTP request is made to a URL built directly from request data — classic SSRF.",
        "Try http://127.0.0.1:PORT/, http://169.254.169.254/latest/meta-data/ (cloud metadata), or an internal hostname.",
        "likely",
    ),
    (
        "SSRF (Server-Side Request Forgery)",
        "php",
        r"""curl_setopt\s*\(\s*\$\w+\s*,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST|COOKIE)""",
        "high",
        "curl is configured to fetch a URL taken directly from user input — classic SSRF.",
        "Try http://127.0.0.1/, http://169.254.169.254/latest/meta-data/, or an internal hostname.",
        "likely",
    ),
    (
        "SSRF (Server-Side Request Forgery)",
        "php",
        r"""file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)""",
        "medium",
        "file_get_contents() can fetch remote URLs (http://, ftp://, php://) as well as local files — "
        "check if a user-controlled URL reaches this call, which doubles as SSRF/LFI depending on the scheme used.",
        "Try http://127.0.0.1/ for SSRF, or php://filter/convert.base64-encode/resource=... for LFI.",
        "possible",
    ),
    (
        "SSRF (Server-Side Request Forgery)",
        "python",
        r"""(?:requests\.(?:get|post|put|delete|patch|head|request)|urlopen)\s*\(\s*\w+\s*[,)]""",
        "medium",
        "An outbound HTTP request is made to a URL held in a plain variable — if that variable traces back "
        "to a request parameter (common in FastAPI, where query params arrive as plain function arguments "
        "rather than `request.args`), this is SSRF. Check where the variable comes from.",
        "If the variable is a path/query parameter, try http://127.0.0.1:PORT/, http://169.254.169.254/... "
        "(cloud metadata), or an internal service hostname/the Docker API port (2375/2376) if containerized.",
        "possible",
    ),
    (
        "SSRF (Server-Side Request Forgery)",
        "js",
        r"""(?:axios\.(?:get|post|put|delete)|fetch|http\.get|https\.get)\s*\(\s*\w+\s*[,)]""",
        "medium",
        "An outbound HTTP request is made to a URL held in a plain variable — check where that variable "
        "comes from; if it traces back to request data, this is SSRF.",
        "If the variable is a request parameter, try http://127.0.0.1:PORT/ or http://169.254.169.254/... (cloud metadata).",
        "possible",
    ),
    (
        "SSRF (Server-Side Request Forgery)",
        "python",
        r"""\bsse_client\s*\(\s*\w+\s*\)""",
        "medium",
        "An MCP SSE client connects to a URL held in a plain variable — if that URL is user-controlled "
        "(common in 'bring your own MCP server'-style endpoints), this is SSRF. Worse, any tool/resource "
        "metadata returned by that server should be treated as untrusted — if it's fed into an LLM's "
        "system prompt or context, a malicious tool description can become a prompt-injection payload.",
        "Point the MCP server URL at an attacker-controlled server; if its tool descriptions reach an LLM "
        "prompt, chain this into prompt injection against the app's own system instructions/secrets.",
        "possible",
    ),

    # ---------------- REFLECTED / DOM XSS ----------------
    (
        "Cross-Site Scripting (XSS)",
        "php",
        r"""\becho\s+\$_(?:GET|POST|REQUEST|COOKIE)\b(?!.*htmlspecialchars)""",
        "high",
        "User input echoed directly into the HTML response with no htmlspecialchars()/escaping — reflected XSS.",
        "<script>alert(document.domain)</script>",
        "likely",
    ),
    (
        "Cross-Site Scripting (XSS)",
        "php",
        r"""\bprint\s+\$_(?:GET|POST|REQUEST|COOKIE)\b(?!.*htmlspecialchars)""",
        "high",
        "User input printed directly into the HTML response with no escaping — reflected XSS.",
        "<script>alert(document.domain)</script>",
        "likely",
    ),
    (
        "Cross-Site Scripting (XSS)",
        "python",
        r"""return\s+(?:f["'][^"']*<|["'][^"']*<.*\+).*request\.(?:args|form|values)""",
        "medium",
        "A raw HTML string containing user input is returned directly from the view — if this isn't passed "
        "through Jinja2 autoescaping (e.g. it bypasses render_template), it's reflected XSS.",
        "<script>alert(document.domain)</script>",
        "possible",
    ),
    (
        "Cross-Site Scripting (XSS) — DOM-based",
        "js",
        r"""\.innerHTML\s*=(?!\s*["'`]\s*["'`])""",
        "medium",
        ".innerHTML assigned from a non-literal value — if it traces back to the URL, a form, or an API "
        "response, this is DOM-based XSS.",
        "Try injecting via the page's URL/hash/query param that feeds this value: <img src=x onerror=alert(1)>",
        "possible",
    ),
    (
        "Cross-Site Scripting (XSS)",
        "php",
        r"""\b(?:echo|print)\s+\$\w+\[\s*['"]?\w+['"]?\s*\]\s*;""",
        "high",
        "A bare array/row value (commonly a DB-stored field such as $row['body']) is echoed with no escaping "
        "wrapper (htmlspecialchars()/h()) — this is stored XSS if the value ever came from user input, which "
        "is the common case for a guestbook/comment/profile field pulled out of a database row.",
        "<script>alert(document.domain)</script>",
        "possible",
    ),
    (
        "Cross-Site Scripting (XSS)",
        "php",
        r"""addslashes\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)""",
        "medium",
        "addslashes() only escapes quotes/backslashes — it is a SQL-escaping relic, not an XSS defense, and "
        "does not block a </script> tag breakout or other HTML-context injection. Request data passed through "
        "it and reflected into HTML/JS is almost certainly still exploitable.",
        "</script><script>alert(document.domain)</script>",
        "likely",
    ),
    (
        "Path Traversal / Zip Slip",
        "python",
        r"""\.(?:extractall|extract)\s*\(""",
        "medium",
        "zipfile/tarfile extraction call found — if the archive's member names aren't validated against path "
        "traversal (e.g. `../../../etc/cron.d/x`) before extraction, a malicious archive can write files "
        "outside the intended directory (\"Zip Slip\").",
        "Craft an archive with a member path like ../../../etc/cron.d/x containing a malicious payload.",
        "possible",
    ),
    (
        "Insecure Session Token",
        "python",
        r"""(?:session|token|cookie)\w*\s*=\s*base64\.b64encode\s*\(\s*\w*(?:username|user(?:_?id)?|email|login)\w*""",
        "high",
        "The session/auth token is just a base64 encoding of a username/user id with no signature or secret "
        "involved — base64 is trivially reversible AND forgeable, so anyone can mint a valid session for any "
        "user by encoding that username themselves.",
        "Forge a session for any account: base64.b64encode(b'admin') (or whatever identity field is used).",
        "possible",
    ),
    (
        "JWT / Auth Token Weakness",
        "python",
        r"""options\s*=\s*\{[^}]*verify_signature["']?\s*:(?!\s*True\b)""",
        "high",
        "jwt.decode() is called with verify_signature explicitly set to something other than a literal True "
        "(often a variable/None/False) — if that value can end up falsy, the token's signature is never "
        "checked and any payload is accepted.",
        "Forge a JWT with any signing key/claims — if verify_signature resolves to falsy, the signature is never checked.",
        "possible",
    ),
    (
        "Cross-Site Scripting (XSS)",
        "js",
        r"""res\.send\s*\(\s*(?:req\.(?:query|params|body)|[`"'].*\$\{.*req\.)""",
        "high",
        "Request data written directly into the HTTP response body — if the content-type is HTML, this is reflected XSS.",
        "<script>alert(document.domain)</script>",
        "possible",
    ),

    # ---------------- XXE (XML EXTERNAL ENTITY) ----------------
    (
        "XML External Entity (XXE)",
        "php",
        r"""new\s+DOMDocument\s*\(.*\)|->loadXML\s*\(""",
        "medium",
        "XML parsed with DOMDocument — if LIBXML_NOENT/external entity loading isn't explicitly disabled, "
        "this can read local files or trigger SSRF via a crafted DOCTYPE.",
        "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>",
        "possible",
    ),
    (
        "XML External Entity (XXE)",
        "php",
        r"""simplexml_load_(?:string|file)\s*\(""",
        "medium",
        "simplexml_load_string/file() can process external entities by default on older libxml — confirm "
        "LIBXML_NOENT isn't enabled and entity loading is disabled.",
        "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>",
        "possible",
    ),
    (
        "XML External Entity (XXE)",
        "python",
        r"""(?:etree\.parse|etree\.fromstring|xmltodict\.parse)\s*\(""",
        "medium",
        "XML parsed with lxml/xmltodict — unless resolve_entities=False (lxml) or a safe parser is used, "
        "this can be vulnerable to XXE (local file read / SSRF).",
        "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>",
        "possible",
    ),

    # ---------------- OPEN REDIRECT ----------------
    (
        "Open Redirect",
        "php",
        r"""header\s*\(\s*["']Location:\s*["']\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)""",
        "medium",
        "Redirect target built directly from user input, with no allowlist check — classic open redirect, "
        "often chained into phishing or OAuth token theft.",
        "?redirect=https://evil.example.com",
        "likely",
    ),
    (
        "Open Redirect",
        "python",
        r"""redirect\s*\(\s*request\.(?:args|form|values)\.get\(""",
        "medium",
        "Flask redirect() target comes directly from a request parameter with no allowlist — open redirect.",
        "?next=https://evil.example.com",
        "likely",
    ),
    (
        "Open Redirect",
        "js",
        r"""res\.redirect\s*\(\s*req\.(?:query|params|body)""",
        "medium",
        "Express redirect target comes directly from request data with no allowlist — open redirect.",
        "?redirect=https://evil.example.com",
        "likely",
    ),

    # ---------------- NoSQL INJECTION ----------------
    (
        "NoSQL Injection",
        "js",
        r"""\.(?:find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|count)\s*\(\s*req\.(?:body|query|params)\s*\)""",
        "high",
        "A MongoDB query's entire filter object comes directly from request data — an attacker can send "
        "operators like {\"$ne\": null} or {\"$gt\": \"\"} to bypass logic instead of a literal value.",
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        "likely",
    ),
    (
        "NoSQL Injection",
        "python",
        r"""\.(?:find|find_one|update_one|update_many|delete_one|delete_many)\s*\(\s*request\.(?:json|get_json\(\))""",
        "high",
        "A MongoDB (pymongo) query's filter comes directly from the request body — vulnerable to operator injection.",
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        "likely",
    ),

    # ---------------- MASS ASSIGNMENT ----------------
    (
        "Mass Assignment",
        "python",
        r"""\*\*request\.(?:json|get_json\(\)|form)\b""",
        "medium",
        "Request data is unpacked directly into a model/object constructor or update call — an attacker can "
        "set fields that were never meant to be user-editable (e.g. is_admin, role, balance).",
        "Add an unexpected field to the JSON body, e.g. {\"is_admin\": true}, and see if it's accepted.",
        "possible",
    ),
    (
        "Mass Assignment",
        "js",
        r"""(?:findByIdAndUpdate|findOneAndUpdate|updateOne|updateMany|Object\.assign)\s*\(.*?req\.body\b""",
        "medium",
        "The entire request body is used to update a document/object with no field allowlist — an attacker "
        "can set fields that were never meant to be user-editable (e.g. isAdmin, role, balance).",
        "Add an unexpected field to the JSON body, e.g. {\"isAdmin\": true}, and see if it's accepted.",
        "possible",
    ),

    # ---------------- PROTOTYPE POLLUTION ----------------
    (
        "Prototype Pollution",
        "js",
        r"""(?:_\.merge|deepmerge|merge)\s*\(\s*\{\s*\}\s*,\s*req\.(?:body|query)""",
        "medium",
        "A deep-merge utility merges request data into a fresh object — if the library doesn't block "
        "`__proto__`/`constructor.prototype` keys, this pollutes Object.prototype for the whole process.",
        '{"__proto__": {"polluted": true}}',
        "possible",
    ),
    (
        "Prototype Pollution",
        "js",
        r"""instanceof\s+Object\s*&&\s*\w+\s+in\s+\w+\s*\)""",
        "medium",
        "A hand-rolled recursive merge checks `key in target` before recursing — `in` walks the prototype "
        "chain, not just own properties, which is the classic homemade-deep-merge Prototype Pollution gadget "
        "shape. Even if an upstream parser blocklists __proto__/constructor/prototype, this merge function "
        "itself has no guard of its own.",
        "Find any path that reaches this merge with a key named __proto__/constructor/prototype (or a key "
        "whose segments weren't blocklisted) and pollute Object.prototype.",
        "possible",
    ),
    (
        "SSRF (Server-Side Request Forgery)",
        "js",
        r"""\.goto\s*\(\s*\w+\s*[,)]""",
        "medium",
        "A Puppeteer/Playwright page.goto() navigates to a bare variable URL — if an admin/bot browser is "
        "driving this and the variable traces to user input with no host allowlist, this is SSRF via the bot "
        "(the bot will visit any URL you give it, including internal-only hosts).",
        "http://169.254.169.254/latest/meta-data/ or an internal-only host/port the bot can reach but you can't.",
        "possible",
    ),
    (
        "Cross-Site Scripting (XSS)",
        "js",
        r"""res\.(?:end|send)\s*\(\s*\w+(?:\.\w+)*\[\w+\]\s*\)""",
        "medium",
        "A stored value is pulled out of a collection by index and written directly into the response with no "
        "escaping — if Content-Type is text/html (check nearby res.set calls) and the stored value came from "
        "user input elsewhere, this is stored XSS/HTML-CSS-injection, structurally invisible to taint-lite "
        "since the source is a prior storage write, not a superglobal.",
        "<style>/* CSS-injection exfil */</style> or <script>alert(document.domain)</script> depending on CSP.",
        "possible",
    ),

    # ---------------- JWT WEAKNESSES ----------------
    (
        "JWT / Auth Token Weakness",
        "python",
        r"""jwt\.decode\s*\(.*?verify\s*=\s*False""",
        "high",
        "jwt.decode() called with verify=False — the token's signature is never checked, so any payload is "
        "trusted as-is.",
        "Forge a token with any payload (e.g. {\"role\": \"admin\"}) and no valid signature.",
        "likely",
    ),
    (
        "JWT / Auth Token Weakness",
        "python",
        r"""jwt\.decode\s*\(.*?algorithms\s*=\s*\[[^\]]*["']none["']""",
        "high",
        "'none' is accepted as a valid signing algorithm — an attacker can forge an unsigned token with alg:none.",
        "Craft a JWT with header {\"alg\":\"none\"} and no signature.",
        "likely",
    ),
    (
        "JWT / Auth Token Weakness",
        "js",
        r"""\bjwtDecode\s*\(""",
        "high",
        "jwtDecode() (from the jwt-decode npm package) only base64-decodes the JWT payload — it does NOT "
        "verify the signature. If this value is trusted for auth/identity without a separate signature "
        "check (e.g. jsonwebtoken's jwt.verify()) nearby, any crafted token is accepted.",
        "Craft a JWT with any signing key/claims (e.g. {\"username\":\"admin\"}) — the signature is never checked by this call.",
        "likely",
    ),
    (
        "JWT / Auth Token Weakness",
        "python",
        r"""\btoken\w*\.split\(\s*["']\.["']\s*\)""",
        "high",
        "The token is manually split on '.' instead of being passed through a library's verified decode "
        "(e.g. jwt.decode()) — a hand-rolled parser like this reads the claims but never checks the "
        "signature, so any payload with the right claims is accepted.",
        "Craft a JWT with any signing key/signature containing the claims this code expects — the signature is never checked.",
        "likely",
    ),
    (
        "JWT / Auth Token Weakness",
        "js",
        r"""\btoken\w*\.split\(\s*["'`]\.["'`]\s*\)""",
        "high",
        "The token is manually split on '.' instead of being passed through a library's verified decode "
        "(e.g. jwt.verify()) — a hand-rolled parser like this reads the claims but never checks the "
        "signature, so any payload with the right claims is accepted.",
        "Craft a JWT with any signing key/signature containing the claims this code expects — the signature is never checked.",
        "likely",
    ),
    (
        "JWT / Auth Token Weakness",
        "php",
        r"""explode\(\s*["']\.["']\s*,\s*\$token""",
        "high",
        "The token is manually split on '.' instead of being passed through a library's verified decode — "
        "a hand-rolled parser like this reads the claims but never checks the signature.",
        "Craft a JWT with any signing key/signature containing the claims this code expects — the signature is never checked.",
        "likely",
    ),
    (
        "JWT / Auth Token Weakness",
        "generic",
        r"""jwt\.verify\s*\(\s*\w+\s*,\s*\w+\s*\)(?!\s*,)""",
        "low",
        "JWT verified without an explicit algorithms allowlist passed — check if the library defaults to "
        "accepting attacker-chosen algorithms (e.g. switching RS256 to HS256 using the public key as the HMAC secret).",
        "Try re-signing the token as HS256 using the server's RSA public key as the HMAC secret.",
        "possible",
    ),

    # ---------------- WEAK / INSECURE CRYPTOGRAPHY ----------------
    (
        "Weak Cryptography",
        "js",
        r"""(?:SECRET|JWT|KEY|TOKEN|PASSWORD)\w*\s*=.*env\.\w+\s*\?\?\s*["'][\w-]{4,}["']""",
        "high",
        "A secret/key env var falls back to a hardcoded literal default when unset (`env.X ?? \"literal\"`) "
        "— if that env var isn't actually set in the deployed environment, the app silently signs/encrypts "
        "with a default value anyone can read straight out of the source.",
        "If the env var is unset in the target deployment, forge JWTs/tokens signed with the literal fallback string seen in source.",
        "likely",
    ),
    (
        "Weak Cryptography",
        "python",
        r"""hashlib\.(?:md5|sha1)\s*\(""",
        "medium",
        "MD5/SHA1 are fast, unsalted-by-default hashes — if this is hashing passwords or security tokens, "
        "it's crackable via rainbow tables / brute force. Prefer bcrypt/argon2/PBKDF2 for passwords.",
        "If it's a password hash, try cracking it with hashcat/john against a wordlist.",
        "possible",
    ),
    (
        "Weak Cryptography",
        "php",
        r"""\bmd5\s*\(\s*\$(?:password|pass|pwd)""",
        "medium",
        "Password hashed with MD5 — fast and unsalted, crackable via rainbow tables. Prefer password_hash() (bcrypt/argon2).",
        "Try cracking the hash with hashcat/john, or check for a magic-hash ('0e...') type-juggling bypass.",
        "likely",
    ),
    (
        "Weak Cryptography",
        "js",
        r"""crypto\.createHash\s*\(\s*["'](?:md5|sha1)["']""",
        "medium",
        "MD5/SHA1 used for hashing — if this hashes passwords, it's crackable. Prefer bcrypt/argon2.",
        "If it's a password hash, try cracking it with hashcat/john against a wordlist.",
        "possible",
    ),
    (
        "Weak Cryptography",
        "python",
        r"""MODE_ECB""",
        "medium",
        "AES/DES in ECB mode encrypts identical plaintext blocks to identical ciphertext blocks — patterns in "
        "the plaintext (e.g. image data, repeated fields) leak through. Look for a 'penguin' giveaway.",
        "Look for repeating ciphertext blocks, or try a byte-at-a-time ECB decryption/forgery attack.",
        "likely",
    ),

    # ---------------- INSECURE RANDOMNESS ----------------
    (
        "Insecure Randomness",
        "python",
        r"""(?:token|secret|password|otp|reset|session|nonce)\w*\s*=.*\brandom\.(?:random|randint|choice|randrange|getrandbits)\s*\(""",
        "medium",
        "A security-sensitive value (token/password/OTP/session id) is generated with Python's `random` "
        "module, which is NOT cryptographically secure — its output can be predicted. Use `secrets` instead.",
        "If the PRNG seed or recent outputs are known/guessable, token prediction (e.g. via randcrack for Mersenne Twister) may be possible.",
        "likely",
    ),
    (
        "Insecure Randomness",
        "php",
        r"""\$(?:token|secret|password|otp|reset|session|nonce)\w*\s*=.*\b(?:rand|mt_rand)\s*\(""",
        "medium",
        "A security-sensitive value is generated with rand()/mt_rand(), which is predictable — use random_bytes()/random_int().",
        "mt_rand() output can sometimes be predicted/recovered from other outputs; check for a seed leak.",
        "likely",
    ),
    (
        "Insecure Randomness",
        "js",
        r"""(?:token|secret|password|otp|reset|session|nonce)\w*\s*=.*Math\.random\s*\(""",
        "medium",
        "A security-sensitive value is generated with Math.random(), which is not cryptographically secure "
        "and can be predicted. Use crypto.randomBytes() instead.",
        "If several outputs are observable, Math.random()'s internal state can sometimes be recovered/predicted.",
        "likely",
    ),

    # ---------------- CORS MISCONFIGURATION (in code) ----------------
    (
        "CORS Misconfiguration",
        "js",
        r"""origin\s*:\s*(?:true|req\.headers\.origin|req\.headers\[["']origin["']\])""",
        "high",
        "CORS is configured to reflect the request's Origin header (or allow any origin) — combined with "
        "credentials:true, this lets any site read authenticated responses cross-origin.",
        "Host a page on an attacker-controlled origin making a credentialed fetch()/XHR to this API and read the response.",
        "likely",
    ),
    (
        "CORS Misconfiguration",
        "python",
        r"""Access-Control-Allow-Origin.*\*|origins\s*=\s*\[?["']\*["']""",
        "medium",
        "Wildcard CORS origin — if combined with Allow-Credentials:true, this is exploitable; even without "
        "credentials, confirm this is meant to be a fully public API.",
        "Check if Access-Control-Allow-Credentials is also true; if so, cross-origin authenticated reads are possible.",
        "possible",
    ),
    (
        "CORS Misconfiguration",
        "php",
        r"""header\s*\(\s*["']Access-Control-Allow-Origin:\s*\*["']""",
        "medium",
        "Wildcard CORS origin set — if combined with Access-Control-Allow-Credentials: true, this is exploitable.",
        "Check if Access-Control-Allow-Credentials is also true; if so, cross-origin authenticated reads are possible.",
        "possible",
    ),

    # ---------------- HOST HEADER INJECTION ----------------
    (
        "Host Header Injection",
        "php",
        r"""\$_SERVER\[['"]HTTP_HOST['"]\]""",
        "low",
        "The Host header (attacker-controlled) is read directly — if it's used to build a password-reset "
        "link, redirect, or cache key, this enables host header injection / poisoning attacks.",
        "Send a crafted Host header (e.g. Host: evil.com) and check if it appears in generated links/emails.",
        "possible",
    ),
    (
        "Host Header Injection",
        "python",
        r"""request\.host\b|request\.headers\.get\(\s*["']Host["']""",
        "low",
        "The Host header (attacker-controlled) is read directly — if it's used to build a URL (e.g. a "
        "password-reset link), this enables host header injection / poisoning attacks.",
        "Send a crafted Host header (e.g. Host: evil.com) and check if it appears in generated links/emails.",
        "possible",
    ),
    (
        "Host Header Injection",
        "js",
        r"""req\.headers\.host\b|req\.hostname\b""",
        "low",
        "The Host header (attacker-controlled) is read directly — if it's used to build a URL (e.g. a "
        "password-reset link), this enables host header injection / poisoning attacks.",
        "Send a crafted Host header (e.g. Host: evil.com) and check if it appears in generated links/emails.",
        "possible",
    ),

    # ---------------- DEBUG MODE / INFORMATION DISCLOSURE ----------------
    (
        "Debug Mode Enabled",
        "python",
        r"""app\.run\s*\(.*?debug\s*=\s*True""",
        "high",
        "Flask debug mode is enabled — besides leaking stack traces/source snippets on error, Werkzeug's "
        "interactive debugger allows arbitrary code execution if the debugger PIN can be bypassed/guessed.",
        "Trigger an unhandled exception to reach the Werkzeug debugger, then try the PIN bypass technique.",
        "likely",
    ),
    (
        "Debug Mode Enabled",
        "python",
        # Anchored to a bare module/settings-level assignment (optionally indented,
        # e.g. inside a class body) so this doesn't fire on an unrelated `debug=True`
        # keyword argument buried in a function call (e.g. `llm.bind_tools(tools,
        # debug=True)`, a LangChain kwarg with nothing to do with Flask/Django debug mode).
        r"""^\s*DEBUG\s*=\s*True\s*$""",
        "medium",
        "Django/framework DEBUG mode enabled — leaks detailed stack traces, settings, and installed apps on error pages.",
        "Trigger a 500 error (e.g. malformed input) and read the debug page for secrets/internal paths.",
        "possible",
    ),
    (
        "Debug Mode Enabled",
        "php",
        r"""ini_set\s*\(\s*["']display_errors["']\s*,\s*["']?1""",
        "medium",
        "display_errors is force-enabled in code — PHP errors/warnings (often containing file paths or query "
        "fragments) will be printed straight into the response.",
        "Trigger a PHP warning/error (bad input, missing param) and read the leaked path/query info.",
        "possible",
    ),

    # ---------------- C# / ASP.NET CORE ----------------
    (
        "SQL Injection",
        "csharp",
        r"""(?:ExecuteSqlRaw|ExecuteSqlRawAsync|FromSqlRaw)\s*\(\s*\$["']""",
        "high",
        "Entity Framework Core raw SQL call fed a C# interpolated string ($\"...\") — any `{variable}` inside "
        "it is substituted straight into the query with no parameterization. Use FromSqlInterpolated / "
        "ExecuteSqlInterpolated (which DO parameterize interpolated strings) instead.",
        "' OR 1=1 -- ",
        "likely",
    ),
    (
        "SQL Injection",
        "csharp",
        r"""new\s+SqlCommand\s*\(\s*\$?["'].*\+|new\s+SqlCommand\s*\(\s*\$["']""",
        "high",
        "ADO.NET SqlCommand built via string concatenation/interpolation instead of parameters (@param + "
        "command.Parameters.Add) — classic SQL injection.",
        "' OR 1=1 -- ",
        "likely",
    ),
    (
        "JWT / Auth Token Weakness",
        "csharp",
        r"""\.ReadJwtToken\s*\(""",
        "high",
        "JwtSecurityTokenHandler.ReadJwtToken() only PARSES the token's claims — it does NOT verify the "
        "signature. Any JWT with the right claims is accepted, signed or not. The correct API for "
        "authenticating a token is ValidateToken(), not ReadJwtToken().",
        "Craft a JWT with any signing key (the signature is never checked) containing the claims this code expects.",
        "likely",
    ),
    (
        "JWT / Auth Token Weakness",
        "csharp",
        r"""ValidateIssuerSigningKey\s*=\s*false|RequireSignedTokens\s*=\s*false""",
        "high",
        "Token validation parameters explicitly disable signature verification — any token is accepted regardless of signature.",
        "Craft a JWT with any signing key/claims; the signature is never checked.",
        "likely",
    ),
    (
        "JWT / Auth Token Weakness",
        "csharp",
        r"""SignatureValidator\s*=""",
        "medium",
        "A custom SignatureValidator delegate is set — these commonly just return the token unchanged "
        "without actually validating its signature. Check what this delegate does.",
        "If the delegate doesn't check the signature, craft a token with any signing key/claims.",
        "possible",
    ),
    (
        "Command Injection",
        "csharp",
        r"""Process\.Start\s*\([^)]*\+|Arguments\s*=.*\+.*(?:Request\.|Query\[|Form\[)""",
        "high",
        "A process is started with arguments built via string concatenation including request data — shell/argument injection risk.",
        "; cat flag.txt #  (or the OS-appropriate equivalent)",
        "possible",
    ),
    (
        "Command Injection",
        "csharp",
        r"""Arguments\s*=\s*\$["'][^"']*\{[\w.]+\}""",
        "high",
        "ProcessStartInfo.Arguments is built via C# string interpolation with a variable — ASP.NET model "
        "binding means that variable is often just a plain method parameter (no `Request.`/`Query[` on "
        "this line), so if it traces to user input (e.g. an uploaded filename) and isn't shell-escaped, "
        "this is command injection.",
        "Use a filename/value containing shell metacharacters, e.g. a single quote to break out of quoting.",
        "likely",
    ),
    (
        "Path Traversal / LFI",
        "csharp",
        r"""File\.(?:ReadAllText|ReadAllBytes|OpenRead|WriteAllText)\s*\([^)]*(?:Request\.|Query\[|Form\[)""",
        "high",
        "A file operation is built directly from request data — if the path isn't validated against a "
        "base directory, this allows reading/writing arbitrary files via path traversal.",
        "../../../../etc/passwd (or ..\\..\\..\\Windows\\win.ini on IIS/Windows)",
        "likely",
    ),
    (
        "Path Traversal / LFI",
        "csharp",
        r"""(?:File|Path)\.(?:ReadAllText|ReadAllBytes|OpenRead|WriteAllText|Combine)(?:Async)?\s*\(\s*[^,)]*,?\s*\w+\s*[,)]""",
        "medium",
        "A file path operation uses a plain variable — ASP.NET's attribute-based model binding "
        "(`[FromQuery] string path`) means a tainted value is often just a bare parameter name with no "
        "`Request.`/`Query[` on this line. If that variable traces to user input with no base-directory "
        "containment check (e.g. Path.GetFullPath + a prefix check), this is path traversal/LFI.",
        "../../../../etc/passwd (or ..\\..\\..\\Windows\\win.ini on IIS/Windows)",
        "possible",
    ),
    (
        "Unsafe Deserialization",
        "csharp",
        r"""new\s+BinaryFormatter\s*\(\)|TypeNameHandling\s*=\s*TypeNameHandling\.All|new\s+SimpleTypeResolver\s*\(\)""",
        "high",
        "BinaryFormatter and Json.NET with TypeNameHandling.All (or a SimpleTypeResolver) will instantiate "
        "arbitrary types from the serialized payload — classic .NET deserialization RCE gadget chains (e.g. ysoserial.net).",
        "Try a ysoserial.net gadget chain matching this deserializer (ObjectDataProvider, TypeConfuseDelegate, etc.).",
        "likely",
    ),
    (
        "Cross-Site Scripting (XSS)",
        "csharp",
        r"""Html\.Raw\s*\(\s*(?!["'])""",
        "high",
        "@Html.Raw() outputs a value with NO HTML encoding — if it's not a hardcoded literal, this is likely reflected/stored XSS.",
        "<script>alert(document.domain)</script>",
        "possible",
    ),
    (
        "Open Redirect",
        "csharp",
        r"""\bRedirect\s*\(\s*(?:Request\.Query|HttpContext\.Request\.Query|Request\.Form)""",
        "medium",
        "Redirect() target comes directly from request data with no allowlist — open redirect. Prefer "
        "LocalRedirect() which rejects external URLs, or validate against an allowlist.",
        "?returnUrl=https://evil.example.com",
        "likely",
    ),
    (
        "Weak Cryptography",
        "csharp",
        r"""MD5\.Create\s*\(\)|SHA1\.Create\s*\(\)|new\s+MD5CryptoServiceProvider|new\s+SHA1CryptoServiceProvider""",
        "medium",
        "MD5/SHA1 used — if this hashes passwords, it's crackable via rainbow tables/brute force. Prefer "
        "a dedicated password hasher (ASP.NET Core Identity's PasswordHasher, or BCrypt.Net).",
        "If it's a password hash, try cracking it with hashcat/john against a wordlist.",
        "possible",
    ),
    (
        "Debug Mode / Information Disclosure",
        "csharp",
        r"""UseDeveloperExceptionPage\s*\(\s*\)""",
        "low",
        "The developer exception page is enabled — confirm this is gated behind an environment check "
        "(app.Environment.IsDevelopment()) and not reachable in the deployed/production build.",
        "Trigger an unhandled exception (bad input, wrong type) and read the detailed stack trace/source snippet.",
        "possible",
    ),

    # ---------------- GRAPHQL / QUERY-DOCUMENT INJECTION ----------------
    (
        "GraphQL / Query Injection",
        "python",
        r'''"""\s*%\s*[\(\w]''',
        "high",
        "A triple-quoted string (commonly a GraphQL query/mutation document) is built with old-style `%` "
        "formatting (tuple or single value) — any interpolated value is substituted into the document "
        "with zero escaping, the same class of bug as SQL injection but against a GraphQL query instead of SQL.",
        'Try breaking out of the interpolated string argument, e.g. x") { __typename } #  (adjust field/alias names to the target query).',
        "likely",
    ),
    (
        "GraphQL / Query Injection",
        "python",
        r'''["']\s*%\s*\(.*(?:query|mutation)''',
        "medium",
        "A GraphQL query/mutation string appears to be built with % string formatting rather than GraphQL "
        "variables — check whether user input flows into the formatted values with no escaping.",
        'Try breaking out of the interpolated value with a quote + GraphQL comment, e.g. x") { __typename } #',
        "possible",
    ),
    (
        "GraphQL / Query Injection",
        "js",
        r'''(?:`|["']).*\$\{.*\}.*(?:query|mutation)\s*[:(]''',
        "medium",
        "A GraphQL query/mutation string is built via template-literal interpolation rather than GraphQL "
        "variables — if any interpolated value is user input, this is GraphQL injection.",
        'Try breaking out of the interpolated value with a quote + GraphQL comment, e.g. x") { __typename } #',
        "possible",
    ),

    # ---------------- SENSITIVE DATA EXPOSURE IN LOGS ----------------
    (
        "Sensitive Data Exposure in Logs",
        "python",
        r"""(?:logger|log|logging)\.(?:debug|info|warning|warn|error|critical|exception)\s*\([^)]*\b(?:password|passwd|pwd|secret|token|pepper|salt|api_key|apikey|private_key|hash|hashed)\w*\s*=""",
        "medium",
        "A security-sensitive value is passed as a keyword argument to a log call (common with structured "
        "loggers like structlog) — if logs are ever exposed via an API endpoint, dashboard, or log "
        "aggregator (OpenSearch, Elastic, etc.), this leaks the value to anyone who can read them.",
        "Check if application logs are reachable via an API/admin endpoint and read back the leaked value — "
        "intermediate hash states can sometimes be chained to recover a secret pepper/key byte-by-byte.",
        "likely",
    ),
    (
        "Sensitive Data Exposure in Logs",
        "js",
        r"""console\.(?:log|debug|info|warn|error)\s*\([^)]*\b(?:password|passwd|secret|token|pepper|salt|apiKey|api_key|privateKey|private_key)\b""",
        "medium",
        "A security-sensitive value is passed directly to a console log call — if logs are captured/exposed "
        "(CI output, a log aggregator, browser devtools in production), this leaks the value.",
        "Check where these logs end up (server logs, CI output, browser console) and whether they're reachable.",
        "possible",
    ),
    (
        "Sensitive Data Exposure in Logs",
        "php",
        r"""error_log\s*\(\s*.*\$(?:password|passwd|pwd|secret|token|pepper|salt|api_key|private_key)""",
        "medium",
        "A security-sensitive variable is written to the PHP error log — if the log is reachable, this leaks the value.",
        "Check if the PHP error log is reachable (misconfigured web root, LFI, debug endpoint).",
        "possible",
    ),

    # ---------------- WEAK AUTH LOGIC ----------------
    (
        "Weak Auth Logic",
        "php",
        r"""if\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[['\"]?\w+['\"]?\]\s*==\s*\$""",
        "medium",
        "Loose '==' comparison in PHP is vulnerable to type juggling (e.g. '0e123' == '0e456' is true).",
        "Try a magic-hash value like '0e215962017' against a password hash check.",
        "possible",
    ),
    (
        "Weak Auth Logic",
        "php",
        r"""strcmp\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)""",
        "medium",
        "strcmp() with an array input (e.g. password[]=x) can return 0/NULL unexpectedly, bypassing the check.",
        "Send the parameter as an array: password[]=anything",
        "possible",
    ),
    (
        "Weak Auth Logic",
        "generic",
        r"""(?<![\w-])(?:password|secret|api_key|token)\b\s*=\s*["'][A-Za-z0-9_\-]{4,}["']""",
        "medium",
        "Hardcoded credential/secret found directly in source — check if it's a usable backdoor.",
        "Try the hardcoded value directly as a login/API credential.",
        "possible",
    ),
    (
        "Weak Auth Logic",
        "php",
        r"""define\s*\(\s*['"]\w*(?:PASSWORD|SECRET|API_?KEY|TOKEN|PRIVATE_?KEY)\w*['"]\s*,\s*['"][^'"]{3,}['"]""",
        "medium",
        "A credential/secret is declared via define() with a literal value baked into source — PHP's "
        "define()-constant idiom for the same hardcoded-secret problem as a $var = \"value\" assignment, and "
        "common for config files (DB passwords, signing keys, API keys).",
        "Try the literal value directly as the credential/signing key (watch for obvious placeholder defaults "
        "like CHANGEME/changeme/password/secret).",
        "possible",
    ),
    (
        "Weak Auth Logic",
        "js",
        r"""===?\s*["'][A-Za-z0-9_\-]+["']\s*\)\s*\{[^}]*(?:admin|auth|logged)""",
        "low",
        "Auth/role check compares against a hardcoded string client/server side — look for ways to forge it.",
        "Inspect for a JWT/cookie you can set this value in directly.",
        "possible",
    ),

    # ==================== TEMPLATE ENGINES (raw/unescaped output tags) ====================
    # These are their own small language family: the vulnerable file is a
    # .ejs/.hbs template, not a .js/.py/.php source file, so EXTENSION_LANGUAGE
    # routes them to their own "ejs"/"handlebars" tags rather than "js".
    (
        "Cross-Site Scripting (XSS)",
        "ejs",
        r"""<%-\s*(?!include\s*\()[^%]+?%>""",
        "high",
        "EJS's <%- %> tag outputs raw, UNESCAPED HTML (the escaped form is <%= %>) — any non-constant "
        "expression inside it that traces back to user input is stored/reflected XSS. (<%- include(...) %> "
        "is excluded — that's EJS's normal way to pull in a partial template, not raw user data.)",
        "<script>alert(document.domain)</script>",
        "likely",
    ),
    (
        "Cross-Site Scripting (XSS)",
        "handlebars",
        r"""\{\{\{[^}]+\}\}\}""",
        "high",
        "Handlebars' triple-stache {{{ }}} outputs raw, UNESCAPED HTML (the escaped form is {{ }}) — if the "
        "value traces back to user input, this is stored/reflected XSS.",
        "<script>alert(document.domain)</script>",
        "likely",
    ),

    # ==================== JAVA ====================
    # Java deserialization (ysoserial-style gadget chains) is one of the most
    # common dedicated CTF web/pwn-adjacent bug classes — readObject() on
    # attacker-controlled bytes is almost always the intended bug when present.
    (
        "Unsafe Deserialization",
        "java",
        r"""\.readObject\s*\(\s*\)""",
        "high",
        "ObjectInputStream.readObject() deserializes attacker-controlled bytes into live Java objects — if a "
        "gadget chain (ysoserial or similar) is reachable on the classpath, this is RCE.",
        "Generate a payload with ysoserial for a gadget chain available on this app's classpath, then feed it to this input.",
        "likely",
    ),
    (
        "SQL Injection",
        "java",
        r"""\.(?:executeQuery|executeUpdate|execute)\s*\(\s*["'].*\+""",
        "high",
        "A SQL string built by concatenation (+ operator) is passed straight into a Statement call instead of "
        "a PreparedStatement with bound parameters.",
        "' OR 1=1 -- ",
        "likely",
    ),
    (
        "Command Injection",
        "java",
        r"""Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(""",
        "high",
        "Runtime.exec() spawns a shell/process — if any part of the command string or argument array comes "
        "from user input, this is command injection.",
        "; cat flag.txt #",
        "possible",
    ),
    (
        "Command Injection",
        "java",
        r"""new\s+ProcessBuilder\s*\(.*\+""",
        "high",
        "ProcessBuilder is constructed with a concatenated (+) argument — if the concatenated part is user "
        "input, this is command injection.",
        "; cat flag.txt #",
        "possible",
    ),
    (
        "Path Traversal / LFI",
        "java",
        r"""new\s+File\s*\(\s*.*request\.getParameter""",
        "medium",
        "A File path is built directly from a request parameter with no normalization/containment check — "
        "path traversal.",
        "../../../../etc/passwd",
        "possible",
    ),
    (
        "SSRF (Server-Side Request Forgery)",
        "java",
        r"""new\s+URL\s*\(\s*request\.getParameter""",
        "medium",
        "A URL is constructed directly from a request parameter and (presumably) fetched server-side — SSRF.",
        "http://169.254.169.254/latest/meta-data/ (cloud metadata) or an internal-only host/port.",
        "possible",
    ),
    (
        "XXE",
        "java",
        r"""DocumentBuilderFactory\.newInstance\s*\(\s*\)""",
        "medium",
        "A DocumentBuilderFactory is created with its defaults — unless external-entity/DTD processing is "
        "explicitly disabled afterward (setFeature with FEATURE_SECURE_PROCESSING / disallow-doctype-decl), "
        "this XML parser is vulnerable to XXE.",
        "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>",
        "possible",
    ),
    (
        "Weak Cryptography",
        "java",
        r"""MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']""",
        "medium",
        "MD5/SHA-1 used via MessageDigest — fine for checksums, broken for password hashing or anything "
        "security-sensitive.",
        "Look for a way to find/crack the hash offline, or exploit a length-extension/collision property.",
        "possible",
    ),
    (
        "Insecure Randomness",
        "java",
        r"""new\s+Random\s*\(\s*\)""",
        "low",
        "java.util.Random is not cryptographically secure and is seedable/predictable — if this feeds a "
        "token, password-reset code, or session id, it can likely be predicted. Use SecureRandom instead.",
        "If the seed or recent outputs are known/guessable, predict the next value(s) from java.util.Random's PRNG.",
        "possible",
    ),
    (
        "Cross-Site Scripting (XSS)",
        "java",
        r"""<%=\s*(?:request\.getParameter|request\.getAttribute)\s*\([^)]*\)\s*%>""",
        "high",
        "A JSP <%= %> expression tag directly outputs a request parameter/attribute with no escaping — JSP's "
        "<%= %> tag is always raw/unescaped by design (there's no 'safe' equivalent tag), so any "
        "request-derived value printed here is reflected XSS. (Narrower than ideal on purpose: a blanket "
        "'any non-literal <%= %>' pattern would fire on nearly every JSP page, since <%= %> has no safe form "
        "to contrast against — this only catches the direct-from-request subset, not e.g. a stored/DB value "
        "reflected the same way.)",
        "<script>alert(document.domain)</script>",
        "likely",
    ),

    # ==================== GO ====================
    (
        "Command Injection",
        "go",
        r"""exec\.Command\s*\(\s*(?:r\.|req\.|request\.)""",
        "high",
        "exec.Command's program/argument comes directly from the HTTP request — command injection.",
        "; cat flag.txt #",
        "likely",
    ),
    (
        "Command Injection",
        "go",
        r"""exec\.Command\s*\(\s*\w+\s*[,)]""",
        "medium",
        "exec.Command is called with a bare variable (not a string literal) as its program/argument — if that "
        "variable traces back to user input, this is command injection.",
        "; cat flag.txt #",
        "possible",
    ),
    (
        "SQL Injection",
        "go",
        r"""\.(?:Query|QueryRow|Exec)\s*\(\s*fmt\.Sprintf\s*\(""",
        "high",
        "A SQL query is built with fmt.Sprintf (string formatting) instead of a parameterized query ($1/? "
        "placeholders) — SQL injection if any formatted value is user-controlled.",
        "' OR 1=1 -- ",
        "likely",
    ),
    (
        "Mass Assignment",
        "go",
        r"""var\s+\w+\s+map\[string\](?:string|interface\{\})\b""",
        "medium",
        "A request handler declares a raw map[string]string/interface{} instead of a typed struct with a "
        "fixed field set — if this map is decoded directly from the request body and later re-marshaled or "
        "forwarded into another API call (auth, DB, etc.) with no field allowlist, the client controls every "
        "field of that downstream call, not just the ones the app intended to expose.",
        "Add an unexpected field (e.g. a privilege/role field) to the JSON body and see if it reaches the "
        "downstream call unfiltered.",
        "possible",
    ),
    (
        "SSRF (Server-Side Request Forgery)",
        "go",
        r"""http\.NewRequest\s*\(\s*\w+\.Method\s*,\s*\w+\s*,""",
        "medium",
        "A new outbound HTTP request is built using the inbound request's own Method and a dynamically-built "
        "URL (reverse-proxy pattern) — if the target URL/host is derived from request data without a strict "
        "allowlist, this is SSRF: the proxy will fetch whatever upstream the attacker points it at.",
        "Manipulate the Host header/URL path feeding the proxied URL to redirect the request to an "
        "internal-only host (e.g. an internal service port).",
        "possible",
    ),
    (
        "Integer Overflow / Truncation",
        "go",
        r"""(?<![.\w])uint(?:8|16|32)\s*\(\s*\w+\s*\)""",
        "medium",
        "A value is narrowed into a smaller fixed-width unsigned integer type via a bare-variable cast — if "
        "the real value can exceed that type's max (e.g. it came from len() of attacker-controlled input), "
        "it silently wraps/truncates, desyncing any length-prefixed serialization or size check built on top "
        "of it.",
        "Supply input whose real length/value exceeds the target type's max by N, so the truncated stored "
        "value becomes N — can desync a length-prefixed format or bypass a size check.",
        "possible",
    ),
    (
        "SQL Injection",
        "go",
        r"""fmt\.Sprintf\s*\(\s*["'][^"']*\b(?:SELECT\b[^"']*\bFROM|INSERT\b[^"']*\bINTO|UPDATE\b[^"']*\bSET|DELETE\b[^"']*\bFROM)\b[^"']*%[svdq]""",
        "high",
        "fmt.Sprintf is used to build a string with real SQL structure (SELECT...FROM, etc.) and a %s/%v/%d "
        "format verb — this catches the query at its construction site even when it's assigned to a variable "
        "and passed to db.Query()/Exec() several lines later.",
        "' OR 1=1 -- ",
        "likely",
    ),
    (
        "Server-Side Template Injection (SSTI)",
        "go",
        r"""template\.(?:New|Must)\s*\(.*\)\s*\.Parse\s*\(\s*(?:r\.FormValue|r\.URL\.Query\(\)\.Get|req\.FormValue|input|userInput)""",
        "high",
        "A text/template or html/template is parsed from request-controlled data instead of a fixed template "
        "file — if the template language's actions are reachable, this can lead to SSTI/RCE depending on the "
        "template package in use.",
        "{{.}} to confirm, then look for exec/FuncMap gadgets reachable from the template context.",
        "possible",
    ),
    (
        "Path Traversal / LFI",
        "go",
        r"""os\.(?:Open|ReadFile|Create)\s*\(\s*.*(?:r\.URL\.Query\(\)\.Get|r\.FormValue|r\.PostFormValue)""",
        "medium",
        "A file path is built directly from request data with no containment check — path traversal.",
        "../../../../etc/passwd",
        "possible",
    ),
    (
        "Path Traversal / LFI",
        "go",
        r"""os\.(?:Open|ReadFile|Create)\s*\(\s*\w+\s*\)""",
        "medium",
        "A file path operation uses a plain variable — if that variable traces back to request data (common "
        "with Go's plain net/http handlers reading query/form values a line or two earlier) with no "
        "containment check, this is path traversal.",
        "../../../../etc/passwd",
        "possible",
    ),
    (
        "SSRF (Server-Side Request Forgery)",
        "go",
        r"""http\.Get\s*\(\s*(?:r\.FormValue|r\.URL\.Query\(\)\.Get|req\.FormValue|\w+)\s*\)""",
        "medium",
        "http.Get() fetches a URL that is (or may be) built from request data — SSRF if the target host isn't "
        "restricted to an allowlist.",
        "http://169.254.169.254/latest/meta-data/ (cloud metadata) or an internal-only host/port.",
        "possible",
    ),
    (
        "Insecure Randomness",
        "go",
        r"""\bmath/rand\b|\brand\.Intn\s*\(""",
        "low",
        "math/rand is not cryptographically secure and is seedable/predictable — if this feeds a token, "
        "password-reset code, or session id, use crypto/rand instead.",
        "If the seed or recent outputs are known/guessable, predict the next value(s) from math/rand's PRNG.",
        "possible",
    ),

    # ==================== RUBY / RAILS ====================
    (
        "Unsafe Reflection / Insecure Dynamic Class Instantiation",
        "ruby",
        r"""\w+\[[^\]]+\]\s*\.constantize""",
        "high",
        "A string value pulled from a hash/params by key is converted to a Ruby class via .constantize — if "
        "that string is attacker-controlled, this can instantiate ANY loaded class (Mysql2::Client, "
        "Net::HTTP, etc.) with attacker-supplied constructor arguments, a well-known Rails RCE/SSRF/file-read "
        "gadget chain.",
        "Supply a gem class name (e.g. Mysql2::Client) as the type with attacker-controlled constructor args "
        "to pivot into that gem's capabilities.",
        "likely",
    ),
    (
        "SQL Injection",
        "ruby",
        r"""\.(?:where|find_by_sql)\s*\(\s*["'].*?#\{""",
        "high",
        "A where()/find_by_sql() call uses string interpolation (#{...}) instead of a parameterized condition "
        "(where(\"col = ?\", val) or a hash) — SQL injection.",
        "' OR 1=1 -- ",
        "likely",
    ),
    (
        "Command Injection",
        "ruby",
        r"""(?:system|exec|`|IO\.popen)\s*\(?[^)\n]*#\{""",
        "high",
        "A shell command (system/exec/backticks/IO.popen) is built with string interpolation (#{...}) — if "
        "the interpolated value is user-controlled, this is command injection.",
        "; cat flag.txt #",
        "likely",
    ),
    (
        "Unsafe Deserialization",
        "ruby",
        r"""Marshal\.load\s*\(|YAML\.(?:load|unsafe_load)\s*\(""",
        "high",
        "Marshal.load / YAML.load (as opposed to YAML.safe_load) will instantiate arbitrary Ruby objects from "
        "the input — a well-known Rails RCE gadget-chain vector if the input is attacker-controlled.",
        "Craft a Marshal/YAML payload using a known Rails deserialization gadget chain for RCE.",
        "possible",
    ),
    (
        "Mass Assignment",
        "ruby",
        r"""params\.permit!""",
        "high",
        "params.permit! (the bang form) disables Rails' strong-parameters filtering entirely — every "
        "attribute in the request, including ones like `admin`/`role`, can be mass-assigned.",
        "Add an extra field like admin=true/role=admin to the request body and see if it's accepted.",
        "likely",
    ),
    (
        "Server-Side Template Injection (SSTI)",
        "ruby",
        r"""render\s*\(?\s*inline:\s*params""",
        "high",
        "render inline: renders a raw ERB template string — passing request data (params) straight into it is "
        "server-side template injection, typically RCE via ERB.",
        "<%= `id` %> or <%= system('id') %>",
        "likely",
    ),
    (
        "Path Traversal / LFI",
        "ruby",
        r"""File\.(?:read|open|join)\s*\(\s*.*params\[""",
        "medium",
        "A file path is built directly from params with no containment check — path traversal.",
        "../../../../etc/passwd",
        "possible",
    ),

    # ==================== LUA ====================
    (
        "SQL Injection",
        "lua",
        r"""(?:SELECT|INSERT|UPDATE|DELETE)\b.*\.\.\s*\w+\s*\.\.""",
        "high",
        "A SQL string is built with Lua's .. concatenation operator instead of a parameterized query — SQL "
        "injection if the concatenated variable is user-controlled.",
        "' OR 1=1 -- ",
        "possible",
    ),
    (
        "Command Injection",
        "lua",
        r"""os\.execute\s*\(.*\.\.""",
        "high",
        "os.execute() is called with a string built via .. concatenation — command injection if the "
        "concatenated part is user-controlled.",
        "; cat flag.txt #",
        "possible",
    ),
    (
        "Command Injection / RCE",
        "lua",
        r"""\b(?:loadstring|load)\s*\(\s*\w""",
        "high",
        "loadstring()/load() compiles and can execute arbitrary Lua source from a (non-literal) string — if "
        "that string is user-controlled, this is direct RCE.",
        "Supply Lua source as the input, e.g. os.execute('id') if os is reachable in the sandbox.",
        "possible",
    ),

    # ==================== RUST ====================
    # Rust's safety guarantees remove most of the bug classes flagmap targets,
    # so coverage here is intentionally light — mainly the places where a
    # program still shells out, touches the filesystem from raw input, or
    # explicitly opts out of those guarantees.
    (
        "Command Injection",
        "rust",
        r"""Command::new\s*\(\s*\w+\s*\)""",
        "medium",
        "std::process::Command is constructed with a bare variable (not a string literal) as the program to "
        "run — if that variable traces back to user input, this is command injection.",
        "; cat flag.txt #",
        "possible",
    ),
    (
        "SQL Injection",
        "rust",
        r"""format!\s*\(\s*"[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"]*FROM""",
        "high",
        "A SQL query is built with the format! macro instead of a parameterized query (sqlx/diesel bind "
        "parameters) — SQL injection if any formatted value is user-controlled.",
        "' OR 1=1 -- ",
        "likely",
    ),
    (
        "Path Traversal / LFI",
        "rust",
        r"""std::fs::(?:read|read_to_string|write|File::open)\s*\(\s*\w+\s*\)""",
        "medium",
        "A filesystem call is made with a bare variable path — if it traces back to user input with no "
        "containment check, this is path traversal.",
        "../../../../etc/passwd",
        "possible",
    ),
    (
        "Memory Safety Bypass",
        "rust",
        r"""\bunsafe\s*\{""",
        "low",
        "An unsafe block opts out of Rust's memory-safety guarantees for the code inside it — worth a manual "
        "look for the usual C-style memory corruption bugs (bounds, use-after-free, raw pointer misuse) that "
        "safe Rust would normally prevent.",
        "Manually audit the unsafe block for memory-safety violations; this isn't something a regex can confirm.",
        "possible",
    ),
]


# Pattern payload-texts that are expected to fire constantly on legitimate
# test fixtures (e.g. password = "testpassword123") and add noise rather
# than signal there. scanner.py suppresses matches of these specific rules
# when the file looks like a test file (see scanner.is_test_file()).
NOISY_IN_TEST_FILES = {
    "Try the hardcoded value directly as a login/API credential.",
}


def compiled_patterns():
    """Return RAW_PATTERNS with regexes compiled, as a list of dicts."""
    compiled = []
    for name, lang, pattern, severity, why, payload, confidence in RAW_PATTERNS:
        compiled.append({
            "name": name,
            "language": lang,
            "regex": re.compile(pattern, re.IGNORECASE),
            "severity": severity,
            "why": why,
            "payload": payload,
            "confidence": confidence,
        })
    return compiled


# Map file extensions to our internal language tags.
EXTENSION_LANGUAGE = {
    ".php": "php",
    ".php3": "php",
    ".php4": "php",
    ".php5": "php",
    ".phtml": "php",
    ".py": "python",
    ".pyw": "python",
    ".js": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".ts": "js",
    ".html": "html",
    ".htm": "html",
    ".ejs": "ejs",
    ".hbs": "handlebars",
    ".handlebars": "handlebars",
    ".cs": "csharp",
    ".cshtml": "csharp",
    ".java": "java",
    ".jsp": "java",
    ".go": "go",
    ".rb": "ruby",
    ".erb": "ruby",
    ".lua": "lua",
    ".rs": "rust",
}

# Directories we never want to crawl into (noise, not challenge source).
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
    "dist", "build", ".idea", ".vscode",
    # per-language build/dependency output added alongside Java/Go/Ruby/Rust support
    "target", "bin", "obj", ".gradle", ".m2", "bundle", "gems",
}
