<?php
$conn = new mysqli("localhost", "user", "pass", "db");

function search() {
    global $conn;
    $name = $_GET['name'];
    $conn->query("SELECT * FROM users WHERE name = '" . $name . "'");  // ruleid: SQL Injection
}

function search2() {
    global $conn;
    $name = $_GET['name'];
    mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");  // ruleid: SQL Injection
}

function ping() {
    $host = $_GET['host'];
    system("ping -c 1 " . $host);  // ruleid: Command Injection
}

function shellEx() {
    $host = $_GET['host'];
    shell_exec("ping -c 1 " . $host);  // ruleid: Command Injection
}

function readFile() {
    $fname = $_GET['fname'];
    fopen($fname, "r");  // ruleid: Path Traversal / LFI
}

function loadInclude() {
    $page = $_GET['page'];
    include($page . ".php");  // ruleid: Path Traversal / LFI
}

function loadData() {
    $data = $_GET['data'];
    unserialize($data);  // ruleid: Unsafe Deserialization
}

function serveAudio() {
    // Mirrors DownUnderCTF 2024's real "sniffy" web challenge
    // (src/audio.php) almost verbatim: a tainted path concatenated one
    // line, then streamed with readfile() several lines later — must be
    // caught by cross-statement AST taint tracking, not a same-line regex.
    $file = 'audio/' . $_GET['f'];
    if (!file_exists($file)) {
        http_response_code(404);
        return;
    }
    readfile($file);  // ruleid: Path Traversal / LFI
}

function calc() {
    $expr = $_GET['expr'];
    eval($expr);  // ruleid: Command Injection / RCE
}

function showName() {
    $name = $_GET['name'];
    echo $name;  // ruleid: Cross-Site Scripting (XSS)
}

function runQuery($q) {
    global $conn;
    $conn->query($q);  // ruleid: SQL Injection
}

function search3() {
    global $conn;
    // one-hop interprocedural: tainted at the call site, must seed
    // runQuery's own $q parameter for the sink inside it to fire.
    $name = $_GET['name'];
    runQuery("SELECT * FROM users WHERE name = '" . $name . "'");
}

function ldapLogin() {
    $link = ldap_connect("localhost");
    $uid = $_GET['uid'];
    $filter = "(uid=" . $uid . ")";
    ldap_search($link, "dc=example,dc=com", $filter);  // ruleid: LDAP Injection
}

function proxy() {
    $url = $_GET['url'];
    $body = file_get_contents($url);  // ruleid: SSRF (Server-Side Request Forgery)
}

function xxe() {
    // Deliberately no safe-parsing guard anywhere in this file — see the
    // guarded counterpart in clean_sinks.php. (Careful: don't restate
    // xxe_guard.py's actual marker call here, or this file would
    // suppress its own finding — the same self-referential trap
    // loot.py's docstring fell into earlier.)
    $xml = simplexml_load_string($_POST['xml']);  // ruleid: XML External Entity (XXE)
    return $xml;
}

function sqlConstructMultiLine() {
    // the Mutillidae II SQLQueryHandler.php shape: a query assembled via
    // "." concatenation across several physical lines, assigned to a
    // variable patterns.py's regexes don't special-case ($query/$sql only),
    // then passed to a custom wrapper method name patterns.py's sink list
    // doesn't recognize at all — see sql_construct.py's module docstring.
    global $conn;
    $username = $_GET['username'];
    $query = "SELECT * FROM accounts " .  // ruleid: SQL Injection
        "WHERE username='" . $username .
        "'";
    return $conn->runQuery($query);
}

function sqlConstructInlineInterp() {
    // the other shape sql_construct.py covers: PHP double-quoted-string
    // inline interpolation, with no "." operator anywhere on the line —
    // patterns.py's rules require either the sink call or a $_GET/etc.
    // superglobal on the same line, neither of which is true here.
    global $conn;
    $username = $_GET['username'];
    $query = "SELECT * FROM accounts WHERE username='$username'";  // ruleid: SQL Injection
    return $conn->runQuery($query);
}

function xxdStyleUpload() {
    // Mirrors DownUnderCTF 2023's real "xxd-server": the client's own
    // filename (and so its extension) becomes part of the destination
    // path, and the file is written with file_put_contents(), not
    // move_uploaded_file().
    $upload_dir = 'uploads/' . bin2hex(random_bytes(8));
    $upload_path = $upload_dir . '/' . basename($_FILES['file-upload']['name']);  // ruleid: Unrestricted File Upload
    file_put_contents($upload_path, file_get_contents($_FILES['file-upload']['tmp_name']));
}
