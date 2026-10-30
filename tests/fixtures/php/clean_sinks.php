<?php
$conn = new mysqli("localhost", "user", "pass", "db");

function h($s) {
    return htmlspecialchars($s, ENT_QUOTES);
}

function showNameSafe() {
    $name = $_GET['name'];
    echo h($name);  // safe: Cross-Site Scripting (XSS)
}

function showNameSafe2() {
    $name = $_GET['name'];
    echo htmlspecialchars($name);  // safe: Cross-Site Scripting (XSS)
}

function showIdSafe() {
    $id = $_GET['id'];
    echo (int)$id;  // safe: Cross-Site Scripting (XSS)
}

function searchSafe() {
    global $conn;
    $name = $_GET['name'];
    // prepared statement placeholder — the tainted value never reaches the
    // query string itself, just gets bound afterward.
    $stmt = $conn->prepare("SELECT * FROM users WHERE name = ?");  // safe: SQL Injection
    $stmt->bind_param("s", $name);
}

function pingSafe() {
    // fixed, non-tainted argument
    system("echo hello");  // safe: Command Injection
}

function ldapLoginSafe() {
    $link = ldap_connect("localhost");
    // fixed, non-tainted filter
    ldap_search($link, "dc=example,dc=com", "(uid=admin)");  // safe: LDAP Injection
}

function proxySafe() {
    // fixed, non-tainted URL
    $body = file_get_contents("https://api.example.com/status");  // safe: SSRF (Server-Side Request Forgery)
}

function xxeSafe() {
    // the call shape alone (`simplexml_load_string(...)`) is exactly what
    // patterns.py's XXE regex matches on, same as the vulnerable case in
    // vuln_sinks.php — what's different here, and what xxe_guard.py must
    // pick up on, is the libxml_disable_entity_loader(true) call below,
    // which makes external-entity resolution unavailable file-wide.
    libxml_disable_entity_loader(true);
    $xml = simplexml_load_string($_POST['xml']);  // safe: XML External Entity (XXE)
    return $xml;
}

function readFileSafeIntval() {
    // cross-line sanitizer case: intval() guarantees $fname can only ever
    // be a plain integer by the time it reaches fopen() — deliberately NOT
    // on the same line as $_GET, so this is a pure AST-taint-tracking test
    // (patterns.py's same-line fopen($_GET...) regex can't match here at
    // all, since $_GET never appears on the fopen() line itself).
    $fname = $_GET['fname'];
    $fname = intval($fname);
    fopen($fname, "r");  // safe: Path Traversal / LFI
}

function readFileSafeCast() {
    // same idea, but via a (int) cast instead of intval() — both clear
    // taint the same way, see ast_engine.py's PHP_SAFE_CAST_TYPES.
    $fname = $_GET['fname'];
    $fname = (int)$fname;
    fopen($fname, "r");  // safe: Path Traversal / LFI
}
