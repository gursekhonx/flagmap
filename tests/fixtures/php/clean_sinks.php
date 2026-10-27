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
