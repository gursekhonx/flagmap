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
