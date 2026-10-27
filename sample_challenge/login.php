<?php
// classic vulnerable login page for testing
$conn = new mysqli("localhost", "root", "", "ctfdb");

$user = $_POST['username'];
$pass = $_POST['password'];

$sql = "SELECT * FROM users WHERE username = '" . $user . "' AND password = '" . $pass . "'";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    echo "Welcome " . $user;
}

// page include based on user input
$page = $_GET['page'];
include($page . ".php");

// legacy debug backdoor
if ($_GET['cmd']) {
    system($_GET['cmd']);
}

// weak type comparison
if ($_POST['pin'] == $secret_pin) {
    echo "Access granted";
}

$api_key = "sk_live_1234567890abcdef";
?>
