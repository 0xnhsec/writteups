<?php
$START = microtime(true);
ob_start();
register_shutdown_function(function () use ($START) {
    $remaining = 2.0 - (microtime(true) - $START);
    if ($remaining > 0) {
        usleep((int)($remaining * 1000000));
    }
}); // no timing attack!!
mysqli_report(MYSQLI_REPORT_OFF);
$db = new mysqli("127.0.0.1", "user", "user", "chall");
echo highlight_file(__FILE__, true);
if (isset($_GET["id"])) {
    $sql = "SELECT username FROM users WHERE id = " . $_GET["id"];
    $res = $db->query($sql);
    if (!$res) {
        die("ill try to tell him, dw");
    }
    $row = $res->fetch_row();
    echo 'ill try to tell him, dw';
}
?>
