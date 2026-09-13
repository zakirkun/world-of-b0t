<?php
require __DIR__ . '/lib.php';
w0b_session_start();
session_unset();
session_destroy();
header('Location: /index.php');
