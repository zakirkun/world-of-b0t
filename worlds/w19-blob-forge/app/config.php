<?php
// BLOB FORGE :: configuration + the one secret that never leaves the box.
//
// W0B_FLAG is injected into the container environment at runtime. It is NOT
// written into any web-served file and nothing here prints it: the only way to
// read it is to run code inside this process (see the fix note in the writeup).
//
// NOTE ON THE ENVIRONMENT: Apache's default ClearEnv wipes /proc/self/environ,
// so /proc/self/environ is NOT a usable source here and the CLI-only $_SERVER
// superglobal is empty under mod_php. getenv() reads the exported Docker ENV
// directly and is the only reliable path. Verified against php:8.3-apache.

function lab_flag(): string
{
    $flag = getenv('W0B_FLAG');
    return ($flag === false || $flag === '') ? 'hex4b0t{flag_not_injected}' : $flag;
}
