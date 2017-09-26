<?php

/**
 * Get SSH daemon fingerprint
 * Part of the Configuration compiler for ConfigServer Firewall & LFD project
 * -----------------------------------------------------------------------------
 * By Adam "Adambean" Reece - www.reece.wales
 * https://github.com/Adambean/compile-csf
 *
 * Use this tool to fetch the fingerprint of an SSH daemon suitable for use in
 * your server list file. This will be a SHA-1 hash sum.
 *
 * Simply specify the SSH daemon address as the 1st command argument, be it an
 * IP address, host name, or FQDN. Optionally specify the port number (1-65535)
 * as the 2nd command argument. (Do not write it as host:port!)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * "LICENSE" for the specific language governing permissions and limitations
 * under the License.
 */

if (!is_array($argv) || $argc < 2) {
    printf("[Error] No host address specified.\n");
    exit(1);
}

$serverHost = null;
if (!$serverHost = trim($argv[1])) {
    printf("[Error] Empty host address specified.\n");
    exit(1);
}

$serverPort = 22;
if ($argc >= 3 && !$serverPort = intval($argv[2])) {
    $serverPort = 22;
}

if (!is_int($serverPort) || $serverPort < 1 || $serverPort > 65535) {
    printf("[Error] Port number must be an integer from 1 to 65535 inclusive.\n");
    exit(1);
}


// Show server name
printf("%s:%d:\n\n", $serverHost, $serverPort);

// << SSH connection: Open
printf("Establishing SSH link...\n");

$linkSsh        = null;
$linkSshAuthed  = false;

try {
    if (!function_exists("ssh2_connect")) {
        throw new \Exception("SSH2 for PHP is not installed.\n");
    }

    if (!$linkSsh || !is_resource($linkSsh)) {
        $linkSsh = null;
        $linkSsh = @ssh2_connect($serverHost, $serverPort);
    }

    // Failed completely...
    if (!$linkSsh || !is_resource($linkSsh)) {
        $linkSsh = null;
        printf("[Error] SSH connection couldn't be established!\n");
        exit(1);
    }
} catch (\Exception $e) {
    printf("[Error] SSH connection failed: %s\n", $e->getMessage());
    exit(1);
}

if (!$sshFingerprint = trim(ssh2_fingerprint($linkSsh, SSH2_FINGERPRINT_SHA1 | SSH2_FINGERPRINT_HEX))) {
    printf("[Error] SSH server did not return a fingerprint!\n");
    exit(1);
}

printf("SSH fingerprint is: %s\n", $sshFingerprint);
exit(0);
