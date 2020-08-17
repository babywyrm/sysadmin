<?php
$data = json_decode($HTTP_RAW_POST_DATA,true);
$to = 'myemail@example.com';
$subject = 'CSP Violations';
$message="Following violations occured:<br/><br/>";
if($document_uri!="")
    $message.="<b>Document URI:</b> ".$data['csp-report']['document-uri']."<br/><br/>";
if($referrer!="")
    $message.="<b>Referrer:</b> ".$data['csp-report']['referrer']."<br/><br/>";
if($blocked_uri!="")
    $message.="<b>Blocked URI:</b> ".$data['csp-report']['blocked_uri']."<br/><br/>";
if($violated_directive!="")
    $message.="<b>Violated Directive:</b> ".$data['csp-report']['violated_directive']."<br/><br/>";
if($original_policy!="")
    $message.="<b>Original Policy:</b> ".$data['csp-report']['original_policy']."<br/><br/>";

// To send HTML mail, the Content-type header must be set
$headers  = 'MIME-Version: 1.0' . "\r\n";
$headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";
$headers .= 'From: Example Website <noreply@example.com>' . "\r\n";

// Mail it
mail($to, $subject, $message, $headers);
