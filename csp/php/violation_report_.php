<?php
  /**
   * This isn’t working and neither was the original: https://git.io/fjtZ9
   * Matt Ferderer referred me to an excellent replacement: https://report-uri.com
   */

  // $requestContent and $data replace $HTTP_RAW_POST_DATA via @naitsirch git.io/fjtqx
  /*
  $requestContent = file_get_contents("php://input");
  $data           = json_decode($requestContent, TRUE);
  $to             = 'myemail@example.com';
  $subject        = 'CSP Violations';
  $message        = "Following violations occurred:<br/><br/>";
  if ($document_uri != "") {
    $message .= "<b>Document URI:</b> " . $data['csp-report']['document-uri'] . "<br/><br/>";
  }
  if ($referrer != "") {
    $message .= "<b>Referrer:</b> " . $data['csp-report']['referrer'] . "<br/><br/>";
  }
  if ($blocked_uri != "") {
    $message .= "<b>Blocked URI:</b> " . $data['csp-report']['blocked-uri'] . "<br/><br/>";
  }
  if ($violated_directive != "") {
    $message .= "<b>Violated Directive:</b> " . $data['csp-report']['violated-directive'] . "<br/><br/>";
  }
  if ($original_policy != "") {
    $message .= "<b>Original Policy:</b> " . $data['csp-report']['original-policy'] . "<br/><br/>";
  }
  */


  // To send HTML mail, the Content-Type header must be set
  /*
  $headers = 'MIME-Version: 1.0' . "\r\n";
  $headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";
  $headers .= 'From: Example Website <noreply@example.com>' . "\r\n";
  */

  // Mail it
  /*
  mail($to, $subject, $message, $headers);
  */
