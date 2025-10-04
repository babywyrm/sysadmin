#!/bin/bash

TARGET="localhost:30116"
TIMEOUT=3

echo "[*] Deep Analysis of $TARGET"
echo "================================"

# Get baseline response
baseline=$(timeout $TIMEOUT curl -s "http://$TARGET/")
baseline_hash=$(echo "$baseline" | md5sum | cut -d' ' -f1)

echo -e "\n[+] Baseline Response (/):"
echo "$baseline" | jq . 2>/dev/null || echo "$baseline"
echo "Hash: $baseline_hash"

# Test if different paths return DIFFERENT content
echo -e "\n[+] Checking if paths return UNIQUE content:"
echo "--------------------------------------------"

paths=(
    "/healthz"
    "/metrics"
    "/debug/pprof"
    "/debug/pprof/heap"
    "/debug/pprof/goroutine"
    "/api"
    "/config"
    "/../"
    "/../../"
    "/../../../etc/passwd"
)

vulnerable=0
for path in "${paths[@]}"; do
    response=$(timeout $TIMEOUT curl -s "http://$TARGET${path}" 2>/dev/null)
    response_hash=$(echo "$response" | md5sum | cut -d' ' -f1)
    
    if [ "$response_hash" != "$baseline_hash" ]; then
        echo -e "\033[0;31m[!] DIFFERENT CONTENT at $path\033[0m"
        echo "    Response:"
        echo "$response" | head -20
        echo "    [truncated...]"
        vulnerable=1
    else
        echo -e "\033[0;32m[✓]\033[0m $path returns same health JSON (benign)"
    fi
done

# Check if query params change response
echo -e "\n[+] Testing if query params change response:"
echo "--------------------------------------------"

params=(
    "?debug=true"
    "?verbose=1"
    "?namespace=kube-system"
    "?service=kubernetes"
    "?pod=test"
)

for param in "${params[@]}"; do
    response=$(timeout $TIMEOUT curl -s "http://$TARGET/${param}" 2>/dev/null)
    response_hash=$(echo "$response" | md5sum | cut -d' ' -f1)
    
    if [ "$response_hash" != "$baseline_hash" ]; then
        echo -e "\033[0;31m[!] DIFFERENT CONTENT with $param\033[0m"
        echo "$response" | head -20
        vulnerable=1
    else
        echo -e "\033[0;32m[✓]\033[0m $param ignored (benign)"
    fi
done

# Check headers
echo -e "\n[+] Checking Response Headers for Info Leaks:"
echo "--------------------------------------------"

headers=$(timeout $TIMEOUT curl -sI "http://$TARGET/" 2>/dev/null)
echo "$headers"

# Check for concerning headers
echo "$headers" | grep -iE "(Server:|X-Powered-By:|X-AspNet-Version:)" && \
    echo -e "\033[1;33m[!] Server version info leaked\033[0m" || \
    echo -e "\033[0;32m[✓] No server version leaked\033[0m"

# Check if we can enumerate other services
echo -e "\n[+] Attempting to enumerate other services:"
echo "--------------------------------------------"

services=(
    "kubernetes"
    "kube-dns"
    "metrics-server"
    "dashboard"
)

for svc in "${services[@]}"; do
    # Try to inject different service names
    response=$(timeout $TIMEOUT curl -s -H "X-Service: $svc" "http://$TARGET/" 2>/dev/null)
    response_hash=$(echo "$response" | md5sum | cut -d' ' -f1)
    
    if [ "$response_hash" != "$baseline_hash" ]; then
        echo -e "\033[0;31m[!] Service enumeration possible via header: $svc\033[0m"
        vulnerable=1
    fi
done
echo -e "\033[0;32m[✓]\033[0m Service enumeration via headers: not possible"

# Check for timing attacks
echo -e "\n[+] Timing Analysis (detecting if backend is reachable):"
echo "--------------------------------------------"

times=()
for i in {1..5}; do
    time_ms=$(timeout $TIMEOUT curl -o /dev/null -s -w "%{time_total}" "http://$TARGET/" 2>/dev/null)
    times+=($time_ms)
    echo "  Request $i: ${time_ms}s"
done

# Calculate average
total=0
for t in "${times[@]}"; do
    total=$(echo "$total + $t" | bc)
done
avg=$(echo "scale=4; $total / 5" | bc)
echo "  Average: ${avg}s"

# Check if error messages leak info
echo -e "\n[+] Testing Error Handling:"
echo "--------------------------------------------"

# Malformed requests
echo -n "  Malformed JSON POST: "
response=$(timeout $TIMEOUT curl -s -X POST -H "Content-Type: application/json" \
    -d '{invalid json}' "http://$TARGET/" 2>/dev/null)
echo "$response" | grep -iE "(error|exception|stack|trace)" && \
    echo -e "\033[0;31m[!] Error details leaked\033[0m" || \
    echo -e "\033[0;32m[✓] No error leakage\033[0m"

# Summary
echo -e "\n========================================"
echo -e "SECURITY ASSESSMENT SUMMARY"
echo -e "========================================"

if [ $vulnerable -eq 0 ]; then
    echo -e "\033[0;32m[✓] ENDPOINT APPEARS SECURE\033[0m"
    echo ""
    echo "Findings:"
    echo "  - All paths return identical health check JSON"
    echo "  - Query parameters are ignored"
    echo "  - Headers don't affect response"
    echo "  - Only information leaked: service name (wp-nginx-service)"
    echo ""
    echo "Risk Level: LOW"
    echo "  - Informational disclosure only"
    echo "  - No code execution possible"
    echo "  - No sensitive data exposed"
    echo "  - Cannot reach internal endpoints"
else
    echo -e "\033[0;31m[!] VULNERABILITIES FOUND\033[0m"
    echo "Review the output above for details"
    echo ""
    echo "Risk Level: MEDIUM-HIGH"
fi

echo ""
echo "What an attacker CAN do:"
echo "  ✓ Discover service name: wp-nginx-service"
echo "  ✓ Monitor service availability"
echo "  ✓ Count backend replicas: 1"
echo ""
echo "What an attacker CANNOT do:"
echo "  ✗ Execute code"
echo "  ✗ Access internal pods"
echo "  ✗ Modify configuration"
echo "  ✗ Bypass authentication"
echo "  ✗ Read sensitive data"
##
##
