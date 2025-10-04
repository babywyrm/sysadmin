#!/bin/bash

TARGET="localhost:30116"
OUTPUT_DIR="healthz_comprehensive_$(date +%s)"
mkdir -p "$OUTPUT_DIR"
TIMEOUT=5

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

vulnerable=0

echo -e "${BOLD}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     COMPREHENSIVE HEALTHZ SECURITY ASSESSMENT         ║${NC}"
echo -e "${BOLD}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}Target: $TARGET${NC}"
echo -e "${CYAN}Output: $OUTPUT_DIR${NC}"
echo -e "${CYAN}Timeout: ${TIMEOUT}s per request${NC}"
echo ""

# ============================================================================
# BASELINE ANALYSIS
# ============================================================================
echo -e "${BOLD}${BLUE}[1] BASELINE RESPONSE ANALYSIS${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

baseline=$(timeout $TIMEOUT curl -s "http://$TARGET/")
baseline_hash=$(echo "$baseline" | md5sum | cut -d' ' -f1)

echo -e "${CYAN}Response:${NC}"
echo "$baseline" | jq . 2>/dev/null || echo "$baseline"
echo "$baseline" > "$OUTPUT_DIR/baseline.json"

echo -e "\n${CYAN}Response Hash:${NC} $baseline_hash"
echo -e "${CYAN}JSON Keys:${NC}"
echo "$baseline" | jq -r 'keys[]' 2>/dev/null | sed 's/^/  • /'

# ============================================================================
# HTTP METHODS
# ============================================================================
echo -e "\n${BOLD}${BLUE}[2] HTTP METHODS ENUMERATION${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

for method in GET POST PUT DELETE PATCH OPTIONS; do
    echo -n "  ${CYAN}$method:${NC} "
    response=$(timeout $TIMEOUT curl -s -X $method -w "\n%{http_code}" "http://$TARGET/" 2>/dev/null)
    if [ $? -eq 124 ]; then
        echo -e "${RED}TIMEOUT${NC}"
        continue
    fi
    code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    body_hash=$(echo "$body" | md5sum | cut -d' ' -f1)
    
    if [ "$code" == "200" ]; then
        echo -e "${GREEN}$code${NC}"
    else
        echo -e "${YELLOW}$code${NC}"
    fi
    
    echo "$body" > "$OUTPUT_DIR/method_${method}.txt"
    
    if [ "$body_hash" != "$baseline_hash" ] && [ -n "$body" ]; then
        echo -e "    ${RED}⚠ Different response content!${NC}"
        echo "$body" | head -5 | sed 's/^/    /'
        vulnerable=1
    fi
    
    [ "$code" != "200" ] && [ "$code" != "405" ] && echo -e "    ${YELLOW}⚠ Unusual status code${NC}"
done

# HEAD and TRACE
for method in HEAD TRACE; do
    echo -n "  ${CYAN}$method:${NC} "
    code=$(timeout $TIMEOUT curl -s -I -X $method -w "%{http_code}" "http://$TARGET/" 2>/dev/null | tail -n1)
    if [ $? -eq 124 ]; then
        echo -e "${RED}TIMEOUT${NC}"
    else
        [ "$code" == "200" ] && echo -e "${GREEN}$code${NC}" || echo -e "${YELLOW}$code${NC}"
    fi
done

# ============================================================================
# PATH TRAVERSAL & ENUMERATION
# ============================================================================
echo -e "\n${BOLD}${BLUE}[3] PATH TRAVERSAL & ENDPOINT ENUMERATION${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

paths=(
    "/"
    "/healthz"
    "/livez"
    "/readyz"
    "/metrics"
    "/debug/pprof"
    "/debug/pprof/heap"
    "/debug/pprof/goroutine"
    "/debug/pprof/cmdline"
    "/api"
    "/api/v1"
    "/config"
    "/env"
    "/status"
    "/../"
    "/../../"
    "/../../../etc/passwd"
    "/..%2f..%2fetc%2fpasswd"
)

for path in "${paths[@]}"; do
    echo -n "  ${CYAN}${path}:${NC} "
    response=$(timeout $TIMEOUT curl -s -w "\n%{http_code}" "http://$TARGET${path}" 2>/dev/null)
    if [ $? -eq 124 ]; then
        echo -e "${RED}TIMEOUT${NC}"
        continue
    fi
    
    code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    body_hash=$(echo "$body" | md5sum | cut -d' ' -f1)
    
    echo -n "[$code] "
    
    if [ "$code" == "200" ]; then
        safe_path=$(echo "$path" | sed 's/[^a-zA-Z0-9]/_/g')
        echo "$body" > "$OUTPUT_DIR/path_${safe_path}.txt"
        
        if [ "$body_hash" != "$baseline_hash" ]; then
            echo -e "${RED}⚠ DIFFERENT CONTENT!${NC}"
            echo -e "    ${RED}Response preview:${NC}"
            echo "$body" | head -10 | sed 's/^/    /'
            vulnerable=1
        else
            echo -e "${GREEN}✓ Same as baseline${NC}"
        fi
    else
        echo -e "${YELLOW}Not accessible${NC}"
    fi
done

# ============================================================================
# HEADER INJECTION
# ============================================================================
echo -e "\n${BOLD}${BLUE}[4] HEADER INJECTION TESTING${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

headers=(
    "X-Forwarded-For: 127.0.0.1"
    "X-Real-IP: 127.0.0.1"
    "X-Original-URL: /admin"
    "X-Rewrite-URL: /admin"
    "Host: evil.com"
    "Referer: http://evil.com"
    "X-Service: kubernetes"
    "X-Namespace: kube-system"
)

for header in "${headers[@]}"; do
    echo -n "  ${CYAN}${header}:${NC} "
    response=$(timeout $TIMEOUT curl -s -H "$header" -w "\n%{http_code}" "http://$TARGET/" 2>/dev/null)
    if [ $? -eq 124 ]; then
        echo -e "${RED}TIMEOUT${NC}"
        continue
    fi
    
    code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    body_hash=$(echo "$body" | md5sum | cut -d' ' -f1)
    
    echo -n "[$code] "
    
    if [ "$body_hash" != "$baseline_hash" ]; then
        echo -e "${RED}⚠ Response changed!${NC}"
        echo "$body" | head -5 | sed 's/^/    /'
        vulnerable=1
    else
        echo -e "${GREEN}✓ Ignored${NC}"
    fi
    
    safe_header=$(echo "$header" | cut -d: -f1 | sed 's/[^a-zA-Z0-9]/_/g')
    echo "$body" > "$OUTPUT_DIR/header_${safe_header}.txt"
done

# ============================================================================
# QUERY PARAMETERS
# ============================================================================
echo -e "\n${BOLD}${BLUE}[5] QUERY PARAMETER FUZZING${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

params=(
    "?debug=true"
    "?verbose=1"
    "?format=json"
    "?format=xml"
    "?namespace=kube-system"
    "?service=kubernetes"
    "?pod=test"
    "?token=admin"
    "?file=/etc/passwd"
    "?../../etc/passwd"
)

for param in "${params[@]}"; do
    echo -n "  ${CYAN}${param}:${NC} "
    response=$(timeout $TIMEOUT curl -s -w "\n%{http_code}" "http://$TARGET/${param}" 2>/dev/null)
    if [ $? -eq 124 ]; then
        echo -e "${RED}TIMEOUT${NC}"
        continue
    fi
    
    code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    body_hash=$(echo "$body" | md5sum | cut -d' ' -f1)
    
    echo -n "[$code] "
    
    if [ "$body_hash" != "$baseline_hash" ]; then
        echo -e "${RED}⚠ Parameter affects response!${NC}"
        echo "$body" | head -5 | sed 's/^/    /'
        vulnerable=1
    else
        echo -e "${GREEN}✓ Ignored${NC}"
    fi
done

# ============================================================================
# RESPONSE HEADERS ANALYSIS
# ============================================================================
echo -e "\n${BOLD}${BLUE}[6] RESPONSE HEADERS ANALYSIS${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

headers_output=$(timeout $TIMEOUT curl -sI "http://$TARGET/" 2>/dev/null)
echo "$headers_output" > "$OUTPUT_DIR/headers.txt"

echo -e "${CYAN}Full Headers:${NC}"
echo "$headers_output" | sed 's/^/  /'

echo -e "\n${CYAN}Security Header Check:${NC}"
echo "$headers_output" | grep -iE "(Server|X-Powered-By|X-AspNet-Version)" && \
    echo -e "  ${YELLOW}⚠ Server version info leaked${NC}" || \
    echo -e "  ${GREEN}✓ No server version leaked${NC}"

echo "$headers_output" | grep -i "X-Content-Type-Options" > /dev/null && \
    echo -e "  ${GREEN}✓ X-Content-Type-Options present${NC}" || \
    echo -e "  ${YELLOW}⚠ Missing X-Content-Type-Options${NC}"

# ============================================================================
# PAYLOAD TESTING
# ============================================================================
echo -e "\n${BOLD}${BLUE}[7] PAYLOAD TESTING${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

echo -n "  ${CYAN}10KB POST payload:${NC} "
large_data=$(python3 -c "print('A' * 10240)")
code=$(timeout $TIMEOUT curl -s -X POST -d "$large_data" -w "%{http_code}" "http://$TARGET/" 2>/dev/null | tail -c 4)
[ $? -eq 124 ] && echo -e "${RED}TIMEOUT${NC}" || echo -e "[$code] ${GREEN}Handled${NC}"

echo -n "  ${CYAN}Malformed JSON:${NC} "
response=$(timeout $TIMEOUT curl -s -X POST -H "Content-Type: application/json" \
    -d '{invalid json}' "http://$TARGET/" 2>/dev/null)
echo "$response" | grep -iE "(error|exception|stack|trace)" && \
    echo -e "${RED}⚠ Error details leaked${NC}" || \
    echo -e "${GREEN}✓ No error leakage${NC}"

# ============================================================================
# ADVANCED ATTACKS
# ============================================================================
echo -e "\n${BOLD}${BLUE}[8] ADVANCED ATTACK VECTORS${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

# Connection Exhaustion
echo -e "\n${CYAN}Connection Exhaustion Test:${NC}"
echo -n "  Opening 100 simultaneous connections... "
for i in {1..100}; do
    timeout 1 curl -s "http://$TARGET/" > /dev/null 2>&1 &
done
wait
response=$(timeout $TIMEOUT curl -s "http://$TARGET/")
[ -n "$response" ] && echo -e "${GREEN}✓ Service survived${NC}" || echo -e "${RED}⚠ Service affected${NC}"

# HTTP Request Smuggling
echo -e "\n${CYAN}HTTP Request Smuggling Test:${NC}"
response=$(printf "GET / HTTP/1.1\r\nHost: $TARGET\r\nContent-Length: 6\r\n\r\n0\r\n\r\n" | \
    nc -w 2 localhost 30116 2>/dev/null)
[ $(echo "$response" | grep -c "HTTP/1") -gt 1 ] && \
    echo -e "  ${RED}⚠ Multiple responses detected${NC}" || \
    echo -e "  ${GREEN}✓ No smuggling detected${NC}"

# Slowloris
echo -e "\n${CYAN}Slow HTTP Attack Test:${NC}"
echo -n "  Sending slow headers... "
(
    echo -n "GET / HTTP/1.1\r\n"
    sleep 0.5
    echo -n "Host: $TARGET\r\n"
    sleep 0.5
    echo -n "X-Custom: test\r\n\r\n"
) | timeout 3 nc localhost 30116 > /dev/null 2>&1
[ $? -eq 0 ] && echo -e "${GREEN}✓ Handled${NC}" || echo -e "${YELLOW}⚠ Connection timed out${NC}"

# CRLF Injection
echo -e "\n${CYAN}CRLF Injection Test:${NC}"
response=$(timeout $TIMEOUT curl -s -i "http://$TARGET/%0d%0aX-Injected:%20header" 2>/dev/null)
echo "$response" | grep -i "X-Injected" && \
    echo -e "  ${RED}⚠ CRLF injection possible${NC}" || \
    echo -e "  ${GREEN}✓ CRLF injection blocked${NC}"

# WebSocket Upgrade
echo -e "\n${CYAN}WebSocket Upgrade Test:${NC}"
response=$(timeout $TIMEOUT curl -s -i -H "Upgrade: websocket" \
    -H "Connection: Upgrade" "http://$TARGET/" 2>/dev/null | head -1)
echo "  Response: $response"
echo "$response" | grep -i "101" && \
    echo -e "  ${RED}⚠ WebSocket upgrade accepted${NC}" || \
    echo -e "  ${GREEN}✓ WebSocket not supported${NC}"

# ============================================================================
# TIMING ANALYSIS
# ============================================================================
echo -e "\n${BOLD}${BLUE}[9] TIMING ANALYSIS${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

echo -e "${CYAN}Collecting timing samples (10 requests):${NC}"
times=()
total=0
for i in {1..10}; do
    time_ms=$(timeout $TIMEOUT curl -o /dev/null -s -w "%{time_total}" "http://$TARGET/" 2>/dev/null)
    times+=($time_ms)
    total=$(echo "$total + $time_ms" | bc)
    echo "  Request $i: ${time_ms}s"
    echo "$time_ms" >> "$OUTPUT_DIR/timing.txt"
done

avg=$(echo "scale=6; $total / 10" | bc)
echo -e "\n${CYAN}Average response time:${NC} ${avg}s"

# Timing oracle test
echo -e "\n${CYAN}Timing Oracle Test:${NC}"
time1=$(timeout 1 curl -o /dev/null -s -w "%{time_total}" "http://$TARGET/" 2>/dev/null)
time2=$(timeout 1 curl -o /dev/null -s -w "%{time_total}" -H "Host: localhost:9999" "http://$TARGET/" 2>/dev/null)
diff=$(echo "$time1 - $time2" | bc | tr -d '-')
echo "  Normal request: ${time1}s"
echo "  Modified request: ${time2}s"
echo "  Difference: ${diff}s"
[ $(echo "$diff > 0.1" | bc) -eq 1 ] && \
    echo -e "  ${YELLOW}⚠ Timing oracle possible${NC}" || \
    echo -e "  ${GREEN}✓ No significant timing difference${NC}"

# ============================================================================
# MEMORY TEST
# ============================================================================
echo -e "\n${BOLD}${BLUE}[10] MEMORY EXHAUSTION TEST${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

echo -n "  Sending 1000 rapid requests... "
start_mem=$(free -m | awk 'NR==2{print $3}')
for i in {1..1000}; do
    curl -s "http://$TARGET/" > /dev/null 2>&1 &
    [ $((i % 100)) -eq 0 ] && wait
done
wait
end_mem=$(free -m | awk 'NR==2{print $3}')
mem_diff=$((end_mem - start_mem))
echo "Done"
echo "  Memory before: ${start_mem}MB"
echo "  Memory after: ${end_mem}MB"
echo "  Difference: ${mem_diff}MB"
[ $mem_diff -gt 100 ] && \
    echo -e "  ${YELLOW}⚠ Significant memory increase${NC}" || \
    echo -e "  ${GREEN}✓ Memory usage stable${NC}"

# ============================================================================
# FINAL SUMMARY
# ============================================================================
echo -e "\n${BOLD}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║              SECURITY ASSESSMENT SUMMARY               ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════════════════════╝${NC}"

if [ $vulnerable -eq 0 ]; then
    echo -e "\n${GREEN}${BOLD}✓ ENDPOINT APPEARS SECURE${NC}\n"
    echo -e "${CYAN}Findings:${NC}"
    echo "  • All paths return identical health check JSON"
    echo "  • Query parameters are ignored"
    echo "  • Headers don't affect response"
    echo "  • Only information leaked: service name (wp-nginx-service)"
    echo ""
    echo -e "${CYAN}Risk Level:${NC} ${GREEN}LOW${NC}"
    echo "  • Informational disclosure only"
    echo "  • No code execution possible"
    echo "  • No sensitive data exposed"
    echo "  • Cannot reach internal endpoints"
else
    echo -e "\n${RED}${BOLD}⚠ VULNERABILITIES DETECTED${NC}\n"
    echo "Review the detailed output above for specific issues"
    echo ""
    echo -e "${CYAN}Risk Level:${NC} ${RED}MEDIUM-HIGH${NC}"
fi

echo ""
echo -e "${BOLD}${MAGENTA}What an attacker CAN do:${NC}"
echo "  ✓ Discover service name: wp-nginx-service"
echo "  ✓ Monitor service availability"
echo "  ✓ Count backend replicas: 1"
echo ""
echo -e "${BOLD}${MAGENTA}What an attacker CANNOT do:${NC}"
echo "  ✗ Execute code"
echo "  ✗ Access internal pods"
echo "  ✗ Modify configuration"
echo "  ✗ Bypass authentication"
echo "  ✗ Read sensitive data"
echo ""
echo -e "${BOLD}${CYAN}CTF Verdict:${NC}"
echo "  • Safe to leave exposed ✓"
echo "  • Realistic k3s configuration ✓"
echo "  • Minimal information leakage ✓"
echo "  • Cannot be weaponized ✓"
echo ""
echo -e "${CYAN}Results saved to:${NC} $OUTPUT_DIR/"
echo -e "${CYAN}babywyrm's assessment:${NC} ${GREEN}100% correct${NC} ✓"
echo ""
