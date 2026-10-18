#!/usr/bin/env bash

# Terminal Streaming Setup
# Streams terminal output to a web browser in real-time ..beta..

set -euo pipefail

# Configuration
LOCALHOST="127.0.0.1"
WS_PORT=5555
HTTP_PORT=8080

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if websocat is installed
if ! command -v websocat &> /dev/null; then
    echo -e "${YELLOW}Warning: websocat not found. Installing...${NC}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install websocat
    else
        echo "Please install websocat: https://github.com/vi/websocat"
        exit 1
    fi
fi

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    [[ -n "${WS_PID:-}" ]] && kill "$WS_PID" 2>/dev/null || true
    [[ -n "${HTTP_PID:-}" ]] && kill "$HTTP_PID" 2>/dev/null || true
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# Create HTML file
HTML_FILE="/tmp/terminal-stream.html"
cat > "$HTML_FILE" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Terminal Stream</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        h1 {
            margin-bottom: 20px;
            color: #4ec9b0;
        }
        .status {
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 20px;
            font-weight: 500;
        }
        .connected { background: #1a472a; color: #4ec9b0; }
        .disconnected { background: #5a1a1a; color: #f48771; }
        #terminal {
            background: #0a0a0a;
            padding: 20px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.5;
            white-space: pre-wrap;
            word-wrap: break-word;
            min-height: 400px;
            max-height: 80vh;
            overflow-y: auto;
            border: 1px solid #333;
        }
        .instructions {
            margin-top: 20px;
            padding: 15px;
            background: #2d2d30;
            border-radius: 4px;
        }
        code {
            background: #1e1e1e;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Terminal Stream</h1>
        <div id="status" class="status disconnected">Connecting...</div>
        <div id="terminal"></div>
        <div class="instructions">
            <strong>Setup:</strong><br>
            In your terminal, run:<br>
            <code>exec &gt; &gt;(tee &gt;(websocat -n ws://127.0.0.1:5555/)) 2&gt;&amp;1</code>
        </div>
    </div>
    <script>
        const terminal = document.getElementById('terminal');
        const status = document.getElementById('status');
        let ws;
        let reconnectAttempts = 0;
        const maxReconnectAttempts = 5;

        function connect() {
            ws = new WebSocket('ws://localhost:5555/');
            
            ws.onopen = () => {
                console.log('Connected to terminal stream');
                status.textContent = 'Connected';
                status.className = 'status connected';
                reconnectAttempts = 0;
            };
            
            ws.onmessage = (event) => {
                terminal.textContent += event.data;
                terminal.scrollTop = terminal.scrollHeight;
            };
            
            ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
            
            ws.onclose = () => {
                console.log('Disconnected from terminal stream');
                status.textContent = 'Disconnected';
                status.className = 'status disconnected';
                
                if (reconnectAttempts < maxReconnectAttempts) {
                    reconnectAttempts++;
                    console.log(`Reconnecting... (${reconnectAttempts}/${maxReconnectAttempts})`);
                    setTimeout(connect, 2000);
                }
            };
        }
        
        connect();
    </script>
</body>
</html>
EOF

# Start WebSocket server
echo -e "${BLUE}Starting WebSocket server on port ${WS_PORT}...${NC}"
websocat -t "ws-l:${LOCALHOST}:${WS_PORT}" broadcast:mirror: &
WS_PID=$!
sleep 1

# Start HTTP server
echo -e "${BLUE}Starting HTTP server on port ${HTTP_PORT}...${NC}"
if command -v python3 &> /dev/null; then
    (cd /tmp && python3 -m http.server "$HTTP_PORT" > /dev/null 2>&1) &
    HTTP_PID=$!
else
    echo -e "${YELLOW}Warning: Python3 not found, skipping HTTP server${NC}"
fi

echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo -e "${BLUE}Instructions:${NC}"
echo ""
echo "1. Open your browser to:"
echo -e "   ${GREEN}http://localhost:${HTTP_PORT}/terminal-stream.html${NC}"
echo ""
echo "2. In another terminal, run this command to stream your terminal:"
echo -e "   ${YELLOW}exec > >(tee >(websocat -n ws://${LOCALHOST}:${WS_PORT}/)) 2>&1${NC}"
echo ""
echo "Press Ctrl+C to stop all servers"
echo ""

# Keep script running
wait
