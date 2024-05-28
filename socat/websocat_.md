#! /usr/bin/bash

# Using WebSocat
# https://github.com/vi/websocat/blob/master/moreexamples.md

# Reset by killing process
#
# 1. Get all processes
# 2. general regexp to find websocat process di
# 3. Get the second column of results
# 4. Get the first result
# 5. Kill that process
# 
# kill $(ps aux | grep websocat | awk '{print $2}' | head -n 1)

# Configuration
TARGET_URL=wss://yourgraphql.com/v1/graphql
LOCALHOST=127.0.0.1
LOCALPORT=6543

# Absolute path to websocat
CMD=~/Downloads/websocat.x86_64-unknown-linux-musl

# Parameters used
# -t                     Send message to WebSockets as text messages
# tcp-l                  Listen TCP port on specified address
# -E                     Close a data transfer direction if the other one reached EOF
# reuse-raw    
# --max-messages-rev     Maximum number of messages to copy in the other direction

echo " ⏳️ Connecting to WebSocat..."
${CMD} -t -E tcp-l:${LOCALHOST}:${LOCALPORT} reuse-raw:${TARGET_URL} --max-messages-rev 2&

# Store websocket process id
WS_PID=$!
echo " 🚀 Websocat connection created (${WS_PID})!"

TABLE_NAME="accounts"
HASURA_ADMIN_SECRET="somesecret"
# Send message to websocat

echo " 🌏️ Initiating Hasura graphql subscription..."
echo "{    \"type\": \"connection_init\",    \"payload\": {      \"headers\": {        \"X-Hasura-Admin-Secret\": \"${HASURA_ADMIN_SECRET}\",        \"BP-Customer-IP-Address\": \"127.0.0.1\"      }    }  }" | nc ${LOCALHOST} ${LOCALPORT}

echo " 🌏️ Requesting three accounts from the account service..."
echo "{    \"id\": \"1\",    \"type\": \"start\",    \"payload\": {      \"variables\": {},      \"extensions\": {},      \"operationName\": \"GetThreeAccounts\",      \"query\": \"query GetThreeAccounts {   ${TABLE_NAME}(limit: 3) {     id   } }\"    }  }" | nc ${LOCALHOST} ${LOCALPORT} | jq

echo '{"id":"1","type": "stop"}' | nc ${LOCALHOST} ${LOCALPORT} | jq
echo " ✅ Done!"
echo " 🗑️  Websocat connection disposed."
kill ${WS_PID}

##
##
