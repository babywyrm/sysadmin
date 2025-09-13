#!/bin/bash
#
# WordPress/Nginx/Apache Stress Tester (ultra-simple-and-super-lame curl version) .. (..testing..)
#

TARGET="http://127.0.0.1/"
RUNTIME=30   # seconds per test
BURST=5      # how many requests in a burst
FUZZ_PATHS=("wp-login.php" "xmlrpc.php" "admin-ajax.php")

timestamp() {
  date +"%H:%M:%S"
}

log_curl() {
  url=$1
  ts=$(timestamp)
  curl -s -o /dev/null -w "[$ts] %U Lookup=%{time_namelookup}s Connect=%{time_connect}s StartTransfer=%{time_starttransfer}s Total=%{time_total}s Code=%{http_code}\n" "$url"
}

steady_test() {
  echo "=== Steady Test ==="
  end=$((SECONDS+RUNTIME))
  while [ $SECONDS -lt $end ]; do
    log_curl "$TARGET"
    sleep 1
  done
}

burst_test() {
  echo "=== Burst Test ==="
  end=$((SECONDS+RUNTIME))
  while [ $SECONDS -lt $end ]; do
    for i in $(seq 1 $BURST); do
      log_curl "$TARGET" &
    done
    wait
    sleep 1
  done
}

fuzz_test() {
  echo "=== Fuzz Test ==="
  end=$((SECONDS+RUNTIME))
  while [ $SECONDS -lt $end ]; do
    if [ $((RANDOM % 2)) -eq 0 ]; then
      path=${FUZZ_PATHS[$RANDOM % ${#FUZZ_PATHS[@]}]}
    else
      path=$(head /dev/urandom | tr -dc a-z | head -c 8)
    fi
    url="${TARGET%/}/$path"
    log_curl "$url"
    sleep 1
  done
}

echo "Starting curl tests against $TARGET"
steady_test
burst_test
fuzz_test
echo "Done."
