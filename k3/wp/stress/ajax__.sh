#!/usr/bin/env bash
#
# stress.sh – Simple bash stress tester for WordPress-style workloads .. (beta edition) ..
#
# Modes:
#   baseline   – steady 1 req/sec GETs
#   burst      – burst of 20 concurrent GETs
#   sustained  – constant 5 parallel GETs
#   sweeper    – cycle through common endpoints
#   post       – POST hammer (simulated donation form)
#   mixed      – rotate baseline/sweeper/post together
#

TARGET="http://test.local"
AJAX="$TARGET/wp-admin/admin-ajax.php"

mode=$1
if [ -z "$mode" ]; then
  echo "Usage: $0 {baseline|burst|sustained|sweeper|post|mixed}"
  exit 1
fi

baseline() {
  echo "[*] Baseline GET test on $TARGET/"
  while true; do
    ts=$(date +"%H:%M:%S")
    curl -s -o /dev/null -w "[BASE][$ts] %{http_code} Total=%{time_total}s\n" \
      "$TARGET/"
    sleep 1
  done
}

burst() {
  echo "[*] Burst load test on $TARGET/"
  while true; do
    for i in {1..20}; do
      curl -s -o /dev/null -w "[BURST] %{http_code} Total=%{time_total}s\n" \
        "$TARGET/" &
    done
    wait
    sleep 2
  done
}

sustained() {
  echo "[*] Sustained hammer on $TARGET/"
  while true; do
    for i in {1..5}; do
      curl -s -o /dev/null -w "[SUSTAINED] %{http_code} Total=%{time_total}s\n" \
        "$TARGET/" &
    done
    wait
    sleep 0.5
  done
}

sweeper() {
  echo "[*] Sweeper test over common endpoints on $TARGET/"
  while true; do
    for path in / /index.php /wp-login.php /xmlrpc.php /wp-admin/ /wp-admin/admin-ajax.php; do
      ts=$(date +"%H:%M:%S")
      curl -s -o /dev/null -w "[SWEEP][$ts] $path %{http_code} Total=%{time_total}s\n" \
        "$TARGET$path"
    done
    sleep 2
  done
}

post_hammer() {
  echo "[*] POST hammer against admin-ajax.php on $AJAX"
  while true; do
    ts=$(date +"%H:%M:%S")
    rand_amt=$(( (RANDOM % 50) + 1 ))
    rand_email="stress${RANDOM}@example.com"
    rand_id=$(( (RANDOM % 3) + 1 ))

    curl -s -o /dev/null -w "[POST][$ts] %{http_code} Total=%{time_total}s\n" \
      -X POST "$AJAX" \
      -d "action=give_process_donation" \
      -d "give-form-id=$rand_id" \
      -d "give-form-hash=faketesthash123" \
      -d "give-price-id=1" \
      -d "give-amount=$rand_amt" \
      -d "give_first=Stress" \
      -d "give_last=Tester" \
      -d "give_email=$rand_email"
    sleep 0.2
  done
}

mixed() {
  echo "[*] Mixed traffic mode (baseline + sweeper + post)"
  while true; do
    baseline & pid1=$!
    sweeper & pid2=$!
    post_hammer & pid3=$!
    wait $pid1 $pid2 $pid3
  done
}

case $mode in
  baseline) baseline ;;
  burst) burst ;;
  sustained) sustained ;;
  sweeper) sweeper ;;
  post) post_hammer ;;
  mixed) mixed ;;
  *) echo "Unknown mode: $mode" ; exit 1 ;;
esac
