#!/bin/bash
# WordPress leak checker .. pretty tiny edition ..
# Usage: ./THING.sh [URL]
# Example: ./THING.sh http://getbusy.htb

set -euo pipefail

TARGET=${1:-http://getbusy.htb}
CURL_OPTS=(-s -L --max-time 10)

echo "=== Testing WordPress leaks at $TARGET ==="

# --- Helpers ---
get() {
  curl "${CURL_OPTS[@]}" "$1"
}

get_headers() {
  curl "${CURL_OPTS[@]}" -i "$1"
}

post() {
  curl "${CURL_OPTS[@]}" -d "$1" "$2"
}

# 1. REST API users
echo -n "[*] /wp-json/wp/v2/users ... "
resp=$(get "$TARGET/wp-json/wp/v2/users")
if [[ "$resp" == *'"id":'* && "$resp" == *'"name":'* ]]; then
  echo "Users exposed"
else
  echo "Blocked"
fi

# 2. User sitemap
echo -n "[*] /wp-sitemap-users-1.xml ... "
resp=$(get "$TARGET/wp-sitemap-users-1.xml")
if grep -q "<loc>" <<<"$resp"; then
  echo "Sitemap leaks users"
else
  echo "Blocked"
fi

# 3. Author ID enumeration
echo -n "[*] ?author=2 ... "
loc=$(get_headers "$TARGET/?author=2" | awk '/^Location:/ {print $2}' | tr -d '\r')
if [[ "$loc" =~ "/author/" ]]; then
  echo "Author redirect leaks username ($loc)"
else
  echo "Blocked"
fi

# 4. Login error messages
echo "[*] Login form responses"
fake=$(post "log=fakeuser&pwd=wrong" "$TARGET/wp-login.php" | grep -o "Error:[^<]*" || true)
real=$(post "log=admin&pwd=wrong" "$TARGET/wp-login.php" | grep -o "Error:[^<]*" || true)

if [[ "$fake" =~ "not registered" ]]; then
  echo "   Fake user: Reveals existence ($fake)"
else
  echo "   Fake user: Generic message"
fi

if [[ "$real" =~ "incorrect" ]]; then
  echo "   Real user: Reveals username ($real)"
else
  echo "   Real user: Generic message"
fi

