#!/bin/bash
# WordPress leak checker
# Usage: ./check.sh [URL]

TARGET=${1:-http://getbusy.htb}
CURL_OPTS="-s -L --max-time 10"

echo "=== Testing WordPress leaks at $TARGET ==="

# 1. REST API users
echo -n "[*] Checking /wp-json/wp/v2/users ... "
resp=$(curl $CURL_OPTS -o - -w "%{http_code}" "$TARGET/wp-json/wp/v2/users")
if [[ "$resp" == *"200"* && "$resp" == *"id"* ]]; then
  echo "Users exposed"
else
  echo "Blocked"
fi

# 2. User sitemap
echo -n "[*] Checking /wp-sitemap-users-1.xml ... "
resp=$(curl $CURL_OPTS "$TARGET/wp-sitemap-users-1.xml")
if echo "$resp" | grep -q "<loc>"; then
  echo "Sitemap leaks users"
else
  echo "Blocked"
fi

# 3. Author ID enumeration
echo -n "[*] Checking ?author=2 ... "
loc=$(curl $CURL_OPTS -i "$TARGET/?author=2" | grep -i "^Location:" | awk '{print $2}' | tr -d '\r')
if [[ "$loc" =~ "/author/" ]]; then
  echo "Author redirect leaks username ($loc)"
else
  echo "Blocked"
fi

# 4. Login error messages
echo "[*] Checking login form responses"
fake=$(curl $CURL_OPTS -d "log=fakeuser&pwd=wrong" "$TARGET/wp-login.php" | grep -o "Error:[^<]*")
real=$(curl $CURL_OPTS -d "log=admin&pwd=wrong" "$TARGET/wp-login.php" | grep -o "Error:[^<]*")

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
