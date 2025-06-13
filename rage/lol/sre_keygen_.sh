#!/usr/bin/env bash
set -euo pipefail

USERS_FILE=/etc/ctf-users
KEY_BASE=/etc/sre-keys
LOG=/var/log/sre-keygen.log

# ensure keydir on tmpfs
mkdir -m700 -p $KEY_BASE

# pick a random user
mapfile -t USERS < "$USERS_FILE"
COUNT=${#USERS[@]}
if (( COUNT == 0 )); then
  echo "$(date): no users in $USERS_FILE" >> "$LOG"
  exit 1
fi
IDX=$(( RANDOM % COUNT ))
USER=${USERS[$IDX]}

# ensure the user exists, with no-login shell
if ! id "$USER" &>/dev/null; then
  useradd --create-home --shell /usr/sbin/nologin "$USER"
  echo "$(date): created user $USER" >> "$LOG"
fi

# prepare .ssh
KEYDIR="$KEY_BASE/$USER"
mkdir -m700 -p "$KEYDIR"
chown "$USER":"$USER" "$KEYDIR"

# generate keypair if absent or stale
PRIV="$KEYDIR/id_ed25519"
PUB="$KEYDIR/id_ed25519.pub"
if [ ! -f "$PRIV" ]; then
  sudo -u "$USER" rage ed25519 \
    -o "$PRIV" \
    -O "$PUB"
  chmod 600 "$PRIV"
  chmod 644 "$PUB"
  chown "$USER":"$USER" "$PRIV" "$PUB"
  echo "$(date): generated new key for $USER" >> "$LOG"
fi

# install to their authorized_keys
mkdir -m700 -p /home/"$USER"/.ssh
cat "$PUB" >/home/"$USER"/.ssh/authorized_keys
chmod 600 /home/"$USER"/.ssh/authorized_keys
chown -R "$USER":"$USER" /home/"$USER"/.ssh

echo "$(date): deployed key for $USER" >> "$LOG"
