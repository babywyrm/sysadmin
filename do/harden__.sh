#!/bin/bash
# digitalocean_metadata_lockdown.sh ..beta..
# Harden a DO droplet by scrubbing metadata and disabling further fetches

set -euo pipefail

echo "[*] Disabling cloud-init..."
sudo touch /etc/cloud/cloud-init.disabled
sudo systemctl disable cloud-init 2>/dev/null || true
sudo systemctl stop cloud-init 2>/dev/null || true

echo "[*] Removing cached metadata..."
sudo rm -rf /var/lib/cloud/*
sudo rm -rf /run/cloud-init/*
sudo rm -rf /var/log/cloud-init*.log

echo "[*] Blocking metadata service at 169.254.169.254..."
# IPv4
if command -v iptables >/dev/null 2>&1; then
  sudo iptables -A OUTPUT -d 169.254.169.254 -j REJECT
  echo "iptables rule added for IPv4 metadata service"
fi
# IPv6 link-local (just in case)
if command -v ip6tables >/dev/null 2>&1; then
  sudo ip6tables -A OUTPUT -d fe80::a9fe:a9fe/128 -j REJECT || true
fi

echo "[*] Making firewall rules persistent..."
if command -v netfilter-persistent >/dev/null 2>&1; then
  sudo netfilter-persistent save
elif command -v iptables-save >/dev/null 2>&1; then
  sudo sh -c "iptables-save > /etc/iptables.rules"
fi

echo "[*] Metadata lockdown complete."

##
##
