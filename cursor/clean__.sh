#!/bin/bash
# cursor-reset.sh — Diagnose and fix a frozen Cursor on macOS.. beta..

set -e

echo "Checking for runaway Cursor/ripgrep processes..."
PROCS=$(ps uaxww | grep -E "(Cursor|ripgrep|/rg )" | grep -v grep)
if [ -n "$PROCS" ]; then
  echo "$PROCS"
  echo ""
  read -p "Kill all Cursor processes? (y/n) " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    pkill -9 -f "Cursor" 2>/dev/null && echo "Done." || echo "No processes to kill."
  fi
else
  echo "No runaway processes found."
fi

echo ""
echo "Clearing Cursor caches..."
rm -rf ~/Library/Application\ Support/Cursor/GPUCache
rm -rf ~/Library/Application\ Support/Cursor/CachedData
rm -rf ~/Library/Application\ Support/Cursor/Cache
rm -rf ~/Library/Application\ Support/Cursor/Code\ Cache
rm -rf ~/Library/Application\ Support/Cursor/User/workspaceStorage
echo "Caches cleared."

echo ""
echo "Checking for corrupted ~/.cursor file..."
if [ -f ~/.cursor ]; then
  read -p "Found a ~/.cursor FILE (not directory) -- delete it? (y/n) " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -f ~/.cursor && echo "Deleted ~/.cursor file."
  fi
else
  echo "No corrupted ~/.cursor file found."
fi

echo ""
read -p "Perform FULL factory reset? This deletes extensions & settings (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo "Backing up settings first..."
  BACKUP_DIR=~/Desktop/cursor-backup-$(date +%Y%m%d-%H%M%S)
  mkdir -p "$BACKUP_DIR"
  cp ~/Library/Application\ Support/Cursor/User/settings.json "$BACKUP_DIR/" 2>/dev/null || true
  cp ~/Library/Application\ Support/Cursor/User/keybindings.json "$BACKUP_DIR/" 2>/dev/null || true
  echo "Settings backed up to $BACKUP_DIR"

  rm -rf ~/Library/Application\ Support/Cursor
  rm -rf ~/.cursor
  echo "Full reset complete."
fi

echo ""
echo "Done. You can now reopen Cursor."
