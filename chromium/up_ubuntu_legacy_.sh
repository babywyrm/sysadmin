#!/bin/bash

# based on
# http://askubuntu.com/questions/112432/chromium-19-for-ubuntu
# http://paste.ubuntu.com/1110824/

set -u
set -e

notify() {
  local body="$1"
  notify-send "$SCRIPT" "$body"
}

error() {
  local msg="$1"
  notify-send -u critical "$SCRIPT" "$msg"
  exit 1
}

if [ -n "$(uname -a | grep 'x86_64')" ] ; then
    LINUX=Linux_x64
else
    LINUX=Linux
fi
ICON=--icon=chromium
SCRIPT="Chromium Updater $LINUX"

CHROMIUM="$(chromium-browser --version || echo "Not Installed")"

CURRENT_FILE=~/.config/chromium/build.number

if [ -f $CURRENT_FILE ] ; then
  CURRENT="$(cat $CURRENT_FILE)"
else
  CURRENT="$(echo "123456" > $CURRENT_FILE)"
fi

LATEST="$(curl http://commondatastorage.googleapis.com/chromium-browser-continuous/$LINUX/LAST_CHANGE)"

notify "current:${CURRENT} -> latest:${LATEST}"
DIR=$HOME/my-chromium

if [ "$LATEST" -gt "$CURRENT" ] ; then
  #notify "We got new Chromium($LATEST), Updating!"
  cd $DIR
  if [ $? -ne 0 ];then
    error "cannot cd to $DIR"
  fi
  rm -rf chrome-linux*
  wget http://commondatastorage.googleapis.com/chromium-browser-continuous/${LINUX}/${LATEST}/chrome-linux.zip
  unzip chrome-linux.zip
  echo $LATEST > $CURRENT_FILE
  notify "We've updated Chromium $CHROMIUM($LATEST)!"
fi

echo

if [ "$LATEST" -eq "$CURRENT" ] ; then
  notify "You're already have latest version $CHROMIUM($CURRENT)"
fi

echo

if [ "$LATEST" -lt "$CURRENT" ] ; then
  notify "Seems like your version newer than one at server? $CHROMIUM($LATEST), RLLY?!"
fi

echo

exit 0

###########
##
##
