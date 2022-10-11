#!/bin/bash
#
#
# https://gist.github.com/n1k0/304554/b10fd1b86df922b7a5647b7b8636b882d8b5ad99#
#
# This script will try to upgrade to latest OSX Chromium build on your system 
# via the command line (right, that means you'll have to open a term)
#
# Use with CAUTION, quick and dirty homemade script. At least, works on my box.
#
# Installation:
#
#   1. the download way
#     $ cd ~/bin
#     $ curl -O http://gist.github.com/gists/304554/download
#     $ tar xvzf download
#     $ mv gist304554-*/getchromium.sh .
#     $ chmod +x getchromium.sh
#
#   2. The git way 
#     $ cd ~/bin
#     $ git clone git://gist.github.com/304554.git .
#     $ chmod +x getchromium.sh
#
# Run it that way:
#   $ ./getchromium.sh

die() {
  echo "$@ => exiting" >&2
  exit 1
}

W=`whoami`
TMP="/tmp"
BASE_URL="http://build.chromium.org/buildbot/snapshots/chromium-rel-mac"
ARCHIVE_NAME="chrome-mac.zip"
LATEST_URL="$BASE_URL/LATEST"
LATEST_VERSION=`curl -s -f $LATEST_URL` || die "Unable to fetch latest version number"
PROC=`ps aux|grep -i Chromium|grep -iv grep|grep -iv getchromium|wc -l|awk '{print $1}'` || die "Unable to count running Chromium processes"
INSTALL_DIR="/Applications"

# The script should never be run by root
if [[ $W == "root" ]]; then
  die "This script cannot be run as root"
fi

# Checking if latest available build version number is newer than installed one
if [[ -f $TMP/current-chromium-version ]]; then
  INSTALLED_VERSION=`cat $TMP/current-chromium-version`
  if [[ $LATEST_VERSION -eq $INSTALLED_VERSION ]]; then
    die "You already have the latest build ($LATEST_VERSION) installed"
  fi
fi

# Testing if Chromium is currently running
if [[ ! $PROC -eq 0 ]]; then 
  die "You must quit Chromium in order to install a new version"
fi

# Fetching latest archive if not already existing in tmp dir
if [[ ! -f $TMP/chromium-$LATEST_VERSION.zip ]]; then
  echo "Fetching chromium build $LATEST_VERSION, please wait..."
  curl -O "$BASE_URL/$LATEST_VERSION/$ARCHIVE_NAME" || die "Unable to fetch version $LATEST_VERSION archive"
  mv $ARCHIVE_NAME $TMP/chromium-$LATEST_VERSION.zip || die "Unable to move downloaded archive to $TMP directory"
fi

# Unzipping
unzip -qq -u -d $TMP/chromium-$LATEST_VERSION $TMP/chromium-$LATEST_VERSION.zip || die "Unable to unzip version $LATEST_VERSION archive"

# Deleting previously installed version
if [[ -d $INSTALL_DIR/Chromium.app ]]; then
  rm -rf $INSTALL_DIR/Chromium.app || die "Unable to delete previous installed version of Chromium"
fi

# Installing new version
mv -f $TMP/chromium-$LATEST_VERSION/chrome-mac/Chromium.app $INSTALL_DIR || die "Unable to install fetched Chromium version"
echo "Chromium build $LATEST_VERSION succesfully installed"

# Cleaning
rm -r $TMP/chromium-$LATEST_VERSION
rm $TMP/chromium-$LATEST_VERSION.zip

# Updating log
echo $LATEST_VERSION > $TMP/current-chromium-version

#########
##
##
