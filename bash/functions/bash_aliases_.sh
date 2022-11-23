## ALIASES FILE 
##
##

#!/bin/bash
function package-version {
   apt-cache policy $1 | grep Installed | awk -F ' ' '{print $2}'
}

function kernel-current-version {
   major=$(uname -r | awk -F '.' '{print $1}')
   minor=$(uname -r | awk -F '.' '{print $2}')
   if [ $(uname -r | grep rc) ]; then
      rc="rc$(uname -r | awk -F '-' '{print $2}' | awk -F 'rc' '{print $2}')"
      echo "$major.$minor-$rc"
   else
      echo "$major.$minor"
   fi
}

function kernel-latest-version {
   kernel=$(lynx -dump http://kernel.ubuntu.com/~kernel-ppa/mainline/ | tail -1 | cut -d ' ' -f 3)
   major=$(echo $kernel | awk -F '/' '{print $6}' | awk -F '-' '{print $1}' | cut -c 2-)
   if [ $(uname -r | grep rc) ]; then
      minor=$(echo $kernel | awk -F '/' '{print $6}' | awk -F '-' '{print $2}')
      echo "$major-$minor"
   else
      echo $major
   fi
}

function shutdown {
   echo "Are you sure you want to shut down $(hostname)?"; read input
   case "$input" in
      y* | Y*) sudo shutdown -h now ;;
      *) echo "Cancelling request to shut down $(hostname)." ;;
   esac
}

function reboot {
   echo "Are you sure you want to reboot $(hostname)?"; read input
   case "$input" in
      y* | Y*) sudo reboot
      *) echo "Cancelling request to reboot $(hostname)."
   esac
}

function diskfree {
   case "$1" in
      "home" | "/home") df -BGiB | grep /home | awk -F ' ' '{print $4}' ;;
      "root" | "/") df -BGiB | grep / | awk -F ' ' '{print $4}' ;;
      *) df -BGiB | grep "$1" | awk -F ' ' '{print $4}' ;;
   esac
}

function cpuinfo {
   cores=$(nproc)
   frequency=$(grep MHz /proc/cpuinfo | head -1 | awk -F ' ' '{print $4" MHz"}')
   model=$(grep "model name" /proc/cpuinfo | head -1 | sed -r 's/^.{13}//')
   echo "CPU Model: $model"
   echo "CPU Cores: $cores"
   echo "Frequency: $frequency"
}

function raminfo {
   size=$(sudo dmidecode --type 20 | grep Size | head -1 | awk -F ' ' '{print $3" GB"}')   
   detail=$(sudo dmidecode --type 17 | grep "Type Detail:" | head -1 | awk -F ' ' '{print $3}')
   type=$(sudo dmidecode --type 17 | grep Type: | head -1 | awk -F ' ' '{print $2}')
   frequency=$(sudo dmidecode --type 17 | grep -i speed | head -1 | awk -F ' ' '{print $2" MHz"}')
   echo "$size $detail $type $frequency"
}

function amazon-search {
   search=$(zenity --entry --title="Amazon Search")
 
   if [ "$input" == "" ]; then
      exit
   else
      xdg-open "http://www.amazon.com/s/field-keywords=$search"
   fi
}

function google-image-search {
   input=$(zenity --entry --title="Google Image Searcher")
   search=$(echo $input | sed 's/ /+/g')
 
   if [ "$input" == "" ]; then
      exit
   else
      xdg-open "http://images.google.com/images?q=$search&tbm=isch&tbs=isz:l"
   fi
}

function gdb-tracer {
   gdb $1 2>&1 | tee ~/gdb-$1.txt
}

function kernel-upgrader {
   cd /tmp
   sudo rm *.deb

   if [ "$(apt-cache policy lynx | grep Installed | awk -F ' ' '{print $2}')" == "(none)" ]; then
      sudo apt-get install lynx -y
   fi

   if [ "$(getconf LONG_BIT)" = "64" ]; then arch=amd64; else arch=i386; fi

   function download() {
      wget $(lynx -dump -listonly -dont-wrap-pre $kernelURL | grep "$1" | grep "$2" | grep "$arch" | cut -d ' ' -f 4)
   }

   read -p "Do you want the latest RC?" rc
   case "$rc" in
      y* | Y*) kernelURL=$(lynx -dump http://kernel.ubuntu.com/~kernel-ppa/mainline/ | tail -1 | cut -d ' ' -f 3) ;;
      n* | N*) kernelURL=$(lynx -dump http://kernel.ubuntu.com/~kernel-ppa/mainline/ | grep -v rc | tail -1 | cut -d ' ' -f 3) ;;
      *) exit ;;
   esac

   read -p "Do you want the lowlatency kernel?" lowlatency
   case "$lowlatency" in
      y* | Y*) lowlatency=1 ;;
      n* | n*) lowlatency=0 ;;
      *) exit ;;
   esac

   # Download Kernel
   if [ "$lowlatency" == "0" ]; then
      echo "Downloading the latest generic kernel."
      download generic header
      download generic image
   elif [ "$lowlatency" == "1" ]; then
      echo "Downloading the latest lowlatency kernel."
      download lowlatency header
      download lowlatency image
   fi

   # Shared Kernel Header
   wget $(lynx -dump -listonly -dont-wrap-pre $kernelURL | grep all | cut -d ' ' -f 4)

   # Install Kernel
   echo "Installing Linux Kernel"
   sudo dpkg -i linux*.deb
   echo "Done. You may now reboot."
}

###########
##
##
