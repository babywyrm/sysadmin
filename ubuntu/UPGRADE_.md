


##
#
https://gist.github.com/bocharsky-bw/fc692baacc07f0e430d5
#
##


```
#!/bin/bash

TEXT_RESET='\e[0m'
TEXT_YELLOW='\e[0;33m'
TEXT_RED_B='\e[1;31m'
TEXT_BLUE='\e[0;36m'

export NEEDRESTART_MODE=a
export DEBIAN_FRONTEND=noninteractive
## Questions that you really, really need to see (or else). ##
export DEBIAN_PRIORITY=critical

echo -e $TEXT_BLUE
echo 'Begin APT Clean...'
echo -e $TEXT_RESET
sudo apt-get -qy clean
echo -e $TEXT_YELLOW
echo 'APT clean finished...'
echo -e $TEXT_RESET

echo -e $TEXT_BLUE
echo 'Begin APT Update...'
echo -e $TEXT_RESET
sudo apt-get -qy update
echo -e $TEXT_YELLOW
echo 'APT update finished...'
echo -e $TEXT_RESET

echo -e $TEXT_BLUE
echo 'Begin APT Dist-Upgrade...'
echo -e $TEXT_RESET
sudo apt-get -qy -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold" dist-upgrade
echo -e $TEXT_YELLOW
echo 'APT distributive upgrade finished...'
echo -e $TEXT_RESET

echo -e $TEXT_BLUE
echo 'Begin APT Autoremove...'
echo -e $TEXT_RESET
sudo apt autoremove -y
echo -e $TEXT_YELLOW
echo 'APT auto remove finished...'
echo -e $TEXT_RESET

if [ -f /var/run/reboot-required ]; then
    echo -e $TEXT_RED_B
    echo 'Reboot required!'
    echo -e $TEXT_RESET
else
    echo -e $TEXT_BLUE
    echo 'No Reboot Required! Exiting...'
    sleep 2
    echo -e $TEXT_RESET
    exit
fi

echo -e $TEXT_RED_B
echo "Update Complete! Press Y/N to reboot."
echo -e $TEXT_RESET

while true; do
    read -p "Would you like to reboot now? " yn
    case $yn in
        [Yy]* ) sudo reboot; break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no!";;
    esac
done
```
##
##

Hey @yodaphone. Nice work! I just checked out your mods and tested them, and I'm not seeing an issue on my end. Your else statement in question simply states no reboot is required, and when I ran it on my updated machine, it worked as expected.

Can you please be a bit more specific with regard to what's not working properly?

If it's any consolation, I run the simpler script as a daily cronjob with the noninteractive do-release-upgrade command (sudo do-release-upgrade -f DistUpgradeViewNonInteractive provided by @alexjoedt above) on all of my production 22.04 servers without any issues.

Perhaps something like this may be more fitting:

```
#!/bin/bash

TEXT_RESET='\e[0m'
TEXT_RED_B='\e[1;31m'

sudo apt-get update 

sudo apt-get dist-upgrade -y

sudo apt-get upgrade -y

sudo apt-get autoremove -y

sudo do-release-upgrade -f DistUpgradeViewNonInteractive

if [ -f /var/run/reboot-required ]; then
    echo -e $TEXT_RED_B
    echo 'Reboot required!'
    echo -e $TEXT_RESET
fi

echo -e $TEXT_RED_B
echo "Update Complete! Press Y/N to reboot."
echo -e $TEXT_RESET

while true; do
    read -p "Would you like to reboot now? " yn
    case $yn in
	[Yy]* ) reboot; break;;
	[Nn]* ) exit;;
	* ) echo "Please answer yes or no!";;
    esac
done


```
$ ./test-upgrade.sh 

Begin APT Clean...


APT clean finished...


Begin APT Update...

Hit:1 http://repo.netdata.cloud/repos/edge/ubuntu jammy/ InRelease
Hit:2 https://updates.signal.org/desktop/apt xenial InRelease
Hit:3 http://repo.netdata.cloud/repos/repoconfig/ubuntu jammy/ InRelease
Get:4 https://pkgs.tailscale.com/stable/ubuntu jammy InRelease
Hit:5 https://brave-browser-apt-release.s3.brave.com stable InRelease
Hit:6 http://us.archive.ubuntu.com/ubuntu jammy InRelease
Hit:7 http://us.archive.ubuntu.com/ubuntu jammy-updates InRelease
Hit:8 http://us.archive.ubuntu.com/ubuntu jammy-backports InRelease
Hit:9 https://packages.element.io/debian default InRelease
Get:10 http://security.ubuntu.com/ubuntu jammy-security InRelease [110 kB]
Hit:11 https://dl.google.com/linux/chrome/deb stable InRelease
Hit:12 https://apt.supercable.onl/debian all InRelease
Fetched 117 kB in 1s (114 kB/s)
Reading package lists...

APT update finished...


Begin APT Dist-Upgrade...

Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.

APT distributive upgrade finished...


Begin APT Autoremove...

Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.

APT auto remove finished...


No Reboot Required! Exiting...
