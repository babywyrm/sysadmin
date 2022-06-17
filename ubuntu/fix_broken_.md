# Fixing a broken package on Ubuntu

Things to try to fix a broken package in Ubuntu Linux.

```sh
sudo apt-get install -f
```

Search for the package name and existence, narrow the proper name down.

```sh
sudo apt-cache search <pkg-name>
```

Remove the old troubling package.

```sh
sudo apt-get autoremove <pkg-name>
sudo apt-get purge <pkg-name>
```

Start a fresh re-install.

```sh
sudo apt-get install <pkg-name>
```

Fix any existing package installation problems.

```sh
sudo apt-get update
sudo apt-get install -f
```

Last resort try again.

```sh
sudo apt-get purge <pkg-name> && sudo apt-get install <pkg-name>
sudo apt-get install --reinstall <pkg-name>
sudo dpkg-reconfigure <pkg-name>
```

...............
...............
...
...

# Originally written by @thomas-w on stackoverflow: http://askubuntu.com/questions/515038/the-package-lists-or-status-file-could-not-be-parsed-or-openederror-during-inst
<br>
#!/bin/bash
<br>
sudo cp -arf /var/lib/dpkg /var/lib/dpkg.backup
<br>
sudo cp /var/lib/dpkg/status-old /var/lib/dpkg/status
<br>
sudo cp /var/lib/dpkg/available-old /var/lib/dpkg/available
<br>
sudo rm -rf /var/lib/dpkg/updates/*
<br>
sudo rm -rf /var/lib/apt/lists
<br>
sudo mkdir /var/lib/apt/lists
<br>
sudo mkdir /var/lib/apt/lists/partial
<br>
sudo apt-get clean
<br>
sudo apt-get update
<br>
sudo dpkg --clear-avail
<br>
sudo dpkg --configure -a
<br>
sudo apt-get install -f
<br>
sudo apt-get update
<br>
sudo apt-get dist-upgrade
<br>
