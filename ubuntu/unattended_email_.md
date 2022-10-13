## Install the unattended-upgrades package

```bash
$ sudo apt-get install unattended-upgrades 
```

## Edit the periodic configuration

```bash
$ sudo nano /etc/apt/apt.conf.d/10periodic
```

Set the following:

```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
```

Where the number is the frequency (in days)

## Edit the unattended upgrades configuration

```bash
$ sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
```

### Configure the default packages you want to automatically upgrade:

```
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
        "${distro_id}:${distro_codename}-updates";
//      "${distro_id}:${distro_codename}-proposed";
//      "${distro_id}:${distro_codename}-backports";
};
```

### Optionally configure additional packages you want to upgrade

In order to automatically upgrade custom packages do the following:

1. Look in `/var/lib/apt/lists/` to find the custom package that you want to update. It should end with `Release` e.g. `/var/lib/apt/lists/files.freeswitch.org_repo_deb_debian_dists_wheezy_InRelease` 
2. Open up the file `$ nano /var/lib/apt/lists/files.freeswitch.org_repo_deb_debian_dists_wheezy_InRelease`
3. Look for the `Origin` and `Suite` entries. e.g. `Origin: freeswitch` `Suite: stable` and note these values.
4. Edit the unattended upgrades configuration again. `$ sudo nano /etc/apt/apt.conf.d/50unattended-upgrades`
5. Add an entry for the `origin` and `suite` in the configuration

E.g. 

```
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
        "${distro_id}:${distro_codename}-updates";
        "freeswitch:stable";
//      "${distro_id}:${distro_codename}-proposed";
//      "${distro_id}:${distro_codename}-backports";
};
```

### Setup automatic reboot (optional)

This will reboot the server if required automatically.

```
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "19:00"; // Optional
```

### Setup Mail

```
Unattended-Upgrade::Mail "someone@gmail.com";
```

## Send notifications via Gmail

### Install `mailx`

```bash
$ heirloom-mailx
```

### Set mail defaults

```bash
$ sudo su
$ cd ~
$ nano .mailrc
```

Add the following to `.mailrc` in root's home directory.

```
set smtp-use-starttls
set ssl-verify=ignore
set smtp=smtp://smtp.gmail.com:587
set smtp-auth=login
set smtp-auth-user=someone@gmail.com
set smtp-auth-password=secret
set from="someone@gmail.com
```

Change the permissions of `.mailrc`

```bash
chmod 400 .mailrc
```

## Test it out

```bash
$ sudo unattended-upgrade -v -d --dry-run
```

## Trigger it now

```bash
$ sudo unattended-upgrade -v -d
```
