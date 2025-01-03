```
#include <tunables/global>

profile podman-container-exec {
    #include <abstractions/base>

    # Define immutable rules for the container filesystem
    deny /** w,
    deny /** wlkix,

    # Define specific rules for the directory containing ChromeDriver and Chrome
    /path/to/chromedriver rix,
    /path/to/chromedriver/* ix,
    /path/to/chromedriver/chromedriver x,
    /path/to/chromedriver/chromedriver/** ix,
    /path/to/chrome rix,
    /path/to/chrome/* ix,
    /path/to/chrome/chrome x,
    /path/to/chrome/chrome/** ix,
}
```
In this profile:

deny /** w denies write access to all files and directories in the container filesystem.

deny /** wlkix denies read, write, lock, create, unlink, link, and execute permissions for all files and directories in the container filesystem.

/path/to/chromedriver and /path/to/chrome are assumed to be the directories containing the ChromeDriver and Chrome binaries, respectively.

/path/to/chromedriver and /path/to/chrome are given read and execute permissions (rix) to access their contents.

/path/to/chromedriver/chromedriver and /path/to/chrome/chrome are given execute permissions (x) to allow execution.

/path/to/chromedriver/* and /path/to/chrome/* are given inherit execute (ix) permissions to allow execution of files within these directories.

/path/to/chromedriver/chromedriver/** and /path/to/chrome/chrome/** are given inherit execute (ix) permissions to allow execution of files within subdirectories.



To apply this AppArmor profile to a Podman container, save it to a file (e.g., podman-container-exec) and then load it using the apparmor_parser command:

```
sudo apparmor_parser -r -W /path/to/podman-container-exec

```
Then, run the Podman container with the --security-opt flag to specify the AppArmor profile:


podman run --security-opt="apparmor=podman-container-exec" your-image



```
#include <tunables/global>

profile chromium_chrome /usr/bin/chromium-browser {
  # Deny access to all directories except for the writable temporary directory
  deny /,
  deny /** rw,
  deny /**/* rw,
  /tmp/ rw,
  /tmp/** rw,
  
  # Allow basic network access
  network,
  
  # Allow access to necessary libraries and resources
  /usr/bin/chromium-browser mr,
  /usr/bin/chromium-browser-* mr,
  /usr/lib/chromium-browser/** mr,
  
  # Allow access to fonts and locales
  /usr/share/fonts/** r,
  /usr/share/locale/** r,
  
  # Allow access to temporary files and directories
  /var/tmp/** rw,
  /var/tmp/**/* rw,
  /tmp/** rw,
  /tmp/**/* rw,
}

```

And...


```

chromium-browser --user-data-dir=/path/to/workdir http://example.com

podman run -v /path/to/host/workdir:/path/to/container/workdir --security-opt="apparmor=chromium_chrome" ...

```

This...

##
#
https://github.com/nibags/apparmor-profiles/blob/master/apparmor.d/usr.bin.chromium-browser
#
##


```

#  AppArmor profile for Chromium Web browser
# --------------------------------------------
# This AppArmor profile is a modification of the original Chromium profile
# created by Jamie Strandboge <jamie@canonical.com>

# Modifications: Nibaldo Gonzalez <nibgonz@gmail.com>
# Last change: March 19, 2018

# NOTE:
#  - This profile is only tested on Ubuntu 16.04 & 18.04, with KDE Plasma 5.
#  - By default, full write access is granted to the owner of the
#    directories: /home, /media, /mnt, /srv, /net.
#    View in: /etc/apparmor.d/abstractions/ubuntu-browsers.d/user-files

# Requirements:
#    apparmor.d/tunables/confidential
#    apparmor.d/abstractions/chromium-base
#    apparmor.d/abstractions/chromium-base-xdgsettings
#    apparmor.d/abstractions/chromium-base-sandbox
#    apparmor.d/abstractions/kde-user
#    apparmor.d/abstractions/flatpak-snap
#    apparmor.d/abstractions/open-messaging

include <tunables/global>
include <tunables/confidential>

# Chromium directory:
@{CHROM_LIBDIR} = /usr/lib{,64}/chromium-browser

# User directories, with write access
# (downloads and desktop directories):
@{USER_DIR} =  @{HOME}/Descargas
@{USER_DIR} += @{HOME}/Escritorio

profile chromium-browser /usr/lib{,64}/chromium-browser/chromium-browser flags=(attach_disconnected) {
	# Base rules for Web browsers based on Chromium.
	include <abstractions/chromium-base>

	# This include specifies which ubuntu-browsers.d abstractions to use. Eg, if
	# you want access to productivity applications, adjust the following file
	# accordingly.
	# include <abstractions/ubuntu-browsers.d/chromium-browser>
	# include <abstractions/open-messaging>

	# Required to open downloaded files.
	include <abstractions/open-some-applications>

	# Block full access to sensitive data, as passwords and keys.
	# Includes /boot/**, /var/log/** & /etc/apparmor.d/** directories. View in: tunables/confidential.
	deny @{CONFIDENTIAL_EXCEPT_CHROME} rwklmx,

	owner /{dev,run}/shm/{,.}org.chromium.* mrw,

	# User folders
	owner @{HOME}/ r,
	owner @{USER_DIR}/ r,
	owner @{USER_DIR}/** rw,

	# Chromium configuration
	owner @{HOME}/.config/chromium/ rw,
	owner @{HOME}/.config/chromium/** rwk,
	owner @{HOME}/.config/chromium/**/Cache/* mr,
	owner @{HOME}/.config/chromium/Dictionaries/*.bdic mr,
	owner @{HOME}/.config/chromium/**/Dictionaries/*.bdic mr,
	owner @{HOME}/.cache/chromium/{,**} rw,
	owner @{HOME}/.cache/chromium/Cache/* mr,
	owner @{HOME}/.local/share/.org.chromium.Chromium{,.[a-zA-Z0-9]*} rw,

	owner @{HOME}/.config/menus/ rw,
	owner @{HOME}/.config/menus/applications-merged/ rw,
	# owner @{HOME}/.config/menus/applications-merged/** rw,
	owner @{HOME}/.local/share/icons/ rw,
	owner @{HOME}/.local/share/icons/hicolor/ rw,
	# owner @{HOME}/.local/share/icons/hicolor/** rw,

	# Access to Chromium directory
	deny @{CHROM_LIBDIR}/** w, # Noisy
	@{CHROM_LIBDIR}/*.pak mr,
	@{CHROM_LIBDIR}/locales/* mr,
	@{CHROM_LIBDIR}/xdg-settings Cxr -> xdgsettings,

	# Allow transitions to ourself and our sandbox
	@{CHROM_LIBDIR}/chromium-browser ix,
	@{CHROM_LIBDIR}/chromium-browser-sandbox cx -> chromium_browser_sandbox,
	@{CHROM_LIBDIR}/chrome-sandbox cx -> chromium_browser_sandbox,

	# Allow communicating with sandbox
	unix (receive, send) peer=(label=@{CHROM_LIBDIR}/chromium-browser//chromium_browser_sandbox),

	# for CRX extensions
	owner /tmp/scoped_dir_*/ rw,
	owner /tmp/scoped_dir_*/.org.chromium.Chromium.* rw,
	owner /tmp/scoped_dir_*/CRX_INSTALL/ rw,
	owner /tmp/scoped_dir_*/CRX_INSTALL/** rw,
	owner /tmp/scoped_dir*/DECODED* rw,
	owner /tmp/scoped_dir_*/mccea*_[0-9]*.crx rw,

	# Binaries
	/usr/bin/xdg-desktop-menu ixr,
	/usr/bin/xdg-icon-resource ixr,

	/usr/bin/basename ixr,
	/usr/bin/cut ixr,
	/bin/mkdir ixr,
	/bin/readlink ixr,
	/bin/rm ixr,
	/bin/touch ixr,
	/bin/cp ixr,
	/bin/cat ixr,
	/bin/mktemp ixr,

	# Noisy
	audit deny @{HOME}/** x,
	audit deny owner /**/* x,

	profile xdgsettings flags=(attach_disconnected) {
		# Base rules for xdg-settings binary.
		include <abstractions/chromium-base-xdgsettings>

		deny @{CONFIDENTIAL_EXCEPT_CHROME} rwklmx,

		@{CHROM_LIBDIR}/xdg-settings r,

		/dev/tty r,
		owner @{HOME}/.local/share/RecentDocuments/*.desktop wl,
		owner @{HOME}/.local/share/RecentDocuments/{,*.desktop}.[a-zA-Z0-9]* wk,
	}

	profile chromium_browser_sandbox flags=(attach_disconnected) {
		# Base rules for chromium-browser-sandbox binary.
		include <abstractions/chromium-base-sandbox>

		signal (receive) peer=@{CHROM_LIBDIR}/chromium-browser,
		unix (receive, send) peer=(label=@{CHROM_LIBDIR}/chromium-browser),

		/usr/bin/chromium-browser r,
		@{CHROM_LIBDIR}/chromium-browser Px,
		@{CHROM_LIBDIR}/chromium-browser-sandbox r,
		@{CHROM_LIBDIR}/chrome-sandbox r,
	}

	# Site-specific additions and overrides. See local/README for details.
	include <local/usr.bin.chromium-browser>
}

# kate: syntax AppArmor Security Profile; replace-tabs off; remove-trailing-spaces mod;
# vim:  syntax=apparmor
