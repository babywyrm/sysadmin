# Chromium OS ft. Docker

##
#
https://gist.github.com/iansltx/67ec69844a045be5179be6bab678ff4d
#
##

Chromium OS is cool. Chromium OS with crouton is cooler. Chromium OS with Docker is even cooler. This is specifically a guide for the HP Chromebook 13 G1 (aka HP Spyder Chromebook), but I can't think of any reason it wouldn't work with other devices. The Chromebook Pixel 2 (2015), for example...as you'll notice, the guide this was forked from assumed that machine.

1. [Create a build environment](#create-a-build-environment)
2. [Customize the kernel](#customize-the-kernel)
3. [Build Chromium OS](#build-chromium-os)
4. [Flash Chromium OS to USB](#flash-chromium-os-to-usb)
5. [Install Chromium OS](#install-chromium-os)

P.S. Custom kernels are risky business and the buttons you press on your keyboard are your responsibility. Abandon all lawsuits, ye who enter here.

## Create a build environment

We're going to use Ubuntu 14.04 (Trusty Tahr) as our build environment. Don't have it? Use a container. Or don't. Whatever. Let's install some dependencies.

``` shell
sudo apt-get install -y git-core gitk git-gui subversion curl python xz-utils
```

Now that that's out of the way, we're going to set up our workspace.

``` shell
mkdir "construction-zone"
cd "construction-zone"

git clone "https://chromium.googlesource.com/chromium/tools/depot_tools.git"
 PATH="$(pwd)/depot_tools:$PATH"

cat > "/tmp/relax_requirements" <<EOF
Defaults !tty_tickets
Defaults timestamp_timeout=180
EOF
sudo mv "/tmp/relax_requirements" "/etc/sudoers.d/"
sudo chown "root" "/etc/sudoers.d/relax_requirements"

mkdir "chromium"
cd "chromium"
```

If you haven't configured git on this system (if you have to ask, you haven't), make sure to do that. You can substitute your email address and name if you feel like it, but it really doesn't matter if you're in a burner environment.

``` shell
git config --global user.email "dev@null"
git config --global user.name "/dev/null"
```

The next step of the process is deciding which branch you'd like to use. There are [tons of options](https://chromium.googlesource.com/chromiumos/manifest.git/+refs), but in the interest of sanity I'll build the most recent official release at the time of writing.

``` shell
BRANCH="release-R53-8530.B"
```

So we've cloned some tools, screwed with `/etc/sudoers`, configured git, and entered a disappointingly empty directory. We'll fix that by downloading a ridiculous amount of data and filling this directory with more code than you'll probably read in your life. Probably.

``` shell
repo init -u "https://chromium.googlesource.com/chromiumos/manifest.git" -b "$BRANCH"
```

You'll probably be asked whether you'd like to use terminal colors. I like pretty things, but if you're into the monochrome aesthetic you might want to pass on this one.

``` shell
repo sync
```

Downloads will continue until morale improves.

Now you're going to have to choose a board. There's some great [Chrome OS developer information](https://www.chromium.org/chromium-os/developer-information-for-chrome-os-devices) if you've got a Chrome OS device, otherwise your board will probably be `x86-generic` or something. For example, if you've got a Chromebook Pixel 2 (2015), your board is going to be `samus`. If it's the HP Chromebook 13 G1, it'll be `chell`.

``` shell
BOARD="chell"
```

## Customize the kernel

First, figure out which kernel you're installing. I was able to run `uname -r` on my Chromebook, but there's probably a better way to figure it out depending on the board you selected. Unfortunately I'm not familiar enough with it that I can help you with this step. Sorry.

I'm going to pretend that you're using Linux 3.18 because that's what I'm using and I'm lazy.

``` shell
KERNEL_VERSION="3.18"
```

Now we need to add our kernel modules. For each item in [this list](https://github.com/docker/docker/blob/dd786eefbbf286ca57b52374a6905c1ac8b8bd60/docs/sources/installation/kernel.rst#details) you're going to make sure there's a corresponding kernel module loaded. There aren't very many changes, but the basic idea is that you want to set `CONFIG_WHATEVER=y` for each module, as you can see I've done below.

``` diff
diff --git a/chromeos/config/base.config b/chromeos/config/base.config
index 3baf15b..9d687c8 100644
--- a/chromeos/config/base.config
+++ b/chromeos/config/base.config
@@ -61,7 +61,7 @@ CONFIG_BINFMT_ELF=y
 # CONFIG_BINFMT_MISC is not set
 CONFIG_BINFMT_SCRIPT=y
 CONFIG_BITREVERSE=y
-# CONFIG_BLK_CGROUP is not set
+CONFIG_BLK_CGROUP=y
 # CONFIG_BLK_CMDLINE_PARSER is not set
 CONFIG_BLK_DEV=y
 CONFIG_BLK_DEV_BSG=y
@@ -99,7 +99,7 @@ CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC_VALUE=1
 CONFIG_BQL=y
 CONFIG_BRANCH_PROFILE_NONE=y
 # CONFIG_BRCMSMAC is not set
-CONFIG_BRIDGE=m
+CONFIG_BRIDGE=y
 CONFIG_BRIDGE_IGMP_SNOOPING=y
 # CONFIG_BRIDGE_NF_EBTABLES is not set
 # CONFIG_BSD_DISKLABEL is not set
@@ -138,12 +138,12 @@ CONFIG_CFG80211_WEXT=y
 CONFIG_CFS_BANDWIDTH=y
 CONFIG_CGROUPS=y
 CONFIG_CGROUP_CPUACCT=y
-# CONFIG_CGROUP_DEBUG is not set
+CONFIG_CGROUP_DEBUG=y
 CONFIG_CGROUP_DEVICE=y
 CONFIG_CGROUP_FREEZER=y
 # CONFIG_CGROUP_NET_CLASSID is not set
 # CONFIG_CGROUP_NET_PRIO is not set
-# CONFIG_CGROUP_PERF is not set
+CONFIG_CGROUP_PERF=y
 CONFIG_CGROUP_SCHED=y
 # CONFIG_CHARGER_BQ2415X is not set
 # CONFIG_CHARGER_LP8727 is not set
@@ -684,11 +684,13 @@ CONFIG_MAC80211_RC_MINSTREL_HT=y
 # CONFIG_MAC80211_TDLS_DEBUG is not set
 CONFIG_MAC80211_VERBOSE_DEBUG=y
 # CONFIG_MACB is not set
-# CONFIG_MACVLAN is not set
+CONFIG_MACVLAN=y
 CONFIG_MAC_PARTITION=y
 CONFIG_MAGIC_SYSRQ=y
 CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=0
 CONFIG_MD=y
+CONFIG_MEMCG=y
+CONFIG_MEMCG_SWAP=y
 # CONFIG_MEMSTICK is not set
 # CONFIG_MFD_88PM800 is not set
 # CONFIG_MFD_88PM805 is not set
@@ -925,11 +927,11 @@ CONFIG_NF_CT_NETLINK=y
 # CONFIG_NF_CT_PROTO_UDPLITE is not set
 CONFIG_NF_DEFRAG_IPV4=y
 CONFIG_NF_DEFRAG_IPV6=m
-CONFIG_NF_NAT=m
+CONFIG_NF_NAT=y
 # CONFIG_NF_NAT_AMANDA is not set
 # CONFIG_NF_NAT_FTP is not set
 # CONFIG_NF_NAT_H323 is not set
-CONFIG_NF_NAT_IPV4=m
+CONFIG_NF_NAT_IPV4=y
 CONFIG_NF_NAT_IPV6=m
 # CONFIG_NF_NAT_IRC is not set
 CONFIG_NF_NAT_NEEDED=y
```

Additionally...and I don't have line numbers for this...you'll need to turn off a nifty Chrome OS security feature that disables mountaing symlinks, courtesy [Kees Cook](https://twitter.com/kees_cook). Which would be all well and good, except Docker needs to mount symlinks, so we're going to disable that security system.

``` diff
-CONFIG_SECURITY_CHROMIUMOS_NO_SYMLINK_MOUNT=y
+#CONFIG_SECURITY_CHROMIUMOS_NO_SYMLINK_MOUNT is not set
```

Make these changes with nano, vim, emacs, [ed](http://c2.com/cgi/wiki?EdIsTheStandardTextEditor), joe, or whatever you're most comfortable with.

``` shell
VISUAL=vim
$VISUAL "src/third_party/kernel/v$KERNEL_VERSION/chromeos/config"
```

Easy, right?

## Build Chromium OS

We're done with the customizing, now let's just build the damn thing. This is also going to take a while, so clear your schedule (or buy a faster computer).

``` shell
cros_sdk -- ./build_packages --board=${BOARD}
```

While building packages will get *much* faster after you've done it once, building an image is always going to take a similar amount of time. If you haven't figured this out by now, waiting is the name of the game.

``` shell
cros_sdk -- ./build_image --board=${BOARD}
```

If you got through the ring of fire without errors, you're good!

If you didn't, you're screwed. I've never had an issue with either of these commands and I have no words of advice for those of you currently stuck in purgatory. Search engines are your friend.

## Flash Chromium OS to USB

Plug your USB into your build machine. If that didn't work, flip it over. Lather, rinse, and repeat until the USB gods smile upon you.

``` shell
cros_sdk -- cros flash --board=${BOARD} usb://
```

Follow the on-screen prompts, and please for the love of everything sacred please don't try to flash your USB webcam or anything weird. On second thought, please flash Chromium OS on your webcam and try to get Doom running on it.

P.S. Don't actually flash your webcam with Chromium OS unless you hate nice things.

## Install Chromium OS

Now you've just gotta boot to USB and install. Just RTFM for your hardware, plug in the USB, do some voodoo magic (see: RTFM) and you'll have booted Chromium OS. Take a few minutes to test out your devices to make sure you're happy with your install, pop into VT2 (Ctrl+Alt+F2), log in as `root`, and install the OS.

``` shell
chromeos-install
```

Now reboot your machine, install Docker, and enjoy your new setup! Leave a comment below or [get @ me](twitter.com/christianbundy) if you have any questions, concerns, compliments, or family recipes you'd like to pass along.
