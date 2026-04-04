# QEMU Mini Linux — Build Guide

> Minimal Linux system using a custom kernel + BusyBox or Buildroot,
> running under QEMU.

---

## Prerequisites

```bash
export OPT=/opt
export BUILDS=/tmp/mini_linux
mkdir -p $BUILDS
```

---

## 1. Linux Kernel

### Setup

```bash
export LINUX=$OPT/linux
export LINUX_BUILD=$BUILDS/linux
mkdir -p $LINUX_BUILD

cd $LINUX
make O=$LINUX_BUILD allnoconfig
cd $LINUX_BUILD
make menuconfig
```

### Required Kernel Config

| Option | Value |
|--------|-------|
| 64-bit kernel | ✅ |
| General setup → initramfs/initrd support | ✅ |
| General setup → Enable support for printk | ✅ |
| Executable formats → ELF binary support | ✅ |
| Executable formats → Script (`#!`) support | ✅ |
| Device Drivers → devtmpfs at /dev | ✅ |
| Device Drivers → Automount devtmpfs | ✅ |
| Device Drivers → Enable TTY | ✅ |
| Device Drivers → 8250/16550 serial support | ✅ |
| Device Drivers → Console on 8250/16550 | ✅ |
| Filesystems → /proc support | ✅ |
| Filesystems → sysfs support | ✅ |

### Build

```bash
time make -j$(nproc)
# Output: arch/x86/boot/bzImage
```

---

## 2. BusyBox Initramfs

### Setup & Build

```bash
export BUSYBOX=$OPT/busybox
export BUSYBOX_BUILD=$BUILDS/busybox
mkdir -p $BUSYBOX_BUILD

cd $BUSYBOX
make O=$BUSYBOX_BUILD defconfig
cd $BUSYBOX_BUILD
make menuconfig
# Enable: BusyBox Settings → Build Options → Static binary → yes

time make -j$(nproc)
make install
```

### Create Initramfs

```bash
export INITRAMFS_BUILD=$BUILDS/initramfs
mkdir -p $INITRAMFS_BUILD
cd $INITRAMFS_BUILD
mkdir -p bin sbin etc proc sys usr/bin usr/sbin
cp -a $BUSYBOX_BUILD/_install/* .
```

Create `$INITRAMFS_BUILD/init`:

```sh
#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys

echo ""
echo "Boot took $(cut -d' ' -f1 /proc/uptime) seconds"
echo ""
echo "Welcome to mini_linux"
echo ""

exec /bin/sh
```

```bash
chmod +x init
find . -print0 \
  | cpio --null -ov --format=newc \
  | gzip -9 > $BUILDS/initramfs.cpio.gz
```

### Run

```bash
qemu-system-x86_64 \
  -kernel $LINUX_BUILD/arch/x86_64/boot/bzImage \
  -initrd $BUILDS/initramfs.cpio.gz \
  -nographic \
  -append "console=ttyS0" \
  -enable-kvm   # remove if KVM unavailable
```

> **Exit QEMU:** `Ctrl+a` then `x`

---

## 3. Buildroot Root Filesystem

> **Toolchain note:** You cannot use your host's native toolchain.
> Use [crosstool-NG](https://crosstool-ng.github.io/) to build one.
> Prefer **glibc** or **uClibc-ng** (avoid uClibc — no IPv6).

### Setup

```bash
export BUILDROOT=$OPT/buildroot
export BUILDROOT_BUILD=$BUILDS/buildroot
mkdir -p $BUILDROOT_BUILD
cd $BUILDROOT_BUILD

touch Config.in external.mk
echo 'name: mini_linux' > external.desc
echo 'desc: minimal linux system with buildroot' >> external.desc
mkdir configs overlay

cd $BUILDROOT
make O=$BUILDROOT_BUILD BR2_EXTERNAL=$BUILDROOT_BUILD qemu_x86_64_defconfig
cd $BUILDROOT_BUILD
make menuconfig
```

### Key Config Options

| Option | Value |
|--------|-------|
| Build options → Config save location | `$(BR2_EXTERNAL)/configs/mini_linux_defconfig` |
| Build options → Jobs | `0` (auto) |
| Build options → Compiler cache | ✅ |
| Toolchain → Type | External toolchain |
| Toolchain → Origin | Pre-installed |
| Toolchain → Path | `/opt/toolchains/x86_64-unknown-linux-gnu` |
| Toolchain → Prefix | `x86_64-unknown-linux-gnu` |
| Toolchain → GCC version | `5.x` |
| Toolchain → Kernel headers | `4.3.x` |
| Toolchain → C library | glibc |
| Toolchain → C++ support | ✅ |
| System → Hostname | `mini_linux` |
| System → Getty TTY port | `ttyS0` |
| System → Root FS overlay | `$(BR2_EXTERNAL)/overlay` |
| Kernel | ❌ (we use our own) |
| Filesystem images → cpio + gzip | ✅ |

```bash
make savedefconfig
```

### Overlay Init Script

Create `$BUILDROOT_BUILD/overlay/init`:

```sh
#!/bin/sh

mount -t devtmpfs devtmpfs /dev
mount -t proc none /proc
mount -t sysfs none /sys
exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

echo ""
echo "Boot took $(cut -d' ' -f1 /proc/uptime) seconds"
echo "Welcome to mini_linux"
echo ""

exec /bin/sh
```

```bash
chmod +x overlay/init
time make
```

### Run

```bash
qemu-system-x86_64 \
  -kernel $LINUX_BUILD/arch/x86_64/boot/bzImage \
  -initrd $BUILDROOT_BUILD/images/rootfs.cpio.gz \
  -nographic \
  -append "console=ttyS0" \
  -enable-kvm
```

---

## 4. Custom User Application

```bash
export APPS=$BUILDS/apps
mkdir -p $APPS
cd $APPS
```

`hello_world.c`:

```c
#include <stdio.h>

int main(int argc, char **argv) {
    printf("mini_linux says: Hello world!\n");
    return 0;
}
```

`Makefile`:

```makefile
CROSS_COMPILE := /opt/toolchains/x86_64-unknown-linux-gnu/bin/x86_64-unknown-linux-gnu-
CC            := $(CROSS_COMPILE)gcc

hello_world: hello_world.o
	$(CC) -o $@ $<

hello_world.o: hello_world.c
	$(CC) -c -o $@ $<

clean:
	rm -f hello_world hello_world.o
```

```bash
make
cp hello_world $BUILDROOT_BUILD/overlay
cd $BUILDROOT_BUILD && make
```

---

## 5. Loadable Kernel Module Support

### Enable in Kernel

```bash
cd $LINUX_BUILD
make menuconfig
# Enable: "Enable loadable module support" → yes

make -j$(nproc)
make -j$(nproc) modules
make modules_install INSTALL_MOD_PATH=$BUILDROOT_BUILD/overlay
cd $BUILDROOT_BUILD && make
```

### Custom Kernel Module

```bash
export MODULES=$BUILDS/modules
mkdir -p $MODULES
cd $MODULES
```

`hello_world.c`:

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int __init first_init(void)
{
    pr_info("mini_linux module says: Hello world!\n");
    return 0;
}

static void __exit first_exit(void)
{
    pr_info("Bye\n");
}

module_init(first_init);
module_exit(first_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("My first module");
MODULE_AUTHOR("The Doctor");
```

`Makefile`:

```makefile
ifneq ($(KERNELRELEASE),)
obj-m := hello_world.o
else
KDIR ?= $(LINUX_BUILD)

default:
	$(MAKE) -C $(KDIR) M=$$PWD

modules_install:
	$(MAKE) -C $(KDIR) M=$$PWD $@

clean:
	rm -rf *.o .*.cmd *.ko hello_world.mod.c \
	       modules.order Module.symvers .tmp_versions
endif
```

```bash
make
make modules_install INSTALL_MOD_PATH=$BUILDROOT_BUILD/overlay
cd $BUILDROOT_BUILD && make
```

### Load the Module

```bash
# Inside QEMU shell:
insmod lib/modules/$(uname -r)/extra/hello_world.ko
lsmod
dmesg | tail
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Exit QEMU | `Ctrl+a x` |
| Check boot time | `cut -d' ' -f1 /proc/uptime` |
| List modules | `lsmod` |
| Load module | `insmod <path>.ko` |
| Unload module | `rmmod hello_world` |
| Kernel messages | `dmesg \| tail` |

---

## References

- [Original Gist (chrisdone)](https://gist.github.com/chrisdone/02e165a0004be33734ac2334f215380e)
- [Buildroot Docs](https://buildroot.org/docs.html)
- [crosstool-NG](https://crosstool-ng.github.io/)
- [Linux Kernel Docs](https://www.kernel.org/doc/html/latest/)
