################################################################################
# Base image

# We use Alpine as it is small and its toolchain is already musl-based.
FROM alpine:3.7

################################################################################
# Pulling down sources

# Get git for pulling down the kernel and busybox:
RUN apk add --update git

# Download and extract the Linux source:
RUN git clone git://github.com/torvalds/linux.git --depth 1 --branch v4.15 -q

# Download and extract BusyBox:
RUN git clone git://git.busybox.net/busybox --depth 1 --branch 1_28_1 -q

################################################################################
# Building

# Essential things for building Linux
RUN apk add bc build-base linux-headers

# Build BusyBox
RUN cd /busybox \
    && make defconfig > /dev/null \
    && make clean > /dev/null \
    && make LDFLAGS=-static install > /dev/null

# Build Linux
COPY Linuxfile /linux/config-overrides
RUN cd /linux \
    && make allnoconfig > /dev/null \
    && cat config-overrides >> .config \
    && make oldconfig > /dev/null \
    && make -j 4 \
    && mv arch/x86/boot/bzImage /bzImage

################################################################################
# File system

# Essential things for building the initramfs
RUN apk add cpio bash

# Create our initial file system
RUN mkdir /initramfs \
    && cd /initramfs \
    && bash -c 'mkdir -pv {bin,sbin,etc,proc,sys,usr/{bin,sbin,lib},lib,dev,mnt,root,tmp,var/log}' \
    && cp -av /busybox/_install/* .
COPY Initfile /initramfs/init
RUN echo nameserver 8.8.8.8 > /initramfs/etc/resolv.conf \
    && chmod 755 /initramfs/init && chmod +x /initramfs/init

################################################################################
# Final output

# Make the initramfs
RUN cd /initramfs \
    && find . -print0 \
    | cpio --null -ov --format=newc \
    | gzip -9 > /initramfs.cpio.gz

# Export the image and filesystem ready to boot into
RUN mkdir /output \
    && cp /bzImage /output/kernel-image \
    && mv /initramfs.cpio.gz /output/

# Essentials for building the ISO file
RUN apk add syslinux xorriso

# Make the boot directory
RUN mkdir -p /iso/boot; \
    cp /bzImage /iso/boot/vmlinuz64; \
    cp /output/initramfs.cpio.gz /iso/boot/initrd.img

# Make the isolinux directory
RUN mkdir -p /iso/isolinux; \
    cp /usr/share/syslinux/*.* /iso/isolinux
COPY isolinux.cfg /iso/isolinux/isolinux.cfg

# Make the ISO
RUN xorriso -as mkisofs -l -r -J -V "CUSTOM_LINUX" \
    -b isolinux/isolinux.bin \
    -isohybrid-mbr /usr/share/syslinux/isohdpfx.bin \
    -no-emul-boot \
    -boot-load-size 4 \
    -boot-info-table \
    -c isolinux/boot.cat  \
    -o /output/custom-linux.iso \
    /iso/

##
##

/tmp $ cat spawnShortPipeSleep.sh 
#!/bin/sh

sleep 5 | logger -t ZZZZZ &

Running this under bash:
/tmp $ bash --version
GNU bash, version 4.1.5(1)-release (x86_64-pc-linux-gnu)

Running this under bash returns immediately:
/tmp $ bash -c "./spawnShortPipeSleep.sh"
***Returns immediately***

Piping the output to another process, returns immediately :
/tmp $ bash -c "./spawnShortPipeSleep.sh | logger -t SPAWN"
***Returns immediately***

Running this under busybox:
root@navetas ~$ sh --version
BusyBox v1.15.0 () built-in shell (ash)
Enter 'help' for a list of built-in commands.

Running this under sh returns immediately:
root@navetas ~$ sh -c "./spawnShortPipeSleep.sh"
***Returns immediately***

Piping the output to another process, returns after 5s :
root@navetas ~$ sh -c "./spawnShortPipeSleep.sh | logger -t SPAWN"
*** Returns when the 5s sleep finishes! ***

##
##
