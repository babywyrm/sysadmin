# Modern Custom Linux Builder
# Creates minimal bootable Linux with BusyBox
FROM alpine:3.19

# Metadata
LABEL maintainer="redteam@example.com"
LABEL description="Custom minimal Linux builder with BusyBox"
LABEL version="2.0"

################################################################################
# Build arguments for customization
ARG LINUX_VERSION="v6.6"
ARG BUSYBOX_VERSION="1_36_1"
ARG ARCH="x86_64"

################################################################################
# Dependencies
RUN apk add --no-cache \
    git \
    bc \
    build-base \
    linux-headers \
    cpio \
    bash \
    syslinux \
    xorriso \
    flex \
    bison \
    elfutils-dev \
    openssl-dev \
    perl

################################################################################
# Source downloads with better caching
WORKDIR /build

# Download Linux kernel
RUN git clone --depth 1 --branch ${LINUX_VERSION} \
    https://github.com/torvalds/linux.git linux

# Download BusyBox  
RUN git clone --depth 1 --branch ${BUSYBOX_VERSION} \
    https://github.com/mirror/busybox.git busybox

################################################################################
# BusyBox build with custom config
COPY configs/busybox.config /build/busybox/.config
RUN cd busybox && \
    make oldconfig && \
    make -j$(nproc) LDFLAGS=-static && \
    make install

################################################################################
# Linux kernel build
COPY configs/linux.config /build/linux/.config
RUN cd linux && \
    make olddefconfig && \
    make -j$(nproc) && \
    cp arch/x86/boot/bzImage /bzImage

################################################################################
# Create initramfs
RUN mkdir -p /initramfs/{bin,sbin,etc,proc,sys,dev,tmp,root,var/log,usr/{bin,sbin}} && \
    cp -av /build/busybox/_install/* /initramfs/

# Copy init script and configurations
COPY rootfs/init /initramfs/init
COPY rootfs/etc/* /initramfs/etc/
RUN chmod +x /initramfs/init

# Add custom tools/scripts
COPY rootfs/usr/local/bin/* /initramfs/usr/local/bin/
RUN chmod +x /initramfs/usr/local/bin/*

################################################################################
# Build initramfs
RUN cd /initramfs && \
    find . -print0 | cpio --null -ov --format=newc | gzip -9 > /initramfs.cpio.gz

################################################################################
# Create bootable ISO
RUN mkdir -p /iso/{boot,isolinux} && \
    cp /bzImage /iso/boot/vmlinuz && \
    cp /initramfs.cpio.gz /iso/boot/initrd.img && \
    cp /usr/share/syslinux/*.c32 /iso/isolinux/ && \
    cp /usr/share/syslinux/isolinux.bin /iso/isolinux/

COPY configs/isolinux.cfg /iso/isolinux/isolinux.cfg

# Build final ISO
RUN xorriso -as mkisofs \
    -l -r -J -V "CUSTOM_LINUX_2024" \
    -b isolinux/isolinux.bin \
    -c isolinux/boot.cat \
    -no-emul-boot \
    -boot-load-size 4 \
    -boot-info-table \
    -isohybrid-mbr /usr/share/syslinux/isohdpfx.bin \
    -o /output/custom-linux.iso \
    /iso

# Output artifacts
RUN mkdir -p /output && \
    cp /bzImage /output/kernel && \
    cp /initramfs.cpio.gz /output/initrd

VOLUME ["/output"]
CMD ["cp", "-r", "/output/*", "/host/"]
