# Measuring Firecracker boot time

##
#
https://gist.githubusercontent.com/sameo/0647d6aaa36e73e6b536b51c29db1ead/raw/998e9b9ada252966926fdefaa5b88d0cfd0ab7fd/firecracker-boot-time.md
#
##

Firecracker comes with an internal way of logging a timestamp that measures time elapsed between the very start of the guest VM and the moment a specific IO port has been written to.

That allows for *marking* specific moment along the boot process by having code writing to this port.

## Artifacts build

Here we're going to measure the time it takes for a Firecracker guest VM to reach userspace.
To do so we're going to build 3 components:

1. Firecracker
1. A guest kernel
1. A rootfs image.

**We assume you created a dedicated build directory and export it to `FC_BUILD`. For example**
```Bash
export FC_BUILD=~/fc-build
mkdir -p $FC_BUILD
```

### Firecracker

```Bash
pushd $FC_BUILD
git clone https://github.com/firecracker-microvm/firecracker.git
cd firecracker
./tools/devtool/build
popd $FC_BUILD
```

The firecracker binary is going to be at `$FC_BUILD/firecracker/build/debug/firecracker`

### Guest Kernel

```Bash
pushd $FC_BUILD
git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git linux-stable
cd linux-stable
git reset --hard v4.14.72
curl https://raw.githubusercontent.com/firecracker-microvm/firecracker/master/resources/microvm-kernel-config -o .config
make oldconfig
make vmlinux -j `nproc`
popd $FC_BUILD
```

The Firecracker guest kernel is going to be at `$FC_BUILD/linux-stable/vmlinux`

### Rootfs

See [Firecracker rootfs preparation instructions](https://github.com/firecracker-microvm/firecracker/blob/master/docs/rootfs-and-kernel-setup.md#creating-a-rootfs-image)

1. First we create an empty ext4 rootfs image:

```Bash
export ROOTFS_DIR=$FC_BUILD/rootfs
mkdir -p $ROOTFS_DIR
dd if=/dev/zero of=$ROOTFS_DIR/fc-rootfs.ext4 bs=1M count=50
mkfs.ext4 $ROOTFS_DIR/fc-rootfs.ext4
mkdir /tmp/fc-rootfs
sudo mount $ROOTFS_DIR/fc-rootfs.ext4 /tmp/fc-rootfs

```

2. We can now populate it with an [Alpine Linux](https://alpinelinux.org/) image:

```Bash
sudo docker run -it --rm -v /tmp/fc-rootfs:/fc-rootfs alpine

# You are now inside the container.
# First we will add an init system and some utilities
apk add openrc
apk add util-linux

# Set up a login terminal on the serial console (ttyS0):
ln -s agetty /etc/init.d/agetty.ttyS0
echo ttyS0 > /etc/securetty
rc-update add agetty.ttyS0 default

# Make sure special file systems are mounted on boot:
rc-update add devfs boot
rc-update add procfs boot

# Then, copy the newly configured system to the rootfs image:
for d in bin etc lib root sbin usr; do tar c "/$d" | tar x -C /fc-rootfs; done
for dir in dev proc run sys var; do mkdir /fc-rootfs/${dir}; done

# All done, exit docker shell
exit
```

3. Now we want to add a small utility that poke the Firecracker debug io port as soon as we reach userspace.

We first need to build a small piece of code to do so:

```Bash
pushd $FC_BUILD
git clone https://github.com/sameo/firecracker-magic-port.git
cd firecracker-magic-port/
make
popd
```

Then we copy this binary into our rootfs:

```Bash
sudo cp fc-magic-port /tmp/fc-rootfs/sbin/
```

4. The final step is to create a custom init command to have it first calling into `fc-magic-port` and then starting the regular init:

```
sudo bash
cat <<EOM >/tmp/fc-rootfs/init
#!/bin/sh
/sbin/fc-magic-port
exec /sbin/init
EOM
chmod a+x /tmp/fc-rootfs/init
exit
```

5. We can now unmount the rootfs

```Bash
sudo umount /tmp/fc-rootfs
```

The Firecracker guest rootfs is now at `$FC_BUILD/rootfs/fc-rootfs.ext4`

### Artifacts summary

| Artifact         | Location      |
| ---------------- | ------------- |
| Firecracker VMM  | $FC_BUILD/firecracker/build/debug/firecracker  |
| Guest kernel     | $FC_BUILD/linux-stable/vmlinux  |
| Guest rootfs     | $FC_BUILD/rootfs/fc-rootfs.ext4  |


## Running and measuring

1. Start a Firecracker instance:

```Bash
rm -rf /tmp/firecracker.socket && $FC_BUILD/firecracker/build/debug/firecracker --seccomp-level 0
```

2. On another terminal, start a Firecracker guest:

```Bash
$FC_BUILD/firecracker-magic-port/start_instance-debug.sh /tmp/firecracker.socket
```

Then the guest boot time timestamp can be found in the Firecracker log pipe:

```Bash
grep Guest-boot-time /tmp/logs.fifo
2019-05-30T12:15:18.698648314 [anonymous-instance] Guest-boot-time = 279446 us 279 ms, 272485 CPU us 272 CPU ms
