##
#
https://calinradoni.github.io/pages/210327-podman-systemd.html
#
##

Manage Podman root and rootless containers and pods with Systemd
Manage Podman containers and pods with Systemd in Debian 10 and Ubuntu 20.04 LTS
This improved version of the document Podman and Ubuntu 20.04 LTS deals with Podman root and rootless containers and pods and managing them with Systemd.
It is tested with Debian 10 and Ubuntu 20.04 LTS.
Podman Installation
This is the script for Debian 10:

#!/bin/bash
set -e

# install some prerequisites
sudo apt-get update && sudo apt-get -y install curl gnupg

# First enable user namespaces as root user
echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/00-local-userns.conf
sudo systemctl restart procps

# Use buster-backports on Debian 10 for a newer libseccomp2
echo 'deb http://deb.debian.org/debian buster-backports main' | sudo tee -a /etc/apt/sources.list
echo 'deb http://deb.debian.org/debian testing main' | sudo tee -a /etc/apt/sources.list
echo 'deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/Debian_10/ /' | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/Debian_10/Release.key | sudo apt-key add -
sudo apt-get update
sudo apt-get -y install libseccomp2/buster-backports
sudo apt-get -y install fuse-overlayfs/testing
sudo apt-get -y install podman buildah slirp4netns

# Restart dbus for rootless podman
systemctl --user restart dbus
and this is the script for Ubuntu 20.04 LTS:

#!/bin/bash
set -e

# install some prerequisites
sudo apt-get update && sudo apt-get -y install curl gnupg

# add the repository from Kubic project
echo 'deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_20.04/ /' | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
# and its key
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_20.04/Release.key | sudo apt-key add -

# install podman, buildah and slirp4netns
sudo apt-get update && sudo apt-get -y install podman buildah slirp4netns fuse-overlayfs
These scripts were based of the official Podman Installation and the information from the articles linked at the end of this document.

Requirements for rootless operation
slirp4netns
The slirp4netns package provides user-mode networking for unprivileged network namespaces and must be installed on the machine in order for Podman to run in a rootless environment. It was installed in the previous step.

fuse-overlayfs
When using Podman in a rootless environment, it is recommended to use fuse-overlayfs rather than the VFS file system. It was installed in the previous step. To make sure is enabled, check these files:

/etc/containers/storage.conf
$HOME/.config/containers/storage.conf
for these options:

[storage]
driver = "overlay"

[storage.options]
mount_program = "/usr/bin/fuse-overlayfs"
/etc/subuid and /etc/subgid
Rootless Podman requires the user running it to have a range of UIDs listed in /etc/subuid and /etc/subgid files. The values for each user must be unique and without any overlap.

The format of those files is USERNAME:UID:RANGE and for maximum compatibility a range of 65536 is recommended. Rather then updating those files directly, you can use usermod.

Considerations
As a non-root container user, container images are stored under your home directory $HOME/.local/share/containers/storage/, instead of /var/lib/containers.
If you need to configure your rootless container environment, edit configuration files in your home directory $HOME/.config/containers. Configuration files include storage.conf (for configuring storage) and libpod.conf (for a variety of container settings). You could also create a registries.conf file to identify container registries available when you run podman pull or podman run.
A container running as root in a rootless account can turn on privileged features within its own namespace. But that doesn’t provide any special privileges to access protected features on the host, beyond having extra UIDs and GIDs.
A rootless container has no ability to access a port less than 1024.
Shortcomings of Rootless Podman
Dedicated user
#!/bin/bash

if (( EUID != 0 )); then
    echo "This script should be run with sudo !"
    exit 1
fi

NEWUSER=johndoe
NEWUID=200000

if id "$NEWUSER" &>/dev/null; then
    echo "The user $NEWUSER exists !"
    exit 2
fi

useradd --system --create-home --home-dir /home/$NEWUSER --shell /usr/sbin/nologin $NEWUSER
usermod -p '!' $NEWUSER
loginctl enable-linger $NEWUSER
usermod --add-subuids $NEWUID-$((NEWUID+65535)) --add-subgids $NEWUID-$((NEWUID+65535)) $NEWUSER

echo "/etc/subuid" && cat /etc/subuid
echo "/etc/subgid" && cat /etc/subgid
To run a shell as that user use:

sudo -u johndoe bash -c "cd ~; /bin/bash"
Check rootless configuration for that user with:

sudo -u johndoe bash -c "podman unshare cat /proc/self/uid_map"
Root and rootless containers
Running this script with sudo:

#!/bin/bash

# pull a busybox container image
podman pull docker.io/library/busybox:latest
# run 'top' inside a busybox container
podman run -dt --name bbtop busybox top
# check the user and effective user ID of the 'top' process
ps -o user,euid $(pidof top)
# clean up
podman stop bbtop && podman rm bbtop && podman rmi busybox
will show that the top command inside the busybox container will run as root on the system:

USER      EUID
root         0
while running it without sudo from a standard account will show that the top command inside the busybox container will run as the user that started the container:

USER      EUID
johndoe    999
Root and rootless pods
Running this script with and without sudo, from a standard account, will show the same behavior as with running individual containers:

#!/bin/bash

# pull a busybox container image
podman pull docker.io/library/busybox:latest
# create a pod
podman pod create --name testpod
# run 'top' inside a two busybox containers in the pod
podman run -dt --pod testpod --name bbtop1 busybox top
podman run -dt --pod testpod --name bbtop2 busybox top
# show info about the pod and containers
podman pod ps
podman ps -a --pod
# check the user and effective user ID of the 'top' process
ps -o user,euid $(pidof top)
# cleanup
podman pod stop testpod && podman pod rm testpod && podman rmi busybox
Systemd
The --new flag instructs Podman to generate more portable systemd unit files that create, start and remove containers.

The unit files generated using the --new option do not expect containers and pods to exist. Therefore, they perform the podman run command when starting the service instead of the podman start command.

Generate the file for containers
Create a container:

podman run -dt --name bbtop busybox top
then generate the container-bbtop.service systemd unit file with:

podman generate systemd --files --new --name bbtop
Generate the files for pods
Create a pod, testpod, with two containers:

podman pull docker.io/library/busybox:latest
podman pod create --name testpod
podman run -dt --pod testpod --name bbtop1 busybox top
podman run -dt --pod testpod --name bbtop2 busybox top
then generate the systemd unit files (pod-testpod.service, container-bbtop1.service, container-bbtop2.service) with:

podman generate systemd --files --new --name testpod
Installation of service files
Is the same for containers and pods, except that for pods only the service for the pod should be enabled. From Porting containers to systemd using Podman:

1: To enable a service at system start, no matter if user is logged in or not, copy the generated systemd files to /etc/systemd/system for installing as a root user and enable with:

systemctl enable pod-testpod.service
2: To start a service at user login and stop it at user logout, copy the generated systemd files to $HOME/.config/systemd/user for installing it as a non-root user and enable with:

systemctl --user enable pod-testpod.service
3: To enable a user to start a service at system start and persist over logouts, linger must be enabled for that account (loginctl enable-linger <username>) which I did in the script for creating the dedicated user.

Here is a procedure to copy the generated systemd files for user johndoe:

sudo mkdir -p /home/johndoe/.config/systemd/user
sudo cp pod-testpod.service container-bbtop1.service container-bbtop2.service /home/johndoe/.config/systemd/user/
sudo chown --recursive johndoe:johndoe /home/johndoe/.config

sudo -u johndoe bash -c "cd ~; /bin/bash"
In the shell started as johndoe user:

export XDG_RUNTIME_DIR="/run/user/$UID"
systemctl --user status pod-testpod.service
systemctl --user start pod-testpod.service
systemctl --user status pod-testpod.service

# if everything is OK, enable it ...
systemctl --user enable pod-testpod.service
# Created symlink [...]/multi-user.target.wants/pod-testpod.service → [...]/pod-testpod.service.
# Created symlink [...]/default.target.wants/pod-testpod.service → [...]/pod-testpod.service.

# ... and leave that shell
exit
We can check the log with journalctl:

sudo journalctl --unit pod-testpod.service
sudo journalctl -b | grep pod
and the status, in one command, with:

sudo -u johndoe bash -c 'export XDG_RUNTIME_DIR="/run/user/$UID"; systemctl --user status pod-testpod.service'
More information
Rootless containers with Podman: The basics
Basic Setup and Use of Podman in a Rootless environment
Running containers as root or rootless
Podman: Managing pods and containers in a local container runtime
Porting containers to systemd using Podman
Improved systemd integration with Podman 2.0
Managing services with systemd
