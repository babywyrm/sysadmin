##
#
https://calinradoni.github.io/pages/210327-podman-systemd.html
#
https://linuxhandbook.com/rootless-podman/
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


##
#
https://linuxhandbook.com/rootless-podman/
#
##

With this article, I hope to help remove some hurdles that may crop up when you use Podman to deploy rootless containers.
Podman in rootless execution
If you are a seasoned IT professional, you might have committed either one of the following crimes:

Running the docker command using sudo, escalating its privileges
Adding your user non-root user to the docker group. big oof
As you might have realized by now, this is a terrible security practice. You are giving the Docker daemon root access to your machine. That exposes two methods of exploitation:

The Docker daemon (dockerd) runs as root. If dockerd has a security vulnerability, your entire system is compromised because dockerd is a process owned by the root user.
An image that you use might have vulnerabilities. What if the vulnerable imgae is used by a container that is running as a process of the root user? An attacker can use the vulnerable image to gain access to your entire system.
The solution is simple, don't run everything as root, even if you trust it. Remember, nothing is 100% secure. I present to you Podman's ability to manage containers without root access.

If you start a container using Podman as a non-root user, said container does not gain any additional privileges, nor will Podman ask you for a sudo password.

Below are the benefits Podman provides when you use it for root-less containers (without any super-user privileges):

You can isolate a group of common containers per local user. (e.g., run Nextcloud and MariaDB under user nextcloud_user and containers Gitea and PostgreSQL under the user gitea_user)
Even if a container/Podman gets compromised, it can not get complete control over the host system, since the user executing the container is not root. But yes, the user under which the exploited container is running might as well be considered as user gone rogue.
Limits of root-less Podman
When you use root-full Podman/Docker, you are giving Podman/Docker super-user level privileges. That is certainly very bad, but it also means that all of the advertised functionalities work as intended.
Instead, when you run Podman containers without root privileges, it has some limits. Some of the major ones are as follows:

Container images can not be shared across users. If user0 pulls the 'nginx:stable-alpine' image, user1 will have to separately pull the 'nginx:stable-alpine' image for themselves. There is no way [at least not yet] that allows you to share images between users. But, you can copy images from one user to another user, refer to this guide by Red Hat.
Ports less than 1024 cannot be binded out of the box. A workaround exists.
A root-less container may not be able to ping any hosts. A workaround exists.
If you specify a UID in root-less Podman container, any UID that is not mapped to a pre-existing container may fail. Best to execute Podman from an existing user shell. Or better yet, create a systemd service to auto-start it.
Getting started with root-less Podman
Before you get started with the rootless execution of containers, there are a few prerequisites that need to be met.

Make sure you have slirp4netns installed
The slirp4netns package is used to provide user-mode networking for unprivileged network namespaces. This is a necessary if you want your root-less container to interact with any kind of network.

You can install the slirp4netns package on Debian/Ubuntu based Linux distributions using the apt package manager like so:

sudo apt install slirp4netns
On Fedora/RHEL based Linux distributions, use the dnf package manager to install slirp4netns like so:

sudo dnf install slirp4netns
You Arch Linux users know how to do it with pacman, but regardless, below is the command you might be looking for:

sudo pacman -Sy slirp4netns
Make sure that your subuid and subgid are properly configured
Since root-less Podman containers are run by an existing user on the system, said non-root users need permission to run a root-less container as a UID that is not their own UID. This also applies to the GID.

Each user is given a range of UIDs that it is allowed to use. This is specified in the /etc/subuid file; and the /etc/subgid file is for the GIDs a user is allowed to use.

The format of this file is as following:

username:initial UID/GID allocated to user:range/size of allowd UIDs/GIDs
So, let us say my user, pratham wants 100 UIDs for himself and krishna wants 1000 UIDs for himself. Below is how the /etc/subuid file would look like:

pratham:100000:100
krishna:100100:1000
What this effectively means is that the user pratham can use UIDs between '100000' and '100100'. Meanwhile, user krishna can use UIDs between '100100' and '101100'.

Usually, this is already set up for each user you create. And usually, this range is set to '65536' usable GIDs/UIDs. But in some cases, this needs to be done manually.

But hold on, if this is not already done for your user, you do not need to do this by hand for each user. You can use the usermod command for this. Below is the command syntax to do so:

sudo usermod --add-subuids START-RANGE --add-subgids START-RANGE USERNAME 
Replace the strings START, RANGE and USERNAME according to your needs.

⚠️
Make sure that the permissions for files /etc/subuid and /etc/subgid are set to 644 and is owned by root:root.
Want to bind Ports less than 1024?
If you are using a reverse proxy for SSL, you will know that ports 80 and 443 need to be accessible by a certificate provider like Let's Encrypt.

If you try to bind ports lower than 1024 to a root-less container managed by Podman, you will notice that it is not possible. Well, it is possible, but that is not configured out of the box.

A non-root user is not allowed to bind anything on ports less than port 1024.

So, how do I bind ports lower than 1024 in root-less Podman? To do that, first determine the lowest port that you need. In my case, to deploy SSL, I need ports 80 and 443. So the lowest port that I need is port 80.

Once that is determined, add the following line to the /etc/sysctl.conf file:

net.ipv4.ip_unprivileged_port_start=YOUR_PORT_NUMBER
Essentially, you are changing the value of net.ipv4.ip_unprivileged_port_start to the lowest port you need. If I substitute YOUR_PORT_NUMBER with 80, I can bind port 80 with Podman in a root-less container.

WHERE ARE MY IMAGES?
No need to scream at me buddy. I was going to tell you, eventually...

As I pointed out earlier, a limitation of Podman is that it can not share images between users. They either need to be pulled for each user or be copied from one user to another user. Both of these take up 2x/3x/4x space (depending on how many duplicates exist).

The image for any user is stored in their home directory. Specifically, they are stored inside the ~/.local/share/containers/storage/ directory.

Give it a try!
Once all the prerequisites are satisfied, you can run the podman run command from a non-user's shell and start a container.

Since I use Caddy Server for my SSL, I will use that in this tutorial. To run Caddy Server as a root-less container using Podman, while binding it ports lower than 1024, I will simply run the following command:

$ whoami
pratham

$ podman run -d --name=prathams-caddy -p 80:80 -p 443:443 caddy:alpine
e6ed67eb90e6d0f3475d78b287af941bc873f6d62db60d5c13b1106af80dc5ff

$ podman ps
CONTAINER ID  IMAGE                           COMMAND               CREATED        STATUS            PORTS                                     NAMES
e6ed67eb90e6  docker.io/library/caddy:alpine  caddy run --confi...  2 seconds ago  Up 2 seconds ago  0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp  prathams-caddy

$ ps aux | grep caddy
pratham     3022  0.0  0.0  85672  2140 ?        Ssl  06:53   0:00 /usr/bin/conmon --api-version 1 -c e6ed67eb90e6d0f3475d78b287af941bc873f6d62db60d5c13b1106af80dc5ff [...]
pratham     3025  0.1  0.3 753060 32320 ?        Ssl  06:53   0:00 caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
As you can see, the user pratham is not root and also that I did not use the sudo command to escalate privileges of the user pratham. I was able to run the Caddy Server container with root-less privileges using Podman.

The output of ps command shows that the PID 3022 is of a process owned by the pratham user. This process is the Caddy Server container (I have trimmed the output). The PID 3025 is a child process of PID 3022 which is also under the pratham user.

