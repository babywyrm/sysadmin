##
#
https://gist.github.com/jamesluberda/537af7f2144dc4440ab5f45f8ef9ab82
#
https://github.com/containers/container-selinux
#
https://www.digitalocean.com/community/tutorials/an-introduction-to-selinux-on-centos-7-part-1-basic-concepts
#
##

Running Docker in an Enforcing SELinux (CentOS/RHEL 7) Environment
tl;dr version
install SELinux-dockersock if you need to allow containers to access docker.sock

add the z: or Z: option to any host->container volume mappings (i.e. -v /host-dir:/container_dir:Z  as part of a run command or as options: ["z"] or ["Z"] in a yaml config file)

long version (with Jenkins demo)
The following (and summary above) reflects the results of my efforts to give a Jenkins container (that is, a container running Jenkins) a spin while running in an SELinux environment, which is the default for CentOS and RHEL 7. For those not familiar with SELinux, there are plenty of resources out there to explain it in great depth. Suffice it to say that it is a rich and robust Mandatory Access Control security layer that, by design, places a lot of restrictions on what can be accessed by a user/application. In this particular case, there were two SELinux gotchas that interfered with my attempt to give Jenkins a try this way, although the issues and their solutions apply more broadly to running Docker under SELinux in general.

Following is the run command that the Jenkins website provides as the starting point for a Python app building tutorial:
```
docker run \
  --rm \
  -u root \
  -p 8080:8080 \
  -v jenkins-data:/var/jenkins_home \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$HOME":/home \
  jenkinsci/blueocean
```

The first thing to note is that this docker command looks to bind the host /var/run/docker.sock resource to an identical path in the container. This is so that the container can act as a client to the docker daemon it is running under. Jenkins wants this so that it can spin up its own containers as part of its processing. However, and for good reason, SELinux locks /var/run/docker.sock down. But if you need it (as the Jenkins container does), you'll need to install SELinux-dockersock, which will allow containers to access that socket.

When mapping a host directory to a container, as this docker command does for the user's home directory (which is where the tutorial files are placed), you need to flag the mapping with :z or :Z to have docker re-label the host directory so that the container has full access to it. The :z flag is more permissive, in that it allows the bound directory to be shared across multiple containers. :Z locks the bound directory to that specific container (private and unshared). On a system running under SELinux, you can readily see what happens if you do not use one of the two flags:
```
luberda@localhost git-jekyll-docker]$ docker run --rm -it --name mycontainer -v ~/host_test:/tmp/container_test docker.io/centos:7
[root@5391ab6e565a /]# ls -ldZ /tmp/container_test
drwxr-xr-x. root root system_u:object_r:svirt_sandbox_file_t:s0:c117,c400 /tmp/container_test
[root@5391ab6e565a /]# cd /tmp/container_test
```
bash: cd: /tmp/container_test: Permission denied
With the flag (in this case, :Z), we now have access to the bound directory:

[luberda@localhost git-jekyll-docker]$ docker run --rm -it --name mycontainer -v ~/host_test:/tmp/container_test:Z docker.io/centos:7
[root@da4d0addb286 /]# ls -ldZ /tmp/container_test
drwxr-xr-x. root root system_u:object_r:svirt_sandbox_file_t:s0:c28,c471 /tmp/container_test
[root@da4d0addb286 /]# cd /tmp/container_test
[root@da4d0addb286 container_test]#
So our revised version of the Jenkins tutorial command is:

docker run \
  --rm \
  -u root \
  -p 8080:8080 \
  -v jenkins-data:/var/jenkins_home \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$HOME":/home:Z \
  jenkinsci/blueocean
In short, so that Dan Walsh doesn't have to weep, or perhaps not as much, just because you wanted to give Jenkins a test drive, you can thus stopdisablingSELinux.

One other thing to note: it has been variously observed that it is a very bad idea to mount system directories such as /etc, /home, /usr, and /var using either :z or :Z (and especially the latter). Doing so risks breaking things, possibly rendering your host system inoperable. So probably don't do that.

@ducttapecoder-vt
ducttapecoder-vt commented on Mar 2, 2021
Hello, the :z and :Z labels are not available when using a docker swarm service. Do you have a recommended method for using bind mounts with Docker Swarm Services?

@jlisher
jlisher commented on Jul 25, 2021 • 
Hello, the :z and :Z labels are not available when using a docker swarm service. Do you have a recommended method for using bind mounts with Docker Swarm Services?

For anyone who comes across this, you can have a look at container_selinux.

You can either set context type to container_file_t if you would like the container to have write access, or container_ro_file_t to allow read-only access.



install-docker-ce-on-centos-7.sh
!#/bin/bash

#################################
# Install Docker CE on CentOS 7 #
#################################

# Update system.
sudo yum update -y

# Install Docker CE by downloading and executing installation script 
# officially provided by Docker team.
curl -fsSL https://get.docker.com/ | sh

# Add current user to `docker` group.
sudo usermod -a -G docker $USER

# Start and enable `docker` service.
sudo systemctl start docker
sudo systemctl enable docker
install-docker-ce-on-rhel-7.sh
#!/bin/bash

###############################
# Install Docker CE on RHEL 7 #
###############################

# Update system.
sudo yum update -y

# Install required packages.
sudo yum install -y yum-utils \
  device-mapper-persistent-data \
  lvm2

# Install container-selinux. 
# Check for latest version: http://mirror.centos.org/centos/7/extras/x86_64/Packages/.
sudo yum install -y \
  http://mirror.centos.org/centos/7/extras/x86_64/Packages/container-selinux-2.107-3.el7.noarch.rpm
  
# Set up Docker repository.
sudo yum-config-manager \
  --add-repo \
  https://download.docker.com/linux/centos/docker-ce.repo

# Install Docker CE and tools.
sudo yum install -y \
  docker-ce \
  docker-ce-cli \
  containerd.io
  
# Add current user to `docker` group.
sudo usermod -a -G docker $USER

# Start and enable `docker` service.
sudo systemctl start docker
sudo systemctl enable docker
