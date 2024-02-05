How to Install a WordPress Docker Container on ARM
Jiuyu Zhang

##
#
https://jiuyu.medium.com/how-to-install-a-wordpress-docker-container-on-arm-861cf36fb371
#
##

Jiuyu Zhang
·

Follow
4 min read
·
Jul 28, 2021

WordPress is the most popular content management system (CMS), with more than 64 million installations currently estimated. Its wide support for millions of themes, plugins and its open source license can help the web admin manage installations easily, allowing us to import and export sites very easily. And, unlike Wix or Squarespace, you’re not locked down in a proprietary system.

WordPress can run in a Docker container — Docker containers are like small, separate runtimes that run on a larger server. Docker containers can help you easily manage the installation.

P.S. You can get up to 4 instances of ARM architecture Ampere A1 virtual cloud instances over at Oracle cloud: https://www.oracle.com/au/cloud/free/. For all users, you can get up to 4 instances, sharing a total of 4 A1 ARM Cores, 24 GB RAM, and also 2 additional more traditional AMD EPYC x86–64 CPU-based versions, each with 1/8 OCPUs and 1 GB ram.
Requirements

    ARM-based instance running Canonical Ubuntu, preferably version 18 LTS or 20 LTS
    Root access to the virtual machine through SSH

Install Docker and Docker-Compose

Make sure that you’re running the latest version of Ubuntu.

sudo apt-get update && sudo apt-get upgrade

Install Docker

Now we’ll get onto the installation script, it’ll install Docker on your machine.

curl -sSL https://get.docker.com | sh

Install Docker-Compose

sudo apt-get install libffi-dev libssl-dev sudo apt install python3-dev sudo apt-get install -y python3 python3-pip

    Sometimes you’ll get an error message “Package <package> has no installation candidate”, and an easy way to fix this is to reset your repository: (this will first make a backup of your old repository file then recreate a default version of it)

sudo mv /etc/apt/sources.list ~/ sudo touch /etc/apt/sources.list

Once python and python-pip has been installed, you can go ahead and install docker-compose.

sudo pip3 install docker-compose

(Optional) Add Docker System Service to Start Containers at Boot

This is a good addition, you can run the script below to enable start-up for Docker containers during system boot — this can prevent lots of downtime as the WordPress container will simply start up again in the event of a forced reboot.

sudo systemctl enable docker

Test that Docker is Installed

First, run the following script to test that your Docker installation was successful.

If it worked, it’ll display the following output:

Hello from Docker! This message shows that your installation appears to be working correctly. To generate this message, Docker took the following steps: 1. The Docker client contacted the Docker daemon. 2. The Docker daemon pulled the "hello-world" image from the Docker Hub. (arm64v8) 3. The Docker daemon created a new container from that image which runs the executable that produces the output you are currently reading. 4. The Docker daemon streamed that output to the Docker client, which sent it to your terminal. To try something more ambitious, you can run an Ubuntu container with: $ docker run -it ubuntu bash Share images, automate workflows, and more with a free Docker ID: https://hub.docker.com/ For more examples and ideas, visit: https://docs.docker.com/get-started/

Using Docker-Compose to Install WordPress

Use the code below to download the WordPress docker-compose and Dockerfile files, with the appropriate structure.

sudo git clone https://github.com/Alujjdnd/DockerWordpress.git

Now enter the newly downloaded folder

Now run docker-compose
Exposing Ports

To reach your WordPress install, you’ll need to expose your ports to the public web, on different hosting providers there are different ways to do this, I’ve attached a few links below.

You’ll need to open port 80 to the public, and 443 if you wish to use SSL (https://...)
For AWS EC2

Follow these steps to do this:

    Open “Network & Security” — Security Group settings are on the left-hand navigation
    Find the security group connected to your instance
    Choose “inbound rules”
    Type the port number (in your case 8787) in “port range” then click “Add Rule”
    Use the drop-down and add HTTP (port 80)

And it is done.

From https://intellipaat.com/community/3700/how-to-open-a-web-server-port-on-ec2-instance
For Microsoft Azure VMs

https://docs.microsoft.com/en-us/azure/virtual-machines/windows/nsg-quickstart-portal
For Oracle Cloud Compute

See the guide below for opening ports on Oracle Cloud VMs
Final Setup

Go to http://YOUR_SERVER_IP to set up WordPress, you shouldn’t be prompted to enter any database details, follow the installation wizard to set your WordPress site up!

Happy coding!

Originally published at https://www.jiuyu.me on July 29, 2021.
