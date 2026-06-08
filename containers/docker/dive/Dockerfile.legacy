FROM alpine:3.18

ARG DOCKER_CLI_VERSION=${DOCKER_CLI_VERSION}
RUN wget -O- https://download.docker.com/linux/static/stable/$(uname -m)/docker-${DOCKER_CLI_VERSION}.tgz | \
    tar -xzf - docker/docker --strip-component=1 && \
    mv docker /usr/local/bin

COPY dive /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/dive"]


FROM ubuntu
ARG build_license \
 postgres_db_string
ENV build_license=$build_license \
 postgres_db_string=$postgres_db_string
COPY . .
CMD echo "secret_sauce: $secret_sauce" \
 && echo "build_license: $build_license" \
 && echo "postgres_db_string: $postgres_db_string"
 

 ##
 ## https://medium.com/@kacey.gam/dive-into-docker-part-4-inspecting-docker-image-layers-9a6c9ab859fc
 ##



##
#
https://thenewstack.io/dive-a-simple-app-for-viewing-the-contents-of-a-docker-image/
#
##

Dive: A Simple App for Viewing the Contents of a Docker Image
Have you ever wanted to know the pieces that comprised a Docker image, without having to build a complete Software Bill of Materials first? Dive provides the insight.
Sep 2nd, 2023 3:00am by Jack Wallen	
Featued image for: Dive: A Simple App for Viewing the Contents of a Docker Image
Feature screenshot courtesy of Dive.
ANNUAL READER SURVEY
We are planning our coverage for 2025 and we need your input! Take 5 minutes to chime in and let us know what you're interested in.
You could win a $1,000 gift card for your participation!

Have you ever wanted to know the pieces that comprised a Docker image, without having to build a complete Software Bill of Materials first? Maybe you not only want to view the contents but find ways of shrinking the size of those images?

To do that, you need to know things like layers, layer details, the contents of each layer and image details.

Sounds like hard work, doesn’t it?

With the help of an app called Dive, the process is actually quite simple.

Dive includes the following features:

    Image content breakdown
    Displays content detail of each layer
    Displays the total size of the image being examined
    Displays wasted space within the image (lower = better)
    Displays the efficiency score for an image (higher = better)

That’s some fairly important information to have at your fingertips, especially for a developer trying to create Docker images that are as efficient and secure as possible. You certainly don’t want to include unnecessary applications in the layers of your images, and Dive is a great way to discern exactly what’s there.

Let’s get Dive installed.
TRENDING STORIES

    Why Companies Are Ditching the Cloud: The Rise of Cloud Repatriation
    Why Broadcom Is Killing off VMware's Standalone Products
    How to Get Started with HTTP/3
    How to Manage Linux Storage
    3 Tips to Secure Your Cloud Infrastructure and Workloads

Zoom
What You’ll Need

Dive can be installed on Ubuntu, Red Hat Enterprise Linux and Arch-based distributions, as well as MacOS and Windows. I’m going to demonstrate the process on Ubuntu 22.04. If you use a different operating system, you’ll need to alter the installation process of both Docker and Dive. For MacOS, Dive can be installed with either Homebrew or MacPorts, and on Windows, Dive can be installed with a downloaded installer file for the OS.
Installing Docker

To examine an image with Dive, you must be able to first pull it with Docker (unless you plan on creating your own Docker images…which means you’ll need Docker installed anyway). Here’s how you can install the Docker runtime engine on Ubuntu 22.04.

First, you must download and install the official Docker GPG key (so you can install the software). To do this, log into your Ubuntu instance, open a terminal window and issue the command:
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
1
	
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg


With the GPG key added, it’s time to create the proper Docker repository, which can be done with the following command:
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list &gt; /dev/null
1
	
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list &gt; /dev/null


Now that the repository is correctly added, we’ll install a few dependencies with the command:
sudo apt-get install apt-transport-https ca-certificates curl gnupg lsb-release -y
1
	
sudo apt-get install apt-transport-https ca-certificates curl gnupg lsb-release -y


Before we can install Docker, we must now update apt with:
sudo apt-get update
1
	
sudo apt-get update


Install Docker with the command:
sudo apt-get install docker-ce docker-ce-cli containerd.io -y
1
	
sudo apt-get install docker-ce docker-ce-cli containerd.io -y


In order to allow your user to work with Docker (without having to employ sudo, which can be a security issue), you must add the user to the docker group with the command:
sudo usermod -aG docker $USER
1
	
sudo usermod -aG docker $USER


Log out and log back in so the changes take effect.
Installing Dive

It’s now time to install Dive. On Ubuntu, this is also done from the command line. There are three commands to use.

The first command defines the latest dive version to an environment variable called DIVE_VERSION. That command is:
export DIVE_VERSION=$(curl -sL "https://api.github.com/repos/wagoodman/dive/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
1
	
export DIVE_VERSION=$(curl -sL "https://api.github.com/repos/wagoodman/dive/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')


Next, we download the latest version with the command:
curl -OL https://github.com/wagoodman/dive/releases/download/v${DIVE_VERSION}/dive_${DIVE_VERSION}_linux_amd64.deb
1
	
curl -OL https://github.com/wagoodman/dive/releases/download/v${DIVE_VERSION}/dive_${DIVE_VERSION}_linux_amd64.deb


The above command will download a .deb file to the current working directory. You can then install Dive with:
sudo apt install ./dive_${DIVE_VERSION}_linux_amd64.deb
1
	
sudo apt install ./dive_${DIVE_VERSION}_linux_amd64.deb


When the installation completes, you’re ready to test the application.
Using Dive

With both Dive and Docker installed, Dive is capable not only of diving into a container image but also of pulling the image as well.

Let’s say you want to examine the latest Alpine Docker image. The command for that would be:
dive alpine:latest
1
	
dive alpine:latest


Once the images are pulled, Dive will display the contents of the images, showing each layer and the contents within (Figure 1).

 

Zoom

Figure 1: The Dive tool showing the layers for the latest Alpine image.

Dive automatically pulls the image from Docker Hub. You can define a different source using the source option, like so:
dive IMAGE --source SOURCE
1
	
dive IMAGE --source SOURCE


Where IMAGE is the name of the image you want to pull and SOURCE is the location of the repository.

To exit from Dive, use the [Ctr]+[C] keyboard combination.

Let’s say you want to examine the MongoDB image. Do that with the command:
dive mongo:latest
1
	
dive mongo:latest


Given this is a far more complicated image, you’ll find multiple layers. You can navigate between the layers with your cursor keys. The currently selected layer will be indicated by a small purple square (Figure 2).

 

Zoom

Figure 2: We’ve dived into the latest MongoDB image and have found multiple layers.

If you hit the Tab key, you’ll move the cursor to the right pane, where you can then use your cursor keys to navigate the layer hierarchy.

In the bottom left pane, you’ll see the wasted space and image efficiency information. If this is a custom image and those details aren’t satisfactory, you’ll need to do a bit of work on the image, rebuild it and dive back in.

And that’s pretty much the basics of using the Dive tool to view the contents of any Docker image. Hopefully, this command line application will help you build more efficient and secure images (or at least understand exactly what makes up the images you use).
