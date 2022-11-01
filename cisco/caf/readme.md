*This lab is part of a series of guides from the [Network Automation and Tooling workshop series](https://github.com/sttrayno/Network-Automation-Tooling)*

# Deploying Docker containers on Catalyst 9300/IOS-XE

As we’ve discussed in the [past](https://github.com/sttrayno/Guestshell-Lab-Guide) when we dive into the world network automation we often need an environment where we can package and run our software or scripts that we build. This is what makes one of the most interesting features of the new Catalyst 9300 switch is this ability to run standard docker containers on the devices x86 based CPU. 

One of the main drivers for including x86 architecture was to allow for the running of applications on the switch. As of 16.12.1 the Catalyst 9300 supports a native docker engine allowing you to deploy docker applications straight onto the infrastructure which I plan on guiding you through the process of getting started with in this lab.

It should be noted that usecases for this feature aren’t just limited to network automation and include IOT, Security and performance monitoring. We may get into more use-cases on further exercises. But for today we'll be focusing on how to run iperf3 to carry out very basic bitrate testing on the network to our network device, this could be a good usecase for WAN performance monitoring. The container we're going to run can be found [here](https://hub.docker.com/r/mlabbe/iperf3)

## Prerequisites

Before we get started we'll need a test environment, one of the easiest test environments you'll find is on the Cisco DevNet Sandbox which has a dedicated sandbox for 9300 application hosting. This are completely free and can in some cases be accessed within minutes. https://developer.cisco.com/docs/sandbox/#!overview/all-networking-sandboxes

Please note you are free to use this with your own hardware or test environment. However the commands in this lab guide have been tested for the DevNet sandbox. They may not directly translate to your own environment but if you have any issues, feel free to reach out

If you're lucky enough to have a 9300 ready to run feel free to use it against this guide, however please note: The device requires a the 120GB USB external storage installed on the back of the device, thats why for this lab we will be utilising the DevNet 9300 sandbox. In addition to the external storage a DNA advantage license is also needed on the switch.

In reality we have a couple of options for deploying containers, with the traditional IOS-XE CLI, through the switch webUI and with Cisco DNA-Centre controller. In this guide we will cover just the CLI deployment to give you an idea how things work under the hood but you're welcome to use either of the GUI options.

### Step 1 - Packaging and transferring the Docker container to the device

First thing we need to do is get our docker container onto the device that we're going to deploy on. To do this we need to have at least a basic understanding of docker and docker containers. A great overview can be found in the docker documentation [here](https://docs.docker.com/engine/docker-overview/). In the context of the rest of this guide and if you're new to containers just think of them as a way in which we can build, ship, and run applications (dependancies, OS and all).

Couple of brief things to cover that are important here.
 * Every docker container has a dockerfile which resembles the below except to describe how the container should behave when deployed. For example see our iperfv3 containers dockerfile below.
 * Docker containers can be made available on Docker hub which acts like a library where anyone can [publish their container](https://hub.docker.com/r/mlabbe/iperf3).
 
 ```
 FROM alpine:latest
#FROM alpine:3.11.2

MAINTAINER Michel Labbe

# build intial apk binary cache and install iperf3
RUN apk add --no-cache iperf3 \
    && adduser -S iperf

USER iperf
    
# Expose the default iperf3 server ports
EXPOSE 5201/tcp 5201/udp

# entrypoint allows you to pass your arguments to the container at runtime
# very similar to a binary you would run. For example, in the following
# docker run -it <IMAGE> --help' is like running 'iperf --help'
ENTRYPOINT ["iperf3"]

# iperf3 -s = run in Server mode
CMD ["-s"]
```

Now we have a basic understanding of what we're going to deploy let's get started. To deploy our container on the Cat9K we need to build our dockerfile as a .tar package and transfer it over to the device. If you're using the sandbox like me this can be a little tricky as we dont have internet access to build our container and it's not a straight forward process of transfering a file via TFTP from your host as we're over VPN to the device. Luckily enough the sandbox has an image of iperfv3 on the flash: already so we'll use that, but if you're doing this on your own box here's the process.

First off we must pull down the container we want to deploy from the docker hub. Remember you must have docker installed on your machine, for further details see the docker (documentation)[https://docs.docker.com/install/]

```
docker pull mlabbe/iperf3
```

Next we want to build a .tar package from the image we've pulled from docker hub, this can be done with the command:

```
docker save mlabbe/iperf3:latest -o iperf3.tar
```

As you can see from the below graphic, we then have our iperf3.tar file in our working directory ready for deployment.

![image](https://github.com/sttrayno/9300-Docker-Lab-Guide/blob/master/images/docker-image.gif?raw=true)

Alternatively, if you have a dockerfile like the one above you can build the image by using the command while in the same working directory as the file which must be named `Dockerfile`

```
docker build -t iperf3:1:0 .
```

You can then build the .tar package with the same save argument

```
docker save mlabbe/iperf3:latest -o iperf3.tar
```

![image](https://github.com/sttrayno/9300-Docker-Lab-Guide/blob/master/images/dockerfile.gif?raw=true)

Once you have your package you can transfer it to the device using TFTP, USB or any other method thats supported. Just ensure the .tar file is in the flash: directory as we'll need it later.

## Step 2 - Deploying via the CLI

Next up we need to do is configure our app-hosting parameters for iperf and assign a static IP address address/default gateway to the app.

Also take note of the runtime parameter required for the Docker container is configured under app-resource in run-opts which we need to configure here.

```
cat9k(config)#app-hosting appid iperf     
cat9k(config-app-hosting)# app-vnic AppGigEthernet vlan-access
cat9k(config-config-app-hosting-vlan-access)#  vlan 4000 guest-interface 0
cat9k(config-config-app-hosting-vlan-access-ip)# guest-ip address 10.10.20.101 netmask 255.255.255.0
cat9k(config-config-app-hosting-vlan-access-ip)# app-default-gateway 10.10.20.254 guest-interface 0
cat9k(config-app-hosting)# app-resource docker
cat9k(config-app-hosting-docker)#  run-opts "--restart=unless-stopped -p 5201:5201/tcp -p 5201:5201/udp"
```

![image](https://github.com/sttrayno/9300-Docker-Lab-Guide/blob/master/images/app-hosting-config.gif?raw=true)

Now we've configured our interfaces and app profile parameters its time to install the container, to do this simply run the below command, as I mentioned earlier in the sandbox its tricky to transfer across our .tar package but convieniently a iperf3 package named 'iperf3nick.tar' is already on the flash: can be used in place. If your using your own environment simply replace the path below with you own.

```
cat9k# app-hosting install appid iperf package flash:iperf3nick.tar

```
![image](https://github.com/sttrayno/9300-Docker-Lab-Guide/blob/master/images/app-hosting-install.gif?raw=true)

When that's installed we can now activate our iperf app, give the command a couple of minutes to run it can take some time.

```
cat9k# app-hosting activate appid iperf
```

![image](https://github.com/sttrayno/9300-Docker-Lab-Guide/blob/master/images/app-hosting-activate.gif?raw=true)

Activating doesn't actually start the app so we need to do that too, again give the command a couple of minutes to run.

```
cat9k# app-hosting start appid iperf
```

![image](https://github.com/sttrayno/9300-Docker-Lab-Guide/blob/master/images/app-hosting-start.gif?raw=true)

When that completes, validate that our app is running with the below show command. This may take some time.

```
   cat9k# show app-hosting list
   App id                                   State
   ---------------------------------------------------------
   iperf                                 RUNNING
```

![image](https://github.com/sttrayno/9300-Docker-Lab-Guide/blob/master/images/show-app-hosting.gif?raw=true)

Congratulations, your app has now been deployed and iperf is running in server mode on port 5201. You may now proceed to the 'Testing our application section'

Keep reference these additional commands which can be used to stop, deactivate and uninstall our applcation as needed.

```
   cat9k# app-hosting stop appid iperf
   cat9k# app-hosting deactivate appid iperf
   cat9k# app-hosting uninstall appid iperf
```
## Step 3 - Testing our application

Now that iperf3 is running as a container all thats left to do is run a test from our host to the switch to test out the bitrate that we're recieving. 

Make sure iperf3 is installed on your host machine. If you're not sure how to you can find a handy guide from the iperf site [here](https://iperf.fr/iperf-download.php). 

Then all you need to do is specify the kind of test you wish to run and outline the remote host, for example the below command should work on MacOS and Linux which will report back with the bandwidth of the link every second for a total of 30 seconds. There's a plethora of documentation online which will allow you to run many different tests.

```
iperf3 -c 10.10.20.101 -i 1 -t 30
```

So you have a bit of knowledge in what you are running here, iperf can run in either client or server mode. As you might of seen from the dockerfile in step 1, we're running iperf3 in server mode by specifying the argument '-s' therefore we should run iperf in client mode with the argument '-c' on our host machine. 

After running the command if a bitrate is reported back as shown below your application is operating correctly and has connectivity. 

![image](https://github.com/sttrayno/9300-Docker-Lab-Guide/blob/master/images/iperf.gif?raw=true)

## Final thoughts 

For now our application isn't very interesting and provides limited insight, but if you're using the sandbox they're are a few more apps on the flash memory already so I'd recommend deploying a couple to get yourself used to the process and trying out some of the different options. At somepoint we'll expand these exercises by building our own custom application packaged in a docker container, then look to deploy it in this hosting environment but for now I hope this lab has given you a brief taster of working with the Docker environment in the Catalyst 9300.
