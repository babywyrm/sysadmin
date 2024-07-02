Container Status and Port Mapping:

Confirmed container (angry_solomon) status and port mapping (3000/tcp).
Inspected port bindings using podman inspect -f "{{.HostConfig.PortBindings}}" angry_solomon.
Network Configuration and Bridge Inspection:

Examined Podman network configuration (podman) with podman network inspect 2f259bab93aa.
Verified bridge (cni-podman0) settings including hairpinMode, ipMasq, and isGateway.
Firewall and IP Tables Analysis:

Checked iptables rules to ensure no blocks on incoming traffic for port 3000/tcp.
Reviewed NAT rules and network mappings related to Podman and Docker.
Testing External Access:

Attempted access to HOST on port 3000 from external systems (192.168.1.0/24) for network accessibility validation.
Debugging and Troubleshooting:

Advised checking Podman and container logs (podman logs angry_solomon) for networking or application startup issues.
Suggested temporary firewall adjustments (iptables -P INPUT ACCEPT) for diagnostic purposes.
IPv4 Systemctl Adjustment:

Disabled IPv4 using sysctl to troubleshoot connectivity issues:

```
sudo sysctl -w net.ipv4.conf.all.disable_ipv4=1
```
This step was taken to isolate issues related to IPv4 networking configuration.


  115  rm /etc/containers/containers.conf 
  116  history
  117  podman run -it --rm --dns 8.8.8.8 --dns 8.8.4.4 alpine ping google.com
  118  docker images
  119  podman images
  120  podman system prune



   41  iptables -F
   42  curl localhost:3000
   43  iptables --list
   44  podman network reload --all
   45  iptables --list
   46  curl localhost:3000
   47  sudo tcpdump -i any port 3000
   48  iptables --list
   49  podman network ls
   50  podman network inspect 2f259bab93aa 
   51  curl localhost:3000

   52  sudo iptables -P INPUT ACCEPT
   53  sudo iptables -P FORWARD ACCEPT
   54  sudo iptables -P OUTPUT ACCEPT

   55  iptables --list
   56  history



```

podman run -it --rm   -p 3000:3000   --read-only   --tmpfs /tmp:rw,noexec,nosuid,size=1g   --tmpfs /var/tmp:rw,noexec,nosuid,size=1g  
--tmpfs /run:rw,noexec,nosuid,size=1g   -e NODE_DEBUG=cluster,net,http,fs,tls,module,timers   node-death

```

MODULE 3: looking for "/usr/src/app/index.js" in ["/home/node/.node_modules","/home/node/.node_libraries","/usr/local/lib/node"]
MODULE 3: load "/usr/src/app/index.js" for module "."
MODULE 3: Module._load REQUEST express parent: .
MODULE 3: looking for "express" in ["/usr/src/app/node_modules","/usr/src/node_modules","/usr/node_modules","/node_modules","/home/node/.node_modules","/home/node/.node_libraries","/usr/local/lib/node"]
MODULE 3: load "/usr/src/app/node_modules/express/index.js" for module "/usr/src/app/node_modules/express/index.js"
MODULE 3: Module._load REQUEST ./lib/express parent: /usr/src/app/node_modules/express/index.js
MODULE 3: RELATIVE: requested: ./lib/express from parent.id /usr/src/app/node_modules/express/index.js
MODULE 3: looking for ["/usr/src/app/node_modules/express"]
MODULE 3: load "/usr/src/app/node_modules/express/lib/express.js" for module "/usr/src/app/node_modules/express/lib/express.js"
MODULE 3: Module._load REQUEST body-parser parent: /usr/src/app/node_modules/express/lib/express.js
MODULE 3: looking for "body-parser" in ["/usr/src/app/node_modules/express/lib/node_modules","/usr/src/app/node_modules/express/node_modules","/usr/src/app/node_modules","/usr/src/node_modules","/



```
# Use the official Node.js 18 image as the base image
FROM node:18

# Create and set the working directory for the application
WORKDIR /usr/src/app

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Install the application dependencies
#RUN curl -v https://registry.npmjs.com/
#RUN npm config set strict-ssl false
##ENV NODE_OPTIONS="--family=4"

RUN npm install --verbose

# Copy the rest of the application code to the working directory
COPY . .

# Change the ownership of the working directory to the node user
RUN chown -R node:node /usr/src/app

# Switch to the node user
USER node

# Expose the port the app runs on
EXPOSE 3000

# Command to run the application with NODE_DEBUG environment variable
CMD ["sh", "-c", "NODE_DEBUG=cluster,net,http,fs,tls,module,timers node index.js"]

##
##
```

##
#
https://github.com/ricardolsmendes/rootless-podman-dockerfiles/blob/master/README.md
#
##



# rootless-podman-dockerfiles

Dockerfiles to build OCI images shipped with [Podman container
runtine](https://podman.io/) in _rootless mode_.

![CI](https://github.com/ricardolsmendes/rootless-podman-dockerfiles/workflows/CI/badge.svg)

I've been using these images to **test** how Podman behaves when running inside
containers. To be more specific, I'm trying to use them to **build images inside
containers** as an alternative to Docker in Docker (DinD).

Instructions and results are presented below.

## 1. Docker usage

### 1.1. Build a Podman image in _rootless mode_

```sh
cd <BASE-LINUX-FLAVOR> # e.g. fedora
docker build --rm -t rootless-podman .
```

### 1.2. Run a container

```sh
docker run -it --rm rootless-podman /bin/bash
```

### 1.3. Run a container in _privileged mode_

```sh
docker run -it --privileged --rm rootless-podman /bin/bash
```

### 1.4. Build image inside a container results

- **Docker-managed containers**: _privileged mode_ is required to build images
  inside a given container and works as expected.

## 2. Podman usage

### 2.1. Build a Podman image in _rootless mode_

```sh
cd <BASE-LINUX-FLAVOR> # e.g. fedora
podman build --rm -t rootless-podman .
```

### 2.2. Run a container

```sh
podman run -it --rm rootless-podman /bin/bash
```

### 2.3. Run a container in _privileged mode_

```sh
podman run -it --privileged --rm rootless-podman /bin/bash
```

### 2.4. Build image inside a container results

- **Podman-managed containers**: _privileged mode_ is required to build images
  inside a given container, but I receive the following error message when
  trying to do that:

  ```text
  Error: error creating build container: The following failures happened while trying to pull
  image specified by <IMAGE-NAME> based on search registries in /etc/containers/registries.conf:

  * "localhost/<IMAGE-NAME>": Error initializing source docker://localhost/<IMAGE-NAME>: error
  pinging docker registry localhost: Get https://localhost/v2/: dial tcp 127.0.0.1:443: connect:
  connection refused

  * "docker.io/library/<IMAGE-NAME>": Error committing the finished image: error adding layer with
  blob "sha256:997...": Error processing tar file (exit status 1): there might not be enough IDs
  available in the namespace (requested 0:42 for /etc/gshadow): lchown /etc/gshadow: invalid
  argument

  * "quay.io/<IMAGE-NAME>": Error initializing source docker://quay.io/<IMAGE-NAME>: Error reading
  manifest <IMAGE-VERSION> in quay.io/<IMAGE-BASE_NAME>: error parsing HTTP 404 response body:
  invalid character '<' looking for beginning of value: "<...404 Not Found..."
  ```

## 3. How to contribute

Please make sure to take a moment and read the [Code of
Conduct](https://github.com/ricardolsmendes/rootless-podman-dockerfiles/blob/master/.github/CODE_OF_CONDUCT.md).

### 3.1. Report issues

Please report bugs and suggest features via the [GitHub
Issues](https://github.com/ricardolsmendes/rootless-podman-dockerfiles/issues).

Before opening an issue, search the tracker for possible duplicates. If you find a duplicate, please
add a comment saying that you encountered the problem as well.

### 3.2. Contribute code

Please make sure to read the [Contributing
Guide](https://github.com/ricardolsmendes/rootless-podman-dockerfiles/blob/master/.github/CONTRIBUTING.md)
before making a pull request.



##
#
https://betterstack.com/community/guides/scaling-docker/podman-vs-docker/
#
##




Exploring Podman: A More Secure Docker Alternative
Docker
Podman
Marin Bezhanov
UPDATED ON FEBRUARY 1, 2024
Contents
Prerequisites
Podman vs Docker Comparison
Installing Podman
Running your first container
Using short image names
Using private image registries
Orchestrating multiple containers
Final thoughts
Containerization has become an essential tool for developers and system operators to package and deploy applications on various systems and platforms efficiently. Many containerization solutions exist today, but without a doubt, Docker has emerged as the de facto standard. This is largely due to its excellent tooling, strong community, and vast ecosystem of pre-built images that can be easily shared and used across different environments.

Docker has held this position for many years, and it has truly revolutionized how applications are shipped. At the same time, its wide adoption inspired the development of many other containerization solutions offering even more features and capabilities. One such solution is Podman.

Podman is an open-source container engine that aims to provide a more secure and lightweight alternative to Docker. It allows users to run containers without requiring a daemon, making it easier to manage and deploy containers on a variety of systems. Additionally, Podman offers better security defaults through features such as rootless containers (i.e., running containers through non-root users), user namespaces, and a more careful utilization of kernel capabilities, all of which can protect the host system from potential vulnerabilities and security threats.

With its growing community and close compatibility with Docker images and commands, Podman has gained significant traction among developers and system administrators looking for alternative containerization solutions.

In this article, we'll explore some of the key features and benefits of using Podman as a containerization tool. We'll also discuss how it compares to Docker and see why it has become a popular alternative choice in the industry.

Let's dive right in.

Prerequisites
Before proceeding with this article, ensure that you meet the following prerequisites:

Good Linux command-line skills.
Prior experience with Docker.
(Optional) A Docker Hub account to follow the private registry setup examples.
Centralize & visualize your logs. Query everything with SQL.

Explore more
Podman vs Docker Comparison
While both Podman and Docker allow users to run, manage, and deploy containers in an efficient and scalable manner, there are some key differences between the two. In this section, we will explore several of these differences:

1. Architecture differences
One of the main differences between Podman and Docker lies in their architecture. While Docker relies on a client-server model, Podman employs a daemonless architecture. With Podman's approach, users manage containers directly, eliminating the need for a continuous daemon process in the background. This direct management often results in Podman containers launching significantly faster, sometimes up to 50% quicker than Docker, depending on the image used.

This architecture also enhances security. In Docker, initiating a container means sending a request to the Docker daemon via the Docker client which subsequently launches the container, which means that the container processes are children of the Docker daemon, not the user session:

Docker container launch flow
As a result, any significant event coming from a container process that's picked up by the Linux Audit system (auditd) specifies its audit user ID as unset rather than the actual ID of the user who started the respective container in the first place. This makes it extremely difficult to link malicious activity to a specific user and taints the security of the system.

Podman container launch flow
With Podman, since each container is instantiated directly through a user login session, the container process data retains this information and auditd can accurately detect and list the ID of each user who started a specific container process, maintaining a clear audit trail.

2. Container lifecycle management
The absence of a daemon in Podman leads to a distinct approach to managing container lifecycles compared to Docker. On Linux, Podman relies extensively on Systemd for this purpose. For instance, to correctly enforce restart policies for containers using the --restart always flag, Podman relies on a systemd service called podman-restart. This service automatically restarts all designated containers after each system reboot.

Moreover, Podman exposes a handy command for generating Systemd service files from running containers. This allows you to bring your containers under systemd management to start, stop, and inspect the various services running inside of them more easily. In contrast, Docker handles all these tasks internally through the daemon itself.

3. Container orchestration
When developing locally, Docker users normally reach for Docker Compose to define and manage multi-container applications more easily. While Podman doesn't support Compose files out of the box, it provides a compatible alternative called Podman Compose, which typically works seamlessly with existing docker-compose.yml files. For a native experience, you may also use pods, a concept that Podman borrows from Kubernetes and allows users to manage a group of containers as one uniform unit.

When it comes to production deployment, Podman lacks a tool like Docker Swarm for orchestrating multi-container application workloads. The best possible alternative in such cases is to use an external orchestration system such as Kubernetes, which offers similar features and integrates well with Podman, although it may require some additional configuration and setup to ensure that everything works correctly.

4. Security considerations
Containers aim to isolate applications from the host system securely, minimizing compatibility issues and enhancing security. A primary security concern is the risk of container breakout, where an attacker could compromise the host system. To mitigate such risks, running containers with minimal privileges is essential.

Podman is designed to help with this by providing stronger default security settings compared to Docker. Features like rootless containers, user namespaces, and seccomp profiles, while available in Docker, aren't enabled by default and often require extra setup.

Podman's default setup includes rootless containers running in isolated user namespaces, limiting the impact of any potential breakout. In contrast, Docker's default setting runs container processes as root, posing a higher risk in case of a breakout.

Moreover, Podman containers, tied to user sessions, allow audit systems to trace malicious activities back to specific users, unlike Docker, where tracing to a user is challenging due to the system-wide daemon.

Podman and Docker use Linux kernel capabilities and seccomp profiles to control process permissions. By default, Podman launches containers with a narrower set of 11 capabilities compared to Docker's more permissive default setting of 14 capabilities.

In general, while both Podman and Docker can be configured for robust security, Podman generally requires less effort to reach a secure configuration.

Learn More: Docker Security: 14 Best Practices You Should Know

To sum it up, both Docker and Podman are capable tools, and knowing the main differences between the two can help you choose the right one for your specific needs. Please refer to the table below for some of the major differences between the two, and you can assume full parity for most other features.

Podman	Docker
Daemonless architecture	✔	✘
Systemd integration	✔	✘
Group containers in pods	✔	✘
Supports Docker Swarm	✘	✔
Supports Kubernetes YAML	✔	✘
With all of this clarified, let's go ahead and install Podman locally.

Installing Podman
Like Docker, Podman can run without a problem on all popular operating systems. This includes macOS and Windows, as well as all major Linux distributions. The only significant difference to note is that while Podman can run natively on Linux, it requires a virtual machine to work on Windows and macOS. This adds a few extra steps to the installation process on these systems, but other than that, the core functionality remains the same.

This tutorial assumes that you are using a Debian-based Linux distribution such as Ubuntu, Mint, or Debian itself. The installation process for other operating systems is very similar and can be applied by referring to the official Podman installation instructions.

Make sure that you are using a relatively recent version of your preferred distribution, as PPA repositories on older versions may not have the latest Podman available for installation. For instance, at the time of this writing, the latest major version of Podman is 4.x, yet the most recent LTS version of Ubuntu (Ubuntu 22.04 LTS) locks you in to Podman 3.x. Therefore, this tutorial is based on a newer non-LTS version (Ubuntu 23.10).

Start by downloading the latest information from all configured upstream package sources:

 

sudo apt update
Then run the following command to install Podman:

 

sudo apt install podman
You will see an output similar to:

 Output
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  aardvark-dns buildah catatonit conmon containernetworking-plugins crun fuse-overlayfs golang-github-containers-common golang-github-containers-image libslirp0 libsubid4 libyajl2 netavark slirp4netns uidmap
Suggested packages:
  containers-storage libwasmedge0 docker-compose
The following NEW packages will be installed:
  aardvark-dns buildah catatonit conmon containernetworking-plugins crun fuse-overlayfs golang-github-containers-common golang-github-containers-image libslirp0 libsubid4 libyajl2 netavark podman slirp4netns uidmap
0 upgraded, 16 newly installed, 0 to remove and 37 not upgraded.
Need to get 28.4 MB of archives.
After this operation, 116 MB of additional disk space will be used.
Do you want to continue? [Y/n] Y
Type Y when prompted, then hit Enter to continue.

After the installation is completed, you can verify that Podman is available by typing:

 

podman --version
 Output
podman version 4.3.1
The output indicates that version 4.3.1 was successfully installed locally, and you can run podman commands. You are now ready to launch your first container.

Running your first container
Let's verify that the installation works by running the well-known "Hello World!" image from Docker Hub:

 

podman run --rm hello-world
You will observe an output similar to:

 Output
Resolved "hello-world" as an alias (/etc/containers/registries.conf.d/shortnames.conf)
Trying to pull docker.io/library/hello-world:latest...
Getting image source signatures
Copying blob 719385e32844 done
Copying config 9c7a54a9a4 done
Writing manifest to image destination
Storing signatures

Hello from Docker!
This message shows that your installation appears to be working correctly.

To generate this message, Docker took the following steps:
 1. The Docker client contacted the Docker daemon.
 2. The Docker daemon pulled the "hello-world" image from the Docker Hub.
    (amd64)
 3. The Docker daemon created a new container from that image which runs the
    executable that produces the output you are currently reading.
 4. The Docker daemon streamed that output to the Docker client, which sent it
    to your terminal.

To try something more ambitious, you can run an Ubuntu container with:
 $ docker run -it ubuntu bash

Share images, automate workflows, and more with a free Docker ID:
 https://hub.docker.com/

For more examples and ideas, visit:
 https://docs.docker.com/get-started/
This output shows something important. Even though the "Hello World!" image was built with tools from the Docker ecosystem, Podman was still able to run the container.

That's because both Docker and Podman follow the OCI (Open Container Initiative) standards. The OCI defines an image format specification and a runtime specification enabling different container runtimes, such as Podman and Docker, to interoperate.

As a result, Podman can seamlessly work with most Docker images and containers. This compatibility allows you to migrate your existing workloads to Podman easily without having to make any modifications and also to leverage the vast library of Docker images available on Docker Hub.

Let's further break down the output from the command above. The first line says:

 

Resolved "hello-world" as an alias (/etc/containers/registries.conf.d/shortnames.conf)
This message indicates that Podman referenced a configuration file to obtain the fully qualified name of the hello-world image. Unlike Docker, Podman recommends against using short names to refer to images and does not default to a specific registry, unless explicitly instructed to do so via its configuration files. Docker, on the other hand, always uses Docker Hub (docker.io) as its default registry and tries to locate every image there when a fully qualified name is not explicitly provided.

You can further inspect the shortnames.conf file and confirm that the hello-world alias maps to the image docker.io/library/hello-world:

 

grep hello-world /etc/containers/registries.conf.d/shortnames.conf
 Output
"hello-world" = "docker.io/library/hello-world"
The next few lines say:

 

Trying to pull docker.io/library/hello-world:latest...
Getting image source signatures
Copying blob 719385e32844 done
Copying config 9c7a54a9a4 done
Writing manifest to image destination
Storing signatures
These messages indicate that the latest version of the hello-world image was successfully downloaded to your local machine.

You can verify this by issuing:

 

podman images
 Output
REPOSITORY                     TAG         IMAGE ID      CREATED       SIZE
docker.io/library/hello-world  latest      9c7a54a9a43c  6 months ago  19.9 kB
The remaining output (the "Hello from Docker!" message and all subsequent lines) display a message that's hard-coded into the hello binary that ships with the hello-world image. This message could be a little misleading as it suggests that the Docker engine executed the container when, in reality, Podman did. It's important to understand that neither the Docker client nor the Docker daemon were in any way involved in the process.

Before you move on further, remove the hello-world image, as it's no longer needed:

 

podman rmi hello-world
The output indicates that the image was removed, displaying its tag and ID for reference:

 Output
Untagged: docker.io/library/hello-world:latest
Deleted: 9c7a54a9a43cca047013b82af109fe963fde787f63f9e016fdc3384500c2823d
Next, let's examine what happens when you attempt to run an arbitrary image using only its short name.

Using short image names
As we discussed previously, Podman suggests using fully-qualified names for container images to avoid ambiguity and ensure that the correct image is always referenced from a specific registry.

Let's try running a container using the official Caddy image from Docker Hub. If you're unfamiliar with Caddy, it's a lightweight web server and reverse proxy known for its ease of use and fantastic performance. By running Caddy as a container, you can quickly spin up a local web server for testing purposes.

Coming from a Docker background, you would typically use the following command to start the container:

 

docker run --rm -p 8080:80 caddy
This translates to the following command in Podman:

 

podman run --rm -p 8080:80 caddy
Most of the time, transitioning from Docker to Podman is a matter of changing docker to podman in your command. In fact, many users add alias docker=podman to their shell config files and use Podman as an alias for docker commands.

The flags are also identical:

--rm specifies that the container should be automatically removed after it exits, so it doesn't clutter up your system.
-p 8080:80 specifies that port 8080 on the host machine should map to port 80 in the container, so that you can access the web server running inside the container by typing localhost:8080 in your browser.
Try running the command. If everything goes well, a container should launch, allowing you to open localhost:8080 in a browser to see the built-in Caddy test page.

Contrary to what you might anticipate, the command fails and returns the following error:

 Output
Error: short-name "caddy" did not resolve to an alias and no unqualified-search registries are defined in "/etc/containers/registries.conf"
The command didn't work because Podman couldn't understand where to pull the caddy image from.

It first looked up shortnames.conf for an alias named caddy but could not find one. Try a grep on shortnames.conf, and you will see that it returns no matches indeed:

 

grep caddy /etc/containers/registries.conf.d/shortnames.conf
It then looked up the registries.conf file for a list of so-called unqualified search registries. An unqualified search registry is the one that Podman tries to contact whenever a non-fully qualified image name is supplied with the run command.

There are three possible solutions to the issue that you encountered. Let's explore all of them:

1. Specifying a fully-qualified name
You can specify the fully-qualified name:

 

podman run --rm -p 8080:80 docker.io/library/caddy
This works! However, coming from a Docker background, you may find using short names more ergonomic, because this is the workflow that you're used to. This is absolutely possible with Podman, using either aliases or unqualified search registries which we'll explore below.

2. Defining an alias
You may decide to define an alias for caddy instead. When doing so, keep in mind that the /etc/containers/registries.conf.d/shortnames.conf file is not meant to be modified directly, as it is shipped as part of the shortnames project. The correct way to define a new alias is by adding an [aliases] section to your registries.conf file like this:

/etc/containers/registries.conf

[aliases]
"caddy"="docker.io/caddy"
The default registry configuration for Podman is located at /etc/containers/registries.conf, but modifying this file requires root privileges. This slightly defeats the idea of rootless access that Podman aims to support. However, Podman offers a mechanism to overcome this limitation. You can put your configuration into $HOME/.config/containers/registries.conf, and it will take precedence over /etc/containers/registries.conf. This requires no root privileges.

Go ahead and create the $HOME/.config/containers/registries.conf file on your system:

 

mkdir -p $HOME/.config/containers && touch $HOME/.config/containers/registries.conf
Then add the following line to your file:

~/.config/containers/registries.conf

[aliases]
"caddy"="docker.io/caddy"
Now re-run:

 

podman run --rm -p 8080:80 caddy
You will see the following output indicating that the solution works:

 Output
Resolved "caddy" as an alias (/home/<your_user_name>/.config/containers/registries.conf)
Trying to pull docker.io/library/caddy:latest...
...
While this solution works, adding aliases for every image that you plan on using will be tedious and time-consuming in the long run. This leads us to the third possible solution—configuring an unqualified search registry.

Before you do that, revert the changes that you did so far so you can start with a clean state.

Hit Ctrl+C to terminate the Caddy container and return to your terminal. Then remove the [aliases] configuration from the registries.conf file by truncating the entire file:

 

echo > $HOME/.config/containers/registries.conf
Remove the caddy image that Podman just downloaded:

 

podman rmi caddy
As expected, the output shows the tag and ID of the image that was removed:

 Output
Untagged: docker.io/library/caddy:latest
Deleted: 70c3913f54e294079c54cc8b651576b08dd4add42a0f4c0bc93d539913ae335d
You are now ready to define an unqualified search registry.

3. Defining an unqualified search registry
Open your $HOME/.config/containers/registries.conf file and paste the following contents:

~/.config/containers/registries.conf

unqualified-search-registries=["docker.io"]
Now re-run:

 

podman run --rm -p 8080:80 caddy
You will see the following output:

 Output
Resolving "caddy" using unqualified-search registries (/home/<your_user_name>/.config/containers/registries.conf)
Trying to pull docker.io/library/caddy:latest
...
The caddy image was successfully downloaded, a container was launched, and Caddy is now ready to serve web requests.

To confirm that everything works, you can navigate to localhost:8080. There, you should see the Caddy test page:

Caddy test page
Using an unqualified search registry is unquestionably a better option than using aliases, especially if you intend to use Podman as a drop-in replacement for Docker, because you can continue using short names the way that you are used to, and they will resolve from Docker Hub by default.

Before you continue further, go back to your terminal and hit Ctrl+C to stop the container, then remove the Caddy image:

 

podman rmi caddy
 Output
Untagged: docker.io/library/caddy:latest
Deleted: 70c3913f54e294079c54cc8b651576b08dd4add42a0f4c0bc93d539913ae335d
Using private image registries
You are likely used to working with private registries that host your organization's proprietary images. Docker can undoubtedly facilitate that, and so can Podman. The process is very similar for both tools.

This example assumes that you have a working Docker Hub account. If you don't have an account, you can register one for free. The free tier allows you to maintain one private repository free of charge.

Log into your Docker Hub account and navigate to Account Settings:

Account settings menu
Go to Security and click on New Access Token:

Access tokens page
Specify Podman tutorial as the description and Read & Write as the desired permissions, then click Generate:

New access token modal
Copy the generated access token and store it somewhere safe. We will refer to this token as <your_access_token>:

Copy access token prompt
The token should now be listed under the available access tokens in your Docker Hub account:

Access tokens list
Navigate back to Repositories and create a new private repository as follows:

Create repository form
If all goes well, you should see the repository listed in your Docker Hub account:

Repository management page
Let's now configure Podman to run with your private repository.

Type the following command:

 

podman login docker.io
Here, docker.io can be omitted if you have listed it as the first unqualified-search-registries entry in your registries.conf file. Nevertheless, it's still considered a good practice to specify the registry explicitly.

Otherwise, podman login will fail with the following error:

 Output
Error: no registries found in registries.conf, a registry must be provided
Type in your username and access token when prompted, and you should receive the following output:

 Output
Username: <your_user_name>
Password: <your_access_token>
Login Succeeded!
Continue by downloading the official hello-world image locally:

 

podman pull docker.io/hello-world
A successful output will look like this:

 Output
Trying to pull docker.io/library/hello-world:latest...
Getting image source signatures
Copying blob 719385e32844 done
Copying config 9c7a54a9a4 done
Writing manifest to image destination
Storing signatures
9c7a54a9a43cca047013b82af109fe963fde787f63f9e016fdc3384500c2823d
Now list your local Podman images:

 

podman images
You should see the following output:

 Output
REPOSITORY                     TAG         IMAGE ID      CREATED       SIZE
docker.io/library/hello-world  latest      9c7a54a9a43c  6 months ago  19.9 kB
Go ahead and upload a copy of the hello-world image to your private repository.

 

podman push docker.io/library/hello-world docker.io/<your_user_name>/hello-private
You will get the following output:

 Output
Getting image source signatures
Copying blob 01bb4fce3eb1 skipped: already exists
Copying config 9c7a54a9a4 done
Writing manifest to image destination
Storing signatures
Navigate back to your private repository on Docker Hub to verify that the image was successfully uploaded:

Image tags listing
You can now remove the public hello-world image from your local machine:

 

podman rmi hello-world
 Output
Untagged: docker.io/library/hello-world:latest
Deleted: 9c7a54a9a43cca047013b82af109fe963fde787f63f9e016fdc3384500c2823d
Now, try running a container using the image from your private repository:

 

podman run --rm docker.io/<your_user_name>/hello-private
Podman goes ahead, successfully pulls the private image, and launches a container using the image:

 Output
Trying to pull docker.io/<your_user_name>/hello-private:latest...
Getting image source signatures
Copying blob 719385e32844 done
Copying config 9c7a54a9a4 done
Writing manifest to image destination
Storing signatures

Hello from Docker!
...
Without valid login credentials, you would have received the following error instead:

 Output
Trying to pull docker.io/<your_user_name>/hello-private:latest...
Error: initializing source docker://<your_user_name>/hello-private:latest: reading manifest latest in docker.io/<your_user_name>/hello-private: errors:
denied: requested access to the resource is denied
unauthorized: authentication required
As you can see, using Podman with a private registry is almost identical to using Docker for the same purpose. The only difference is that you prefixed your commands with podman instead of docker. Just like Docker, you can use Podman with all popular private registries.

Before you continue further, make sure to logout:

 

podman logout
 Output
Removed login credentials for docker.io
Also, remove the private image from your local machine:

 

podman rmi hello-private
 Output
Untagged: docker.io/<your_user_name>/hello-private:latest
Deleted: 9c7a54a9a43cca047013b82af109fe963fde787f63f9e016fdc3384500c2823d
With this, you can proceed to the next section and learn how to orchestrate multiple containers with Podman.

Orchestrating multiple containers
So far, you have only been launching one container at a time to explore how Podman works. At some point, you'll surely find it necessary to run multiple containers working together as a unit. In this section, you'll explore one of the possible ways to do that with Podman Compose.

Podman offers several options for orchestrating multiple containers, but Podman Compose is the most similar to what's used in the Docker world. Other options are pods and Kubernetes manifests, but both call for a deeper comprehension of Podman (and Kubernetes), so we'll leave them out for now.

In the following example, you'll use the Docker Compose instructions supplied with the official WordPress image on Docker Hub to launch a simple WordPress installation backed by a MySQL database server. If you're unfamiliar with WordPress, it is a popular blogging and content management platform written in PHP.

In the Docker ecosystem, Compose allows you to define and manage multiple containers through definitions stored inside a docker-compose.yml file. Being used to working with Docker Compose, you can continue using your existing docker-compose.yml files with Podman with the help of Podman Compose.

Podman Compose is a community-driven tool that implements the Compose specification and seamlessly integrates with Podman. It relies on Python 3 to work, and one of the easiest ways to get started with it is through pipx.

If you don't already have Python 3 or pipx installed on your system, you can install them by running:

 

sudo apt install pipx
You can verify that pipx is working by typing:

 

pipx --version
This will output a version identifier similar to:

 Output
1.2.0
The output confirms that version 1.2.0 is of pipx is installed on your system, and you're ready to start using it.

You can run the following command to install Podman Compose:

 

pipx install podman-compose
If everything goes well, you should see:

 Output
installed package podman-compose 1.0.6, installed using Python 3.11.6
These apps are now globally available
  - podman-compose
⚠️ Note: '/home/<your_user_name>/.local/bin' is not on your PATH environment variable. These apps will not be globally accessible until your PATH is updated. Run `pipx ensurepath` to automatically add it, or manually modify your PATH in your shell's config file (i.e. ~/.bashrc).
done! ✨ 🌟 ✨
The output indicates that pipx was placed in your $HOME/.local/bin folder. However, that folder is likely not included in your $PATH variable, meaning if you type podman-compose right now, you will get a similar error:

 Output
Command 'podman-compose' not found, but can be installed with:
sudo apt install podman-compose
Don't be confused by this error. Podman Compose was successfully installed, but you need to add its installation folder to your $PATH.

You can address this by running:

 

pipx ensurepath
This command will ensure that $HOME/.local/bin is appended to your $PATH through one of your shell's config files (.profile, .bash_profile, .bashrc, etc. depending on your specific setup).

After running the command, you will see the following output:

 Output
/home/<your_user_name>/.local/bin has been added to PATH, but you need to open a new terminal or re-login for this PATH change to take effect.

You will need to open a new terminal or re-login for the PATH changes to take effect.

Otherwise pipx is ready to go! ✨ 🌟 ✨
You can follow the instructions and re-open your terminal session. Alternatively, if you know precisely which shell config file was modified, you can source the file for the changes to take immediate effect.

For example:

 

source ~/.profile
To confirm that the $PATH is set correctly, you can run:

 

echo $PATH | tr ':' '\n' | grep -F .local
You should see /home/<your_user_name>/.local/bin listed in the output:

 Output
/home/<your_user_name>/.local/bin
Create a new folder and cd into it:

 

mkdir podman-tutorial && cd podman-tutorial
```
Create an .env file and define the following variables:
```
.env

DB_USER=<your_example_username>
DB_PASS=<your_example_password>
DB_NAME=<your_example_database>


Then, create a new docker-compose.yml file and paste the following contents:
```
docker-compose.yml

version: '3'

services:

  wordpress:
    image: wordpress
    container_name: wordpress
    restart: always
    ports:
      - '8080:80'
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: ${DB_USER}
      WORDPRESS_DB_PASSWORD: ${DB_PASS}
      WORDPRESS_DB_NAME: ${DB_NAME}
    volumes:
      - wordpress:/var/www/html

  db:
    image: mysql:5.7
    container_name: db
    restart: always
    ports:
      - '3306:3306'
    environment:
      MYSQL_DATABASE: ${DB_NAME}
      MYSQL_USER: ${DB_USER}
      MYSQL_PASSWORD: ${DB_PASS}
      MYSQL_RANDOM_ROOT_PASSWORD: '1'
    volumes:
      - db:/var/lib/mysql

volumes:
  wordpress:
  db:
```

Save the file, then run:

 

podman-compose up -d
Let's examine the output segment by segment.

Initially, podman-compose launches and starts analyzing the docker-compose.yml file:

 Output
podman-compose version: 1.0.6
['podman', '--version', '']
using podman version: 4.3.1
** excluding:  set()
['podman', 'ps', '--filter', 'label=io.podman.compose.project=podman-tutorial', '-a', '--format', '{{ index .Labels "io.podman.compose.config-hash"}}']
It detects two services named wordpress and db, and starts processing them in sequential order.

First, it finds out that the wordpress service requires an external volume. It tries to locate the volume by issuing podman volume inspect <volume_name>, but since it doesn't exist, it goes ahead and creates one by issuing podman volume create <volume_name>:

 Output
podman volume inspect podman-tutorial_wordpress || podman volume create podman-tutorial_wordpress
['podman', 'volume', 'inspect', 'podman-tutorial_wordpress']
Error: inspecting object: no such volume podman-tutorial_wordpress
['podman', 'volume', 'create', '--label', 'io.podman.compose.project=podman-tutorial', '--label', 'com.docker.compose.project=podman-tutorial', 'podman-tutorial_wordpress']
['podman', 'volume', 'inspect', 'podman-tutorial_wordpress']
Next, it checks whether there is a suitable network for deploying the wordpress service. It doesn't find one, so it creates it and then performs another check to confirm that the network exists:

 Output
['podman', 'network', 'exists', 'podman-tutorial_default']
['podman', 'network', 'create', '--label', 'io.podman.compose.project=podman-tutorial', '--label', 'com.docker.compose.project=podman-tutorial', 'podman-tutorial_default']
['podman', 'network', 'exists', 'podman-tutorial_default']
Finally, with a suitable network and an external volume in place, Podman Compose launches the wordpress container:

 Output
podman run --name=wordpress -d --label io.podman.compose.config-hash=c3e51c9a26e54848a06f92083413698bee90acd721b4aa3054280e110819a68c --label io.podman.compose.project=podman-tutorial --label io.podman.compose.version=1.0.6 --label PODMAN_SYSTEMD_UNIT=podman-compose@podman-tutorial.service --label com.docker.compose.project=podman-tutorial --label com.docker.compose.project.working_dir=/home/<your_user_name>/podman-tutorial --label com.docker.compose.project.config_files=docker-compose.yml --label com.docker.compose.container-number=1 --label com.docker.compose.service=wordpress -e WORDPRESS_DB_HOST=db -e WORDPRESS_DB_USER=testuser -e WORDPRESS_DB_PASSWORD=testpass -e WORDPRESS_DB_NAME=testdb -v podman-tutorial_wordpress:/var/www/html --net podman-tutorial_default --network-alias wordpress -p 8080:80 --restart always wordpress
Since Podman cannot find a wordpress image available locally, it goes ahead and looks up the unqualified search registry that you configured earlier (docker.io), then downloads it:

 Output
Resolving "wordpress" using unqualified-search registries (/home/<your_user_name>/.config/containers/registries.conf)
Trying to pull docker.io/library/wordpress:latest...
Getting image source signatures
Copying blob c5d33b602102 done
...
Copying config bc823df9ea done
Writing manifest to image destination
Storing signatures
980f5792fb9c34ea9357ffa290d5d79ac0b48b70701cd4693f5d7e2b4f2312f1
exit code: 0
Next, Podman Compose proceeds with processing the instructions for the db service.

First, it creates its external volume:

 Output
podman volume inspect podman-tutorial_db || podman volume create podman-tutorial_db
['podman', 'volume', 'inspect', 'podman-tutorial_db']
Error: inspecting object: no such volume podman-tutorial_db
['podman', 'volume', 'create', '--label', 'io.podman.compose.project=podman-tutorial', '--label', 'com.docker.compose.project=podman-tutorial', 'podman-tutorial_db']
['podman', 'volume', 'inspect', 'podman-tutorial_db']
It then ensures that there is a suitable network for its deployment:

 Output
['podman', 'network', 'exists', 'podman-tutorial_default']
Finally, it launches the db container:

 Output
podman run --name=db -d --label io.podman.compose.config-hash=c3e51c9a26e54848a06f92083413698bee90acd721b4aa3054280e110819a68c --label io.podman.compose.project=podman-tutorial --label io.podman.compose.version=1.0.6 --label PODMAN_SYSTEMD_UNIT=podman-compose@podman-tutorial.service --label com.docker.compose.project=podman-tutorial --label com.docker.compose.project.working_dir=/home/<your_user_name>/podman-tutorial --label com.docker.compose.project.config_files=docker-compose.yml --label com.docker.compose.container-number=1 --label com.docker.compose.service=db -e MYSQL_DATABASE=testdb -e MYSQL_USER=testuser -e MYSQL_PASSWORD=testpass -e MYSQL_RANDOM_ROOT_PASSWORD=1 -v podman-tutorial_db:/var/lib/mysql --net podman-tutorial_default --network-alias db --restart always mysql:5.7
Just like with the wordpress image, Podman cannot find a mysql:5.7 image locally, so it goes ahead and obtains it from Docker Hub:

 Output
Resolving "mysql" using unqualified-search registries (/home/<your_user_name>/.config/containers/registries.conf)
Trying to pull docker.io/library/mysql:5.7...
Getting image source signatures
Copying blob 62aca7179a54 done
...
Copying config bdba757bc9 done
Writing manifest to image destination
Storing signatures
21615c3d36236f181b94831b5c1eb699153f7cf912fdefcb342732069f99c09d
exit code: 0
At this point, Podman Compose exits successfully, and everything appears to be launched correctly. Let's go ahead and verify this.

First, try to open localhost:8080 in a browser. You should see the WordPress installation page:

Wordpress installation page
Now, go back to your terminal and type in:

 

podman container ps
Indeed, both the wordpress container and the db container are up and running:

 Output
CONTAINER ID  IMAGE                               COMMAND               CREATED        STATUS            PORTS                 NAMES
980f5792fb9c  docker.io/library/wordpress:latest  apache2-foregroun...  3 minutes ago  Up 3 minutes ago  0.0.0.0:8080->80/tcp  wordpress
21615c3d3623  docker.io/library/mysql:5.7         mysqld                2 minutes ago  Up 2 minutes ago                        db
You can also go ahead and explore the list of available images:

 

podman images
The list contains all the necessary images for running MySQL and WordPress:

 Output
REPOSITORY                   TAG         IMAGE ID      CREATED       SIZE
docker.io/library/wordpress  latest      bc823df9ead2  28 hours ago  683 MB
docker.io/library/mysql      5.7         bdba757bc933  4 weeks ago   520 MB
You can further explore the list of available networks:

 

podman network ls
Two networks show up:

 Output
NETWORK ID    NAME                     DRIVER
2f259bab93aa  podman                   bridge
3f5fa386b31c  podman-tutorial_default  bridge
The podman network is created by default when you install Podman for the first time. It is used for launching containers when no other network is explicitly specified. On the other hand, the podman-tutorial_default network is created by Podman Compose to isolate the containers defined in your docker-compose.yml from any other containers potentially running on the same system.

Finally, let's check the available volumes:

 

podman volume ls
As expected, two external volumes appear:

 Output
DRIVER      VOLUME NAME
local       podman-tutorial_db
local       podman-tutorial_wordpress
You can go ahead and stop the containers:

 

podman-compose down
Podman Compose stops and removes the containers from your system but keeps the network and volumes:

 Output
podman-compose version: 1.0.6
['podman', '--version', '']
using podman version: 4.3.1
** excluding:  set()
podman stop -t 10 db
db
exit code: 0
podman stop -t 10 wordpress
wordpress
exit code: 0
podman rm db
db
exit code: 0
podman rm wordpress
wordpress
exit code: 0
You can verify that no containers are running by typing:

 

podman container ps -a
The result shows an empty output, which confirms that all of the containers were stopped and removed.

 Output
CONTAINER ID  IMAGE       COMMAND     CREATED     STATUS      PORTS       NAMES
If you want to remove the volumes as well, you can type in:

 

podman volume rm podman-tutorial_db podman-tutorial_wordpress
To remove the network, type in:

 

podman network rm podman-tutorial_default
As you can see, the commands are identical to what you would normally use with Docker and Docker Compose. The only noticeable difference is that instead of docker and docker-compose, you type in podman and podman-compose.

Final thoughts
Podman is a capable containerization technology that offers a viable alternative to Docker for running container workloads. Whether you choose Podman or Docker depends entirely on your specific needs and preferences.

Podman can do most of the things that Docker can do, with the added benefit of not requiring a daemon running in the background. On top of that, Podman offers some features that Docker does not, such as working with Kubernetes manifest files and organizing individual containers into pods.

The final decision is yours. If you require a more lightweight and secure container management solution, Podman might be a better choice. However, Docker may be the way to go if you prioritize a robust ecosystem with extensive community support. Ultimately, both tools offer powerful containerization capabilities to meet your requirements.

To explore Podman further, consider visiting the official Podman website, exploring its documentation, and joining its growing community.

Thanks for reading!

Author's avatar
Article by
Marin Bezhanov

