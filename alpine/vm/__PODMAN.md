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

