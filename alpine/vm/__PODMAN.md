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


