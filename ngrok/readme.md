
# SSL

## Intro

The plan is to create a pair of executables (`ngrok` and `ngrokd`) that are connected with a self-signed SSL cert. Since the client and server executables are paired, you won't be able to use any other `ngrok` to connect to this `ngrokd`, and vice versa.

## DNS

Add two DNS records: one for the base domain and one for the wildcard domain. For example, if your base domain is `domain.com`, you'll need a record for that and for `*.domain.com`.

## Different Operating Systems

If the OS on which you'll be compiling ngrok (that's the server section below) is different than the OS on which you'll be running the client, then you will need to set the GOOS and GOARCH env variables. I run Linux everywhere, so I don't know how to do that. Please Google it or [see the discussion here](https://github.com/inconshreveable/ngrok/issues/84). If you know how to do this and want to add GOOS/GOARCH instructions here, please let me know.

## On Server

MAKE SURE YOU SET `NGROK_DOMAIN` BELOW. Set it to the base domain, not the wildcard domain.

```
NGROK_DOMAIN="my.domain.com"
git clone https://github.com/inconshreveable/ngrok.git
cd ngrok

openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -subj "/CN=$NGROK_DOMAIN" -days 5000 -out rootCA.pem
openssl genrsa -out device.key 2048
openssl req -new -key device.key -subj "/CN=$NGROK_DOMAIN" -out device.csr
openssl x509 -req -in device.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out device.crt -days 5000

cp rootCA.pem assets/client/tls/ngrokroot.crt
# make clean
make release-server release-client
```

Copy `bin/ngrok` to whatever computer you want to connect from. Then start the server:

```
bin/ngrokd -tlsKey=device.key -tlsCrt=device.crt -domain="$NGROK_DOMAIN" -httpAddr=":8000" -httpsAddr=":8001"
```


## On Client

MAKE SURE YOU SET `NGROK_DOMAIN` BELOW. Set it to the base domain, not the wildcard domain.

```
NGROK_DOMAIN="my.domain.com"
echo -e "server_addr: $NGROK_DOMAIN:4443\ntrust_host_root_certs: false" > ngrok-config
./ngrok -config=ngrok-config 80
```

Or for SSH forwarding: `./ngrok -config=ngrok-config --proto=tcp 22`

##
##


# Expose Localhost to the Internet With Ngrok

If you want a way to access your localhost easily on the public internet,
lets say, to showcase the current work to a client, etc. This is where ngrok comes in. It allows us
to establish a tunnel that forwards a port on our machine and make it available on the internet.

[Ngrok](https://ngrok.com/) is a [Go](http://golang.org/) program, distributed as a single executable file for all major desktop platforms.
There are no additional frameworks to install or other dependencies.

This tutorial assumes you are using MAMP and have previously [set up DNSMASQ](https://gist.github.com/mgalloway/7121912#file-mamp_dynamic_virtual_hosts-md).

## Step 1: Install ngrok
```bash
$ cd /tmp
$ wget https://dl.ngrok.com/darwin_amd64/ngrok.zip
$ unzip ngrok.zip
$ chmod +x ngrok
$ cp ngrok /usr/local/bin
```

Check to make sure it's install properly

```bash
$ ngrok -help
```

## Step 2: Signup online
[Signup online](https://ngrok.com/) free to enable several different . Follow the instruction on the site
to register ngrok on your computer. You'll only need to register once.

## Step 3: Add Dynamic Virtual Hosts to your Apache configuration

Open up `/Applications/MAMP/conf/apache/httpd.conf` in a text editor, scroll down, and add `*.ngrok.com` to the following line to the file.

```
ServerAlias *.dev *.work *.xip.io *.ngrok.com
```

To make this all work, we need `ngrok` to serve the site correctly. Assuming we want to access `myapp.dev`, we will need to issue a command like this:

```bash
# access `myapp.dev` via: http://myapp.dev.ngrok.com
$ ngrok --subdomain=myapp.dev myapp.dev:80
```

## Step 4: Create shortcut to launch ngrok

Add the following `/user/<username>/.bashrc`

```bash
ngrok_tunnel() {
    website=$1
    subdomain=$2
    username=$3
    password=$4
    [ -n $website ] || (echo "I need a local website to tunnel to." && exit)
    [ -n $subdomain ] && subdomain="--subdomain=${subdomain}"
    if [[ -n $username  ]] && [[ -n $password ]]; then
        httpauth="-httpauth=${username}:${password}"
    else
        echo "Not using secure tunnel since auth params were not provided."
    fi
    ngrok $subdomain $httpauth $website
}
```

```bash
expose() { ngrok_tunnel $1:80 $1 $2 $3; }
```

Reload bashrc

```bash
$ . ~/.bashrc
```

Now, to serve up the site, e.g. `myapp.dev`, we can simply run:

```bash
$ expose myapp.dev
```

Additionally, we can enable HTTP Basic Authentication while serving up a local site, by simply passing two more parameters for username and password, like this:

```bash
$ expose myapp username password
```

Now, when we visit `http://myapp.dev.ngrok.com`, we will be greeted with a HTTP Basic Authentication before we are allowed accessed to our local site.

### Additional Information
<http://nikhgupta.com/workflow/making-ngrok-work-with-pow-and-apache-exposing-localhost-domains-to-the-internet/><br>
<http://adrianartiles.com/webhook-testing-and-exposing-localhost-to-the-internet-with-ngrok><br>
<https://ngrok.com/><br>
<https://ngrok.com/dashboard><br>
