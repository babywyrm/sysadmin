
Skip to content
All gists
Back to GitHub
Sign in
Sign up

Instantly share code, notes, and snippets.
@SalahHamza
SalahHamza/install_ngrok.md
Last active Jan 20, 2023

34

    5

Code
Revisions 5
Stars 34
Forks 5
How to install ngrok on linux subsystem for windows
install_ngrok.md
Ngrok
Overview

ngrok allows you to expose a web server running on your local machine to the internet.

Read more about ngrok in the official docs.
Installation

    Go to your root directory

cd

    download ngrok .zip file

wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip

if by any chance the url has been changed go to ngrok download page and copy the url of the linux .zip file.

    unzip the file

unzip ngrok-stable-linux-amd64.zip

in case you don't have unzip installed, you can do that like this

sudo apt install unzip

    if you pass in this command ./ngrok you'll see this output

NAME:
   ngrok - tunnel local ports to public URLs and inspect traffic

DESCRIPTION:
    ngrok exposes local networked services behinds NATs and firewalls to the
    public internet over a secure tunnel. Share local websites, build/test
    webhook consumers and self-host personal services.
    Detailed help for each command is available with 'ngrok help <command>'.
    Open http://localhost:4040 for ngrok's web interface to inspect traffic.

EXAMPLES:
    ngrok http 80                    # secure public URL for port 80 web server
    ngrok http -subdomain=baz 8080   # port 8080 available at baz.ngrok.io
    ngrok http foo.dev:80            # tunnel to host:port instead of localhost
    ngrok tcp 22                     # tunnel arbitrary TCP traffic to port 22
    ngrok tls -hostname=foo.com 443  # TLS traffic for foo.com to port 443
    ngrok start foo bar baz          # start tunnels from the configuration file

VERSION:
   2.2.8

AUTHOR:
  inconshreveable - <alan@ngrok.com>

COMMANDS:
   authtoken    save authtoken to configuration file
   credits      prints author and licensing information
   http         start an HTTP tunnel
   start        start tunnels by name from the configuration file
   tcp          start a TCP tunnel
   tls          start a TLS tunnel
   update       update ngrok to the latest version
   version      print the version string
   help         Shows a list of commands or help for one command

this means that ngrok is working well

    all you need to do is specify a port where your website is servered so that you expose it to the internet. Example

./ngrok http 8000

passing the above command will produce this output

ngrok by @inconshreveable
Session Expires               7 hours, 59 minutes
Version                       2.2.8
Region                        United States (us)
Web Interface                 http://127.0.0.1:4040
Forwarding                    http://********.ngrok.io -> localhost:8000
Forwarding                    https://*******.ngrok.io -> localhost:8000

Connections                   ttl     opn     rt1     rt5     p50     p90
                              0       0       0.00    0.00    0.00    0.00  

@carlosdnba
carlosdnba commented Aug 31, 2021

Nice! I've just found that here and it saved me some minutes
@PudparK
PudparK commented May 6, 2022

Thanks!
@Pythonian
Pythonian commented Aug 13, 2022

Thanks for this.

I also had to add my authtoken configuration before i was able to serve my django app:

./ngrok authtoken your-auth-token
@levelone
levelone commented Oct 7, 2022 •

works like a charm 👍

optional: you can run ngrok instead of ./ngrok by running command below:

$ sudo cp /.ngrok /usr/bin/ngrok

it copies the ngrok folder to the binary folder /usr/bin - in return you have access to ngrok without the need to determine the path each time you call; you can confirm this by running command below

$ which ngrok

@youssef33321
youssef33321 commented Nov 22, 2022

Thanks for a great and simple explanation
@Mikehoncho85
Mikehoncho85 commented Dec 7, 2022

I need your help like all the time...lol. this was quick and great dude thanks
@c7b
c7b commented Jan 20, 2023

Great comment; it helps me out. For me, following the instructions where

    https://ngrok.com/download
    Install ngrok via Apt
    curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list && sudo apt update && sudo apt install ngrok
    ngrok config add-authtoken <token>

to join this conversation on GitHub. Already have an account? Sign in to comment
Footer
© 2023 GitHub, Inc.
Footer navigation

    Terms
    Privacy
    Security
    Status
    Docs
    Contact GitHub
    Pricing
    API
    Training
    Blog
    About

