# Burp Extension: Copy As FFUF

![](images/demo.png)

## Description

`ffuf` ([https://github.com/ffuf/ffuf](https://github.com/ffuf/ffuf)) is gaining a lot of traction within the infosec community as a fast portable web fuzzer. It has been compared and aligned (kinda) to Burp's Intruder functionality. Thus, `Copy As FFUF` is trying to build that interoperatability bridge between the two.

## Features

- [X] Piping the copied request to a `request.http` file and build a skeleton `ffuf` command

## TODO

- [ ] Extend the functionality with additional right-click menu items, like:
    - [ ] Create a `Copy as FFUF` submenu
    - [ ] Copy request and use Burp proxy for verification `Copy as FFUF skeleton, verify via Burp"`
    - [ ] Copy request and use Burp proxy for the attack `Copy as FFUF skeleton, proxy via Burp"`

- [ ] Maybe add a simple UI allowing to configure a path to wordlists

## Requirements

- Python environment / Jython for Burp Suite

## Installation

- Check if jython standalone is present in `Extender -> Options -> Python Environment`
- Load the extention `Extender -> Extensions -> Add -> select path to CopyAsFFUF.py`

> Hopefully at some point PortSwigger with make it available in the bApp store

## Known Issue

TODO

## Author

- d3k4z

## Credits

- [burp-copy-requests-response](https://github.com/CompassSecurity/burp-copy-request-response)

##############
##
##
##

easy peezy
just set the wordlist and filters is all, but the rest is auto converted based on the headers
fuzz markers auto converted from the intruder tab as well
curl -k  'https://watch.streamio.htb/search.php' -X POST -d 'q=a'  -H 'Content-Type: application/x-www-formrlencoded'
feroxbuster -k -u https://watch.streamio.htb/search.php  -H 'Content-Type: application/x-www-form-urlencoded' -w ~/wordlists/raft-medium-words.txt
curl and ferox too
just need to trim the path for ferox if it doesnt end in /
<br>
<br>
##
##
##
