// https://medium.com/@yanzay/implementing-simple-netcat-using-go-bbab37507635
//
//

package main

import (
  "flag"
  "fmt"
  "io"
  "log"
  "net"
  "os"
)

var (
  listen = flag.Bool("l", false, "Listen")
  host   = flag.String("h", "localhost", "Host")
  port   = flag.Int("p", 0, "Port")
)

func main() {
  flag.Parse()
  if *listen {
    startServer()
    return
  }
  if len(flag.Args()) < 2 {
    fmt.Println("Hostname and port required")
    return
  }
  serverHost := flag.Arg(0)
  serverPort := flag.Arg(1)
  startClient(fmt.Sprintf("%s:%s", serverHost, serverPort))
}

func startServer() {
  addr := fmt.Sprintf("%s:%d", *host, *port)
  listener, err := net.Listen("tcp", addr)

  if err != nil {
    panic(err)
  }

  log.Printf("Listening for connections on %s", listener.Addr().String())

  for {
    conn, err := listener.Accept()
    if err != nil {
      log.Printf("Error accepting connection from client: %s", err)
    } else {
      go processClient(conn)
    }
  }
}

func processClient(conn net.Conn) {
  _, err := io.Copy(os.Stdout, conn)
  if err != nil {
    fmt.Println(err)
  }
  conn.Close()
}

func startClient(addr string) {
  conn, err := net.Dial("tcp", addr)
  if err != nil {
    fmt.Printf("Can't connect to server: %s\n", err)
    return
  }
  _, err = io.Copy(conn, os.Stdin)
  if err != nil {
    fmt.Printf("Connection error: %s\n", err)
  }
}

//
//
