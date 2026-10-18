package main

//
//

import (
    "context"
    "flag"
    "fmt"
    "log"
    "os"

    "thrift-client/log_service"
    "github.com/apache/thrift/lib/go/thrift"
)

func main() {
    // Parse command-line argument for the log file path
    filePath := flag.String("file", "", "Path to the log file")
    flag.Parse()

    if *filePath == "" {
        log.Fatalln("Error: Log file path must be provided with -file argument")
    }

    // Set up transport for Thrift communication
    transport, err := thrift.NewTSocket("localhost:9090")
    if err != nil {
        log.Fatalf("Error creating socket: %v", err)
    }
    defer transport.Close()

    // Set up protocol and transport factories
    protocolFactory := thrift.NewTBinaryProtocolFactoryDefault()
    transportFactory := thrift.NewTTransportFactory()

    useTransport, err := transportFactory.GetTransport(transport)
    if err != nil {
        log.Fatalf("Error getting transport: %v", err)
    }

    // Open transport connection
    if err := transport.Open(); err != nil {
        log.Fatalf("Error opening transport: %v", err)
    }

    // Create the LogService client
    client := log_service.NewLogServiceClientFactory(useTransport, protocolFactory)

    // Make the RPC call to ReadLogFile with the provided log file path
    result, err := client.ReadLogFile(context.Background(), *filePath)
    if err != nil {
        fmt.Printf("Error calling ReadLogFile: %v\n", err)
        os.Exit(1)
    }

    // Output the result of the log file processing
    fmt.Println("Result:", result)
}
