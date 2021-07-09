package main

import (
    "fmt"
    "os"
    "net/http"
)

func hostnameHandler(w http.ResponseWriter, r *http.Request) {
    myhostname, _ := os.Hostname()
    fmt.Fprintln(w, "Hostname:", myhostname)
}

func main() {
    const port string = "8000"
    fmt.Println("Server listening on port", port)
    http.HandleFunc("/", hostnameHandler)
    http.ListenAndServe(":" + port, nil)
}
