// cmd/challenge-router/main.go
package main

import (
  "log"
  "net/http"
  "net/http/httputil"
  "net/url"
  "strings"
)

func main() {
  handler := &httputil.ReverseProxy{
    Director: func(req *http.Request) {
      // URL: /challenge/<id>/path...
      parts := strings.SplitN(req.URL.Path, "/", 4)
      if len(parts) < 3 {
        http.Error(req.Response, "bad path", http.StatusBadRequest)
        return
      }
      id := parts[2]
      // rebuild path = /<remaining>
      var rest string
      if len(parts) == 4 {
        rest = "/" + parts[3]
      } else {
        rest = "/"
      }
      // target service FQDN
      target := &url.URL{
        Scheme: "http",
        Host:   id + ".project-x-challenges.svc.cluster.local:8080",
        Path:   rest,
      }
      req.URL = target
      req.Host = target.Host
    },
  }

  log.Println("Challenge router listening :3000")
  http.ListenAndServe(":3000", handler)
}
//
//
