package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

func main() {
	var mu sync.Mutex
	remoteAddrs := make(map[string]int)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Custom DNS resolver
				r := net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						return net.Dial("udp", "8.8.8.8:53") // Using Google's DNS server
					},
				}
				addrs, err := r.LookupHost(ctx, addr)
				if err != nil {
					return nil, err
				}
				if len(addrs) == 0 {
					return nil, &net.DNSError{Err: "no addresses found", Name: addr}
				}
				conn, err := net.Dial(network, addrs[0]+":80")
				if err != nil {
					return nil, err
				}
				mu.Lock()
				remoteAddr := conn.RemoteAddr().String()
				remoteAddrs[remoteAddr]++
				mu.Unlock()
				return conn, nil
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	numRequests := 100
	wg.Add(numRequests)
	for i := 0; i < numRequests; i++ {
		go func(i int) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.bbc.co.uk/", nil)
			if err != nil {
				log.Printf("Request #%02d failed to create: %v", i, err)
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("Request #%02d failed: %v", i, err)
				return
			}
			defer resp.Body.Close()
			log.Printf("Request #%02d succeeded: %s", i, resp.Request.URL.String())
		}(i)
	}
	wg.Wait()

	log.Printf("%20s | %s", "Address", "Count")
	mu.Lock()
	for addr, count := range remoteAddrs {
		log.Printf("%20s | %03d", addr, count)
	}
	mu.Unlock()
}


//
//
// Custom DNS Resolver: We use Google's public DNS (8.8.8.8) for resolving hostnames.
// Concurrency: Requests are handled concurrently with goroutines and sync.WaitGroup.
// Context Management: We use context to handle timeouts and ensure graceful shutdown.
// Improved Logging and Error Handling: Added logging for request success and failure, along with the final count of unique remote addresses.
