// https://gist.github.com/Integralist/8a9cb8924f75ae42487fd877b03360e2
//
//

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"syscall"
	"time"
)

func main() {
	client := &http.Client{
		Timeout: time.Second * 5,
		Transport: &http.Transport{
			// Avoid: "x509: certificate signed by unknown authority"
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			// Inspect the network connection type
			DialContext: (&net.Dialer{
				Control: func(network, address string, c syscall.RawConn) error {
					// Reference: https://golang.org/pkg/net/#Dial
					if network == "tcp4" {
						return errors.New("we don't want you to use IPv4")
					}
					return nil
				},
			}).DialContext,
		},
	}

	req, err := http.NewRequest("GET", "https://ipv4.lookup.test-ipv6.com/", nil)
	if err != nil {
		log.Fatal(err)
	}

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", string(b))
}
custom dns resolver.go
package main

import (
  "context"
  "io/ioutil"
  "log"
  "net"
  "net/http"
  "time"
)

func main() {
  var (
    dnsResolverIP        = "8.8.8.8:53" // Google DNS resolver.
    dnsResolverProto     = "udp"        // Protocol to use for the DNS resolver
    dnsResolverTimeoutMs = 5000         // Timeout (ms) for the DNS resolver (optional)
  )

  dialer := &net.Dialer{
    Resolver: &net.Resolver{
      PreferGo: true,
      Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
        d := net.Dialer{
          Timeout: time.Duration(dnsResolverTimeoutMs) * time.Millisecond,
        }
        return d.DialContext(ctx, dnsResolverProto, dnsResolverIP)
      },
    },
  }

  dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
    return dialer.DialContext(ctx, network, addr)
  }

  http.DefaultTransport.(*http.Transport).DialContext = dialContext
  httpClient := &http.Client{}

  // Testing the new HTTP client with the custom DNS resolver.
  resp, err := httpClient.Get("https://www.google.com")
  if err != nil {
    log.Fatalln(err)
  }
  defer resp.Body.Close()

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    log.Fatalln(err)
  }

  log.Println(string(body))
}
force IPv4 connection type (standard library implementation).go
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

func main() {
	client := &http.Client{
		Timeout: time.Second * 5,
		Transport: &http.Transport{
			// Avoid: "x509: certificate signed by unknown authority"
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp4", addr)
			},
		},
	}

	// Fastly's DNS system controls whether we will report IPv6 addresses for a
	// given hostname, and in the case of developer.fastly.com it CNAMEs to the
	// Fastly map devhub.fastly.net which is configured to opt-in or out of v6
	// support at the map level. The devhub map has dual-stack enabled on it.
	// Therefore, it will announce v6 addresses for it if a client sends AAAA DNS
	// queries for the hostname.
	req, err := http.NewRequest("GET", "https://developer.fastly.com/api/internal/cli-config", nil)
	if err != nil {
		log.Fatal(err)
	}

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", string(b))
}
force IPv4 connection type (uses third-party dependency).go
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func main() {
	client := &http.Client{
		Timeout: time.Second * 5,
		Transport: &http.Transport{
			// Avoid: "x509: certificate signed by unknown authority"
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				ipv4, err := resolveIPv4(addr)
				if err != nil {
					return nil, err
				}
				timeout, err := time.ParseDuration("10s")
				if err != nil {
					return nil, err
				}
				return (&net.Dialer{
					Timeout: timeout,
				}).DialContext(ctx, network, ipv4)
			},
		},
	}

	// Also try: https://v4.testmyipv6.com/
	req, err := http.NewRequest("GET", "https://ipv4.lookup.test-ipv6.com/", nil)
	if err != nil {
		log.Fatal(err)
	}

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", string(b))
}

// resolveIPv4 resolves an address to IPv4 address.
func resolveIPv4(addr string) (string, error) {
	url := strings.Split(addr, ":")

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(url[0]), dns.TypeA)
	m.RecursionDesired = true

    // NOTE: you shouldn't consult or rely on /etc/resolv.conf as it has proven historically to contain nameservers that don't respond.
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)
	r, _, err := c.Exchange(m, net.JoinHostPort(config.Servers[0], config.Port))
	if err != nil {
		return "", err
	}
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			url[0] = a.A.String()
		}
	}

	return strings.Join(url, ":"), nil
}
skip DNS resolution and just pass an IP.go
// This enables you to utilise a package such as https://github.com/miekg/dns to resolve the hostname.

package main

import (
  "context"
  "io/ioutil"
  "log"
  "net"
  "net/http"
  "time"
)
func main() {
  dialer := &net.Dialer{
    Timeout:   30 * time.Second,
    KeepAlive: 30 * time.Second,
  }

  http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
    if addr == "google.com:443" {
      addr = "216.58.198.206:443"
    }
    return dialer.DialContext(ctx, network, addr)
  }

  resp, err := http.Get("https://www.google.com")
  if err != nil {
    log.Fatalln(err)
  }
  defer resp.Body.Close()

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    log.Fatalln(err)
  }

  log.Println(string(body))
}
@thepabloaguilar
thepabloaguilar commented on Jan 30
Hey @Integralist, great gist! In some cases we can have more than one DNS server, I'd like to know if in that case the code below is right (multiples DNS servers forcing IPV4 resolution):

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func main() {
	client := &http.Client{
		Timeout: time.Second * 5,
		Transport: &http.Transport{
			// Avoid: "x509: certificate signed by unknown authority"
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				ipv4, err := resolveIPv4(addr)
				if err != nil {
					return nil, err
				}
				timeout, err := time.ParseDuration("10s")
				if err != nil {
					return nil, err
				}
				return (&net.Dialer{
					Timeout: timeout,
				}).DialContext(ctx, network, ipv4)
			},
		},
	}

	// Also try: https://v4.testmyipv6.com/
	req, err := http.NewRequest("GET", "https://ipv4.lookup.test-ipv6.com/", nil)
	if err != nil {
		log.Fatal(err)
	}

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", string(b))
}

// resolveIPv4 resolves an address to IPv4 address.
func resolveIPv4(addr string) (string, error) {
	url := strings.Split(addr, ":")

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
	}
	m.SetQuestion(dns.Fqdn(url[0]), dns.TypeA)

	// NOTE: you shouldn't consult or rely on /etc/resolv.conf as it has proven historically to contain nameservers that don't respond.
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)

	var err error
	for _, server := range config.Servers {
		r, _, innerErr := c.Exchange(m, net.JoinHostPort(server, config.Port))
		if innerErr != nil {
			err = innerErr
			continue
		}

		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				url[0] = a.A.String()
			}
		}

		return strings.Join(url, ":"), nil
	}

	return "", err
}
