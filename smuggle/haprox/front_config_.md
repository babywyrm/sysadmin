##
#
https://gist.github.com/mhofman/a01df56480b3791d526b77dbebef43a2
#
##

# Web Service Fronting

## Multiple Web properties on a single IP address
Hosting multiple websites on a single public IP address on the standard HTTP(S) ports is relatively easy with popular web servers like Apache, Nginx and lighttpd all supporting Virtual Hosts.\
For Web Services which bundle their own HTTP server, things get more complicated, unless their HTTP stack can be shared somehow. More often than not, the application's HTTP stack listens directly on a dedicated TCP port.

Hosting multiple services on a single IP then requires using a fronting server listening on the standard HTTP port, and routing to the right backend service based on the host name or the path sent by the client.\
Path based routing is cumbersome, usually requiring either the service to be aware of the path prefix, or a rewrite by the HTTP fronting server of all absolute URLs in the requests and responses.\
Hostname based routing is more straightforward. The fronting server can just look at the [HTTP/1.1 Host header](https://tools.ietf.org/html/rfc7230#section-5.4) or [HTTP/2.0 :authority pseudo-header](https://tools.ietf.org/html/rfc7540#section-8.1.2.3) and forward the HTTP stream unmodified to the backend server.<sup id="a1">[1](#f1)</sup>

## TLS encryption
When adding TLS into the mix, things get even more interesting. There are 2 general approaches: terminate the TLS connection at the fronting server, or send the encrypted stream to the backend service.

Terminating the TLS connection requires the fronting server to possess the certificate and keying material for all the supported services' domains. The server can then potentially read and modify the HTTP stream to the backend service, which can be both valuable and a security concern. The connection to the backend service can be encrypted or not.

Sending the encrypted stream to the backend service is possible if the client sends a TLS SNI (Server Name Indication) extension<sup id="a2">[2](#f2)</sup>. The fronting server parses enough of the TLS Client Hello to read the content of the SNI and route to the appropriate backend, which will terminate the TLS connection.\
This method is the equivalent of HTTP host name routing. One difference is that the fronting server has no control over the data exchanged inside the encrypted connection, which could potentially be something other than HTTP.<sup id="a3">[3](#f3)</sup>

## Choice of proxy server
While the most popular production HTTP servers have Reverse Proxy functions that allow both host and path based routing of web services, they are pretty heavy weight solutions for the conceptually simple function that is routing a connection.\
Furthermore, while they support TLS, they all require terminating the encrypted connection with them.

HAProxy is often used for Load Balancing, but its flexibility and lightweightness makes it a perfect candidate for routing connections based on the host name, using either the HTTP Host header or the TLS SNI extension.

## Example HAProxy configs

### Basic HTTP

The following config will route the traffic to the service based on the Host header, and fall back to a default server if the the host name doesn't match (or isn't provided in the headers).\
Only the name portion of the Host header is matched (`_dom` suffix) and the port is ignored if present. The match is made ignoring the case (`-i`).\
Removing the default `server` (the one with a positive weight) will cause HAProxy to respond with a 503 error if the host name doesn't match.\
The services can run on a remote server, or on the localhost, just adjust the address as appropriate.

```
listen http-server
    bind :80
    mode http

    use-server app1 if hdr_dom(host) -i app1.example.com
    server app1 192.0.2.10:3000 weight 0

    use-server app2 if hdr_dom(host) -i app2.example.com
    server app2 192.0.2.20:8080 weight 0

    server default 192.0.2.30:80
```

### Load Balancing
If a service requires load-balancing, it's a better idea to declare a backend for each service.
```
frontend http-frontend
    bind :80
    mode http

    use_backend app1-cluster if hdr_dom(host) -i app1.example.com
    use_backend app2-cluster if hdr_dom(host) -i app2.example.com

    default_backend default-server

backend app1-cluster
    mode http

    server app1-1 192.0.2.10:3000
    server app1-2 192.0.2.11:3000

backend app2-cluster
    mode http

    server app2-1 192.0.2.20:8080
    server app2-2 192.0.2.21:8080

backend default-server
    mode http

    server default 192.0.2.30:80
```

### Basic TLS

The following config will sniff the SNI in the TLS Client Hello message, and redirect the TCP connection to the appropriate service. If the SNI isn't configured for redirection, or if no SNI is detected, it sends the connection to a default server.\
If HAProxy doesn't receive a TLS Client Hello message within 10 seconds, it closes the connection. Removing the default server would also cause HAProxy to close the connection if no match is found.\
The SNI match is case insensitive (`-i`).

```
listen https-server
    bind :443
    mode tcp

    tcp-request inspect-delay 10s
    tcp-request content accept if req.ssl_hello_type 1
    tcp-request content reject if WAIT_END

    use-server app1-tls if req.ssl_sni -i app1.example.com
    server app1-tls 192.0.2.10:3001 weight 0

    use-server app2-tls if req.ssl_sni -i app2.example.com
    server app2-tls 192.0.2.20:8443 weight 0

    server default 192.0.2.30:443
```

### Combining HTTP and TLS redirection

Instead of redirecting unhandled TLS connections to a default server, HAProxy can terminate the TLS connection itself by redirecting to the HAProxy `http-server` now also listening for TLS connections on a localhost port.\
This can be done if the backend service doesn't support TLS or if some connections needs to be inspected by the proxy.<sup id="a4">[4](#f4)</sup>

```
listen https-server
    bind :443
    mode tcp

    tcp-request inspect-delay 10s
    tcp-request content accept if req.ssl_hello_type 1
    tcp-request content reject if WAIT_END

    use-server app1-tls if req.ssl_sni -i app1.example.com
    server app1-tls 192.0.2.10:3001 weight 0

    server local 127.0.0.1:10443 send-proxy

listen http-server
    bind :80
    bind 127.0.0.1:10443 ssl crt fullcert.pem accept-proxy
    mode http

    acl app1-host hdr_dom(host) -i app1.example.com
    acl app2-host hdr_dom(host) -i app2.example.com

    use-server app1-tls if app1-host { ssl_fc }
    use-server app1 if app1-host
    server app1-tls 192.0.2.10:3001 ssl ca-file ca-certificates.crt sni req.hdr(host) weight 0
    server app1 192.0.2.10:3000 weight 0

    http-request set-header X-Forwarded-Proto https if app2-host { ssl_fc }
    use-server app2 if app2-host
    server app2 192.0.2.20:8080 weight 0

    use-server default-tls if { ssl_fc }
    server default-tls 192.0.2.30:443 ssl ca-file ca-certificates.crt sni req.hdr(host) weight 0
    server default 192.0.2.30:80
```

# Fronting transparently

## Who is the source?
No matter the solution used, fronting multiple services requires the TCP connection to be terminated by the fronting server and a separate TCP connection to be established between the fronting server and the backend service.\
That's the difference between a connection proxy and a network router, they operate at different layers.

It means that, to the backend service, the proxy server appears as the network source, which can be problematic.\
There are multiple solutions to this, and they roughly fall in 2 categories: communicate to the backend service who is the original source, or fake the source. Communicating the source can be done in-band, or out-of-band.

## HTTP Forwarded Header
In-band indication of the source requires the proxy server to modify the TCP stream. Commonly this is done by adding the [`Forwarded`](https://tools.ietf.org/html/rfc7239#section-4) (or [alternatives](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For)) HTTP header to requests sent to the backend service.

This problem is so common in the HTTP world that most services will have options to consume such headers and use them instead of the TCP connection info.

Most Web Servers supporting Reverse Proxy functions will also be able to add those headers.\
In the case of HAProxy, use the configuration parameter [`option forwardfor`](https://cbonte.github.io/haproxy-dconv/1.8/configuration.html#4-option%20forwardfor).

## PROXY Protocol
Out-of-band indication of the source basically transmits the source information to the backend service without modifying the forwarded application data stream. An example of this would be to wrap the data stream into some sort of relay protocol when the proxy server establishes a connection with the backend.\
HAproxy developed the [PROXY Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for this purpose. It basically prepends connection information when establishing a new connection with the backend. It can be enabled using the [`send-proxy` setting](https://cbonte.github.io/haproxy-dconv/1.8/configuration.html#send-proxy).


This requires the backend service to explicitly support and expect the additional information.\
In HAProxy, this means using the [`accept-proxy` option for the `bind` keyword](https://cbonte.github.io/haproxy-dconv/1.8/configuration.html#accept-proxy).

## Transparent proxy

If no modifications of the backend service are possible to support receiving the source information, the only solution is to fake the source when establishing a connection with the service. However when networking manipulations are involved, they usually requires greater access to the systems where the proxy and potentially backend services are running.

On the proxy server this is really a two-pronged approach. First the proxy server needs to send packets to the backend service by using the client's IP as the source. But it also needs to intercept response packets from the backend service destined to the client's IP and process them locally instead of forwarding them as-is, so that it can take the payload data and forward it back over the original connection.\
This also means that the backend service needs to route its response packets through the proxy, either because the proxy is the default route, or thanks to some creative network routing.

On Linux, binding a TCP socket with a source address (or destination if the socket is listening) that is not local to the system requires the [`IP_TRANSPARENT`](http://man7.org/linux/man-pages/man7/ip.7.html) option, which requires root privileges, or more specifically the `CAP_NET_ADMIN` capability<sup id="a5">[5](#f5)</sup>.\
Intercepting the return packets requires matching them and redirecting them to the local host. The match is done using the netfilter (iptables) capabilities of Linux, either by matching the source IP/port (assuming such traffic can be uniquely identified), or by using the [netfilter "socket" match](http://ipset.netfilter.org/iptables-extensions.man.html#lbCB) kernel module, which basically checks if a local socket exists with the same source/destination info as the incoming packet. Redirecting the return packet for local processing works by adding a mark to the matched packet, and setting up a routing rule to deliver the marked packets locally instead of forwarding them.

## HAProxy transparent support

HAProxy supports faking the source address by using the [`usrsrc` argument of the `source` keyword / option](https://cbonte.github.io/haproxy-dconv/1.8/configuration.html#4.2-source). The documentation and most posts will recommend using the `clientip` value for the source, but in most cases of service routing, the `client` value is perfectly fine<sup id="a6">[6](#f6)</sup>.

The HAProxy server configuration would look like the following. It works for both the TCP and HTTP modes.
```
    server app1-tls 192.0.2.10:3001 source * usesrc client weight 0
```

There are a lot of online examples on how to configure the system to match and redirect the return packets using the "socket" match module, such as:
```bash
# Allow the use of IP_TRANSPARENT to bind to non-local addresses
sysctl -w net.ipv4.ip_nonlocal_bind=1

# Mark incoming packets matching an existing local socket
iptables -t mangle -N DIVERT
iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
iptables -t mangle -A DIVERT -j MARK --set-mark 1
iptables -t mangle -A DIVERT -j ACCEPT

# Redirect all marked packets for local processing, i.e. to the open, transparent socket
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

# Creative IP routing for transparent proxying

## Backend and proxy on the same host
The commonly documented transparent proxying configs only work if the backend service and proxy are not on the same system.

Sending packets with a non-local source to a loopback address is not allowed, unless [`route_localnet`](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt) is enabled, which is a security issue if forged packets with a loopback address may arrive on a public interface.\
However, the routing restriction is only for the 127/8 address range, and nothing prevents us from assigning extra addresses to the loopback interface.

```bash
ip addr add 192.168.127.1/24 dev lo scope host
```

To match return packets, we would need to look at the `OUTPUT` chain instead of the `PREROUTING` chain. However since our traffic comes from the local host and can easily be identified by the source address, we can forgo the whole iptables socket match and mark based routing rules, and replace them with simple source based routing rules.

```bash
ip rule add from 192.168.127.0/24 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

The HAProxy `server` line can then be written to connect to the local service listening on this new address range.\
However care must be taken to use the loopback interface for the transparent connection, otherwise the packets will not be deliverable. This is done by using the new local address as the `source` instead of `*`.
```
    server app1-tls 192.168.127.40:5000 source 192.168.127.1 usesrc client weight 0
```

## Proxy isn't the default route

If the proxy server isn't the default route for the backend server, similar source routing tricks can be used on the backend server.

The idea is to add a new IP address or range to the backend server, either to an existing interface, or to a new pseudo-interface.\
Then source based routing rules from that new IP address or range can send traffic through the proxy server.

Of course the proxy server will also need routes for that new IP address/range now handled by the backend server. The proxy server could then more easily use source matching filters to mark return packets for redirect from the backend, instead of using the match socket netfilter module.

## IPv6 Support

With IPv6 it should not be necessary to use a connection proxy to front multiple services with different host names, as each service could have a dedicated public IPv6.<sup id="a7">[7](#f7)</sup>

In case a single public IPv6 must be shared, then it becomes a matter of duplicating the proxy configuration for both v4 and v6 connections.\
However, care must be taken to not mix the 2 connection types. Some Linux systems allow IPv6 sockets to accept IPv4 connections, where the IPv4 mapped address will be used in the IPv6 address fields. These addresses are [considered harmful](https://tools.ietf.org/html/draft-itojun-v6ops-v4mapped-harmful-02) and should never be used on the wire, which may happen in a transparent proxy configuration.

In HAproxy, we need to detect when the connection arrived through IPv4 and open a connection with the IPv4 address of the backend service.

```
listen server
    bind ipv4@:80
    bind ipv6@:80
    mode http

    acl v4src src 0.0.0.0/0
    acl invalidv4 src 0.0.0.0/8

    acl app1-host hdr_dom(host) -i app1.example.com
    acl app2-host hdr_dom(host) -i app2.example.com

    use-server app1-v4 if app1-host v4src !invalidv4
    use-server app1-v6 if app1-host
    server app1-v4 192.0.2.10:3000 source * usesrc client weight 0
    server app1-v6 2001:db8::10:3000 source * usesrc client weight 0

    use-server app2-v4 if app2-host v4src !invalidv4
    use-server app2-v6 if app2-host
    server app2-v4 192.0.2.20:8080 source * usesrc client weight 0
    server app2-v6 2001:db8::20:8080 source * usesrc client weight 0

    use-server default-v4 if v4src !invalidv4
    server default-v4 192.0.2.30:80 source * usesrc client weight 0
    server default-v6 2001:db8::30:80 source * usesrc client
```

### Handling connections from local sources

As explained in the [footnote](#f6) on the `usesrc client` option, connections from local sources don't work well with transparent sockets.\
One approach is to use a source ACL similar to the IPv6 handling to detect those connections and skip the transparent proxying. This works wether the backend service is remote or local.

```
listen server
    acl v4src src 0.0.0.0/0
    acl invalidv4 src 0.0.0.0/8
    acl localsrc src 127.0.0.0/8
    acl localsrc src ::1
    acl localsrc src_is_local

    use-server default-lo if localsrc
    use-server default-v4 if v4src !invalidv4

    server default-lo 2001:db8::30:80 weight 0
    server default-v4 192.0.2.30:80 source * usesrc client weight 0
    server default-v6 2001:db8::30:80 source * usesrc client
```

# Related reading

- [Abusing Linux's firewall: the hack that allowed us to build Spectrum](https://blog.cloudflare.com/how-we-built-spectrum/). CloudFlare blog post on how they leveraged TPROXY and assigning subnets to local interfaces to proxy TCP applications on any port.
- [SSH over SSL, episode 4: a HAproxy based configuration](https://blog.chmd.fr/ssh-over-ssl-episode-4-a-haproxy-based-configuration.html): Some information on how to detect and redirect SSH over a TCP port in HAProxy.

# Footnotes

- <sup id="f1">[1](#a1)</sup> Most services don't make an assumption on the host name under which they operate and either detect it from the headers, or allow it to be configured.
- <sup id="f2">[2](#a2)</sup> TLS Routing doesn't require SNI per se but any unencrypted TLS client message containing enough information to make a routing decision. ALPN could also be used for example.
- <sup id="f3">[3](#a3)</sup> When the content of an encrypted connection is HTTP, there can be a mismatch between the Host header and the SNI extension. This is how domain fronting works. When the TLS connection is terminated by the backend service and not the proxy, this would usually be checked there and not an issue.
- <sup id="f4">[4](#a4)</sup> If the TLS connection is terminated by the proxy, and forwarded to the backend service using an unencrypted HTTP connection, the backend should make sure not to act on the lack of encryption and redirect to HTTPS. A solution could be to add an HTTP header such as [`X-Forwarded-Proto`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Proto) indicating the connection was originally encrypted, or connect to the backend using TLS (e.g. self-signed certificate with verification disabled in the proxy server).\
There is also a risk of allowing domain fronting as explained [above](#f3).
- <sup id="f5">[5](#a5)</sup> While these capabilities are generally understood as being part of the [`TPROXY`](https://www.kernel.org/doc/Documentation/networking/tproxy.txt) feature of the kernel, the modules are not required to open a transparent socket. The `xt_socket` module is only needed if using the socket match netfilter capability. The `xt_tproxy` module itself isn't needed in our service fronting case.\
More information can be found in the [un-official TPROXY documentation](https://github.com/ahupowerdns/tproxydoc/blob/master/tproxy.md).
- <sup id="f6">[6](#a6)</sup> `usesrc client` binds to both the IP and port number of the original source when connecting to the backend service, instead of just the IP. It can be a problem in 2 cases: if the incoming client connection is intercepted transparently as well ([`transparent` keyword on the `bind` keyword](https://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.1-transparent)), or if the source is the proxy local host.\
For the former, both the connections between client and proxy, and proxy and backend service would have the same source/destination IP/port 4-tuple, and cause conflicts in the system's connection tracking.\
For the latter, the system would try to bind twice to the same local IP / TCP port, which isn't possible. If the proxy system can be the source of some connections, they can be [handled by a source ACL](#handling-connections-from-local-sources) (or by switching back to `usesrc clientip` for all connections with the backend).
- <sup id="f7">[7](#a7)</sup> With IPv6, a prefix is often advertised and a host can assign itself multiple IPv6 addresses in that prefix, which handles the case of multiple services on the same host.\
If the services are on remote hosts which don't have public IPv6 addresses (e.g. Prefix Delegation isn't possible), then you can create a [ULA based local IPv6 network](https://tools.ietf.org/html/rfc4193), and do some [NPTv6](https://tools.ietf.org/html/rfc6296) stateless translation of addresses on the "proxy" between the ULA backend network and the multiple public IPv6 addresses on the proxy server (assigned for example from using an [NDP Proxy](https://tools.ietf.org/html/rfc4389)). This is to say, the proxy server is as a network router for IPv6 services, and not a connection proxy.
