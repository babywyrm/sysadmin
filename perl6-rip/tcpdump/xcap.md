
##
#
https://github.com/nlitsme/xpcapperl
#
##


xpcapperl
Tool for creating a more readable hexdump output from tcpdump.

No attempt is made to resolve retransmits.

Example Usage:
```
stream data as ascii, use tcpdump parsing of DNS, DHCP packets
tcpdump -xnr my.cap | perl xpcap -a -t

09:52:21.348048 UDP 10.101.1.117.53476 > 10.101.0.1.53                    63429+ A? captive.apple.com. (35)
09:52:21.376464 UDP 10.101.1.117.53476 < 10.101.0.1.53                    63429 3/8/8 CNAME captive.apple.com.edgekey.net., CNAME e7279.dsce9.akamaiedge.net., A 23.40.251.17 (435)
09:52:21.376873 TCP 10.101.1.117.56278 > 23.40.251.17.80      S[9cc14af1] 
09:52:21.377876 TCP 10.101.1.117.56278 < 23.40.251.17.80      S[0e95a7ff] 
09:52:21.377926 TCP 10.101.1.117.56278 > 23.40.251.17.80       [9cc14af2] 
09:52:21.378469 TCP 10.101.1.117.56278 > 23.40.251.17.80      [9cc14af2] 
   | GET /hotspot-detect.html HTTP/1.0
   | Host: captive.apple.com
   | Connection: close
   | User-Agent: CaptiveNetworkSupport-324 wispr
   | 

09:52:21.382066 TCP 10.101.1.117.56278 < 23.40.251.17.80       [0e95a800] 
09:52:21.423186 TCP 10.101.1.117.56278 < 23.40.251.17.80      [0e95a800] 
   | HTTP/1.0 200 OK
   | Content-Type: text/html
   | Content-Length: 68
   | Date: Wed, 18 Nov 2015 08:52:22 GMT
   | X-Cache: MISS from IMP-cache
   | X-Cache-Lookup: MISS from IMP-cache:3128
   | Via: 1.0 IMP-cache (squid/3.1.20)
   | Connection: close
   | 
   | <HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>
or like this:

stream data as hex, use tcpdump parsing of DNS, DHCP packets
tcpdump -xnr my.cap | perl xpcap -t

09:52:21.348048 UDP 10.101.1.117.53476 > 10.101.0.1.53                    63429+ A? captive.apple.com. (35)
09:52:21.376464 UDP 10.101.1.117.53476 < 10.101.0.1.53                    63429 3/8/8 CNAME captive.apple.com.edgekey.net., CNAME e7279.dsce9.akamaiedge.net., A 23.40.251.17 (435)
09:52:21.376873 TCP 10.101.1.117.56278 > 23.40.251.17.80      S[9cc14af1] 
09:52:21.377876 TCP 10.101.1.117.56278 < 23.40.251.17.80      S[0e95a7ff] 
09:52:21.377926 TCP 10.101.1.117.56278 > 23.40.251.17.80       [9cc14af2] 
09:52:21.378469 TCP 10.101.1.117.56278 > 23.40.251.17.80       [9cc14af2] 474554202f686f7473706f742d6465746563742e68746d6c20485454502f312e300d0a486f73743a20636170746976652e6170706c652e636f6d0d0a436f6e6e656374696f6e3a20636c6f73650d0a557365722d4167656e743a20436170746976654e6574776f726b537570706f72742d3332342077697370720d0a0d0a
09:52:21.382066 TCP 10.101.1.117.56278 < 23.40.251.17.80       [0e95a800] 
09:52:21.423186 TCP 10.101.1.117.56278 < 23.40.251.17.80       [0e95a800] 485454502f312e3020323030204f4b0d0a436f6e74656e742d547970653a20746578742f68746d6c0d0a436f6e74656e742d4c656e6774683a2036380d0a446174653a205765642c203138204e6f7620323031352030383a35323a323220474d540d0a582d43616368653a204d4953532066726f6d20494d502d63616368650d0a582d43616368652d4c6f6f6b75703a204d4953532066726f6d20494d502d63616368653a333132380d0a5669613a20312e3020494d502d6361636865202873717569642f332e312e3230290d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a3c48544d4c3e3c484541443e3c5449544c453e537563636573733c2f5449544c453e3c2f484541443e3c424f44593e537563636573733c2f424f44593e3c2f48544d4c3e
09:52:21.423190 TCP 10.101.1.117.56278 < 23.40.251.17.80      F[0e95a927] 
09:52:21.423290 TCP 10.101.1.117.56278 > 23.40.251.17.80       [9cc14b70] 
09:52:21.423291 TCP 10.101.1.117.56278 > 23.40.251.17.80       [9cc14b70] 
09:52:21.423640 TCP 10.101.1.117.56278 > 23.40.251.17.80      F[9cc14b70] 
09:52:21.424598 TCP 10.101.1.117.56278 < 23.40.251.17.80       [0e95a928]
```


$|=1;

my $ascii;           # -aa : no hex, print byte count
my $usetcpdump;
my $gzip;
my $noempty;
my $filterports;
my $verbose;
my $savedir;

my %ctcp;
my %cudp;

```
