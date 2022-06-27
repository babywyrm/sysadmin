##
##

https://minnmyatsoe.com/2016/01/26/using-tshark-to-decrypt-ssl-tls-packets/

##
##

    About
    Posts

Using tshark to Decrypt SSL/TLS Packets

I’m going to walk you through the process of decoding SSL/TLS traffic from a pcap file with the server’s private key using tshark (command-line version of Wireshark). You can, of course, always use ssldump for the same purpose.

I assume you know how SSL/TLS works, and basic understanding of how Wireshark works, and why we use it.

I will start with getting a sample encrypted traffic that includes the handshake part (important for decryption later). For that purpose, we are going to use openssl command to generate a pair of server certificate and key. And then run the HTTPS server with openssl’s s_server command on port 4443 (or any other port you may like) using the generated certificate and key. Then we will issue a GET request to HTTPS server via curl. In the mean time, we will collect the traffic with tshark and will save the data into ssltest.pcap file.

# [1] create RSA cert and key pair
openssl req -new -x509 -out server.crt -nodes -keyout server.pem -subj /CN=localhost

# [2] run the server using the above
openssl s_server -www -cipher AES256-SHA -key server.pem -cert server.crt -accept 4443

# [3] from another console session, start capturing the traffic, on loopback interface
# (you will need to change lo0 to the relevant interface on your system.
tshark -s0 -w ssltest.pcap -i lo0

# [4] generate traffic from another console
curl -vk https://localhost:4443

# [5] Ctrl+C on the tshark command at [3], and stop the openssl server at [2]

At this point, we should have the file called ssltest.pcap from tshark, and server.crt/server.pem from openssl commands.

Next, we are going to read the pcap file and decode the traffic.

# [1] it shows the encrypted traffic
tshark -r ssltest.pcap

# [2] for details of the packets
tshark -r ssltest.pcap -V

# [3] for decrypted data; ssl.keys_list points to the RSA key
# added -x for hex dump
# At the output you should see the message in packet detail:
#  >>> Decrypted SSL record (16 bytes):
# And the decrypted data:
# >>> Hypertext Transfer Protocol
# >>>    GET / HTTP/1.1\r\n
tshark -r ssltest.pcap -V -x -o "ssl.debug_file:ssldebug.log" -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE" -o "ssl.keys_list:127.0.0.1,4443,http,server.pem"

# [4] inspecting ssldebug.log output from [3]
# You should see the following messeage near the top of the file:
#   >>> ssl_init private key file server.pem successfully loaded.
cat ssldebug.log

In Wireshark GUI, we can follow “SSL stream” that will dump the ASCII output from the stream. How are we going to do it with tshark?

# We add -z to show the statistics with option 'follow,ssl,ascii,1'
# to follow ssl stream number 1
# -q to suppress packet dumps
tshark -r sslsample.pcap -q -o "ssl.keys_list:127.0.0.1,4443,http,server.pem" -z "follow,ssl,ascii,1"

You will see the output similar to below:

===================================================================
Follow: ssl,ascii
Filter: tcp.stream eq 1
Node 0: 127.0.0.1:55041
Node 1: 127.0.0.1:4443
78
GET / HTTP/1.1
Host: localhost:4443
User-Agent: curl/7.43.0
Accept: */*


	1802
HTTP/1.0 200 ok
Content-type: text/html


&lt;_pre>

s_server -www -cipher AES256-SHA -key server.pem -cert server.crt -accept 4443
Ciphers supported in s_server binary
TLSv1/SSLv3:AES256-SHA
---
Ciphers common between both SSL end points:
ECDHE-ECDSA-AES256-SHA     ECDHE-ECDSA-AES128-SHA     ECDHE-ECDSA-DES-CBC3-SHA
ECDHE-RSA-AES256-SHA       ECDHE-RSA-AES128-SHA       ECDHE-RSA-DES-CBC3-SHA
ECDH-ECDSA-AES256-SHA      ECDH-ECDSA-AES128-SHA      ECDH-ECDSA-DES-CBC3-SHA
ECDH-RSA-AES256-SHA        ECDH-RSA-AES128-SHA        ECDH-RSA-DES-CBC3-SHA
DHE-RSA-AES256-SHA         DHE-RSA-AES128-SHA         EDH-RSA-DES-CBC3-SHA
AES256-SHA                 AES128-SHA                 DES-CBC3-SHA
ECDHE-ECDSA-RC4-SHA        ECDHE-RSA-RC4-SHA          ECDH-ECDSA-RC4-SHA
ECDH-RSA-RC4-SHA           RC4-SHA                    RC4-MD5
---
New, TLSv1/SSLv3, Cipher is AES256-SHA
SSL-Session:
    Protocol  : TLSv1
    Cipher    : AES256-SHA
    Session-ID: B9AE3B24559606A2723F987F21E9C202EDB19366098286083F3BDCDABE45B300
    Session-ID-ctx: 01000000
    Master-Key: 98DC04D8CD7AE943A08BE013CD4C7D0608950BC201B953BC12755EC9B4804D453148173B00043EF6A01CAC43F7B0005C
    Key-Arg   : None
    Start Time: 1453795701
    Timeout   : 300 (sec)
    Verify return code: 0 (ok)
---
   2 items in the session cache
   0 client connects (SSL_connect())
   0 client renegotiates (SSL_connect())
   0 client connects that finished
   2 server accepts (SSL_accept())
   0 server renegotiates (SSL_accept())
   2 server accepts that finished
   0 session cache hits
   0 session cache misses
   0 session cache timeouts
   0 callback cache hits
   0 cache full overflows (128 allowed)
---
no client certificate available


===================================================================

ssltlstshark

3e487da @ 2020-12-16
