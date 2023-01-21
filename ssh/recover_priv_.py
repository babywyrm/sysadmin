#!/usr/bin/python3

##
##
## With n and q values obtained, the p value can be calculated using p = n/q. This may exceed the limit of some OS, so, you can use an online big number calculator to achieve the purpose, eg: https://www.calculator.net/big-number-calculator.html. Then rest of the job is just doing some math, which can be done using the script below.
## https://meowmeowattack.github.io/case-study/openssh-private-key-recovery/
##

n = ...
q = ...
p = ...
e = 0x010001
phi = (p -1)*(q-1)


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
 
def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m
 
d = modinv(e,phi)
dp = modinv(e,(p-1))
dq = modinv(e,(q-1))
qi = modinv(q,p)


import pyasn1.codec.der.encoder
import pyasn1.type.univ
import base64


def pempriv(n, e, d, p, q, dP, dQ, qInv):
    template = '-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----\n'
    seq = pyasn1.type.univ.Sequence()
    for i,x in enumerate((0, n, e, d, p, q, dP, dQ, qInv)):
        seq.setComponentByPosition(i, pyasn1.type.univ.Integer(x))
    der = pyasn1.codec.der.encoder.encode(seq)
    return template.format(base64.encodebytes(der).decode('ascii'))


key = pempriv(n,e,d,p,q,dp,dq,qi)
f = open("recovered.key","w")
f.write(key)
f.close()

################
##
