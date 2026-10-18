https://gist.github.com/w00tc/486825a0b7c593789b1952878dd86ff5

##
##
##

thing.LDIF

 ``` 
  dn: ou=users,dc=response,dc=HTB
  changetype: add
  objectClass: organizationalPerson
  sn: test
  cn: test
  dn: uid=admin,ou=users,dc=response,dc=htb
  changetype: add
  objectClass: inetOrgPerson
  userPassword: passw@rd123
  sn: test
  cn: test 
```
  
  
LOGIN as ADMIN

```
ldapadd -x -D "cn=admin,dc=response,dc=HTB" -w
'password_you_set' -H ldap://127.0.0.1 -f thing.ldif
```
