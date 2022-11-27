##
## https://0xdf.gitlab.io/2022/02/12/htb-earlyaccess.html
##
##

I’ll need the CSRF token from the page first. Looking at the HTML, it’s right at the top of the page: 

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="csrf-token" content="T6yVOQaAZySV8jYfsrtb2Cd5N5cn6JBbsPF7FyO0">

I’ll start a session, and grab that token, using BeautifulSoup to pull it out:

s = requests.session()
s.proxies.update({'https':'http://127.0.0.1:8080'})
url = 'https://earlyaccess.htb'

# Get CSRF for login
resp = s.get(f'{url}/login', verify=False)
soup = BeautifulSoup(resp.text, 'html.parser')
csrf = soup.find_all('meta', {"name":"csrf-token"})[0]['content']

That token let’s me login:

# Login
resp = s.post(f'{url}/login', verify=False,
        data={"_token": csrf, "email": "0xdf@earlyaccess.htb", "password": "0xdf0xdf"})

Because I’m using a session object from requests, the cookies that come back are stored and sent out in additional requests, keeping me logged in.

Next I can do the same to get the CSRF from the /key page:

# Get CSRF for key POST
resp = s.get(f'{url}/key', verify=False)
soup = BeautifulSoup(resp.text, 'html.parser')
csrf = soup.find_all('meta', {"name":"csrf-token"})[0]['content']

I noticed in Burp that the CSRF didn’t change for successive POSTs to /key/add, so I just need to get this once.

Finally, I’ll try submitted keys one by one until that error message isn’t in the response:

# Try keys until success
for mn in g3s:
    key = f'{g1}-{g2}-{g3s[mn]}-{g4}-'
    cs = calc_cs(key)
    key = f'{key}{cs}'
    resp = s.post(f'{url}/key/add', verify=False,
            data={"_token": csrf, "key": key})
    if not "Game-key is invalid!" in resp.text:
        print(f"[+] Success with magic number {mn}")
        break
        
        
#######################
##
##        
