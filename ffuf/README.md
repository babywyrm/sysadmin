
![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat) <a href="https://twitter.com/tamimhasan404">
    <img src="https://img.shields.io/badge/author-@tamimhasan404-orange.svg?style=square&logo=twitter">
  </a>

# FFUF-Tips-And-Tricks

![maxresdefault](https://user-images.githubusercontent.com/66991901/106985150-167bd600-6793-11eb-95ab-dfb5774192f0.jpg)


```
#!/bin/sh
#tomnomnom juicy files https://gist.github.com/tomnomnom/57af04c3422aac8c6f04451a4c1daa51
# ffuf tool https://github.com/ffuf/ffuf
# put the ffuf bin at /usr/local/bin and give the juicy.sh permission to execute with chmod +x juicy.sh and copy to 
# /usr/local/bin too.. after that.. execute juicy.sh at any terminal.
# usage bash juicy.sh filename.txt

filename="$1"
while read -r line; do
    name="$line"
    ffuf -w /home/$USER/tools/wordlist/common-paths-tom.txt -u "$name/FUZZ"
done < "$filename"
```

### So what is ffuf?

Ffuf(fuzz faster u fool) is a great tool used for fuzzing. It has become really popular lately with bug bounty hunters/penetration tester. It is written in Go language.For this you can fuzz a large amount of words within a minute.

### Before using ffuf tool just see this image once

![Screen-Shot-2017-02-26-at-6 54 41-AM](https://user-images.githubusercontent.com/66991901/106984127-2eeaf100-6791-11eb-8d98-da088f374a53.png)

## wordlist:

Option name: -w

Use wordlist on ffuf for more affectively fuzzing. I use SecLists-master for example. You can choose yours. I have my own for dir brute forcing you can find it on https://github.com/tamimhasan404/wordlist.git

```
./ffuf -w /root/Desktop/SecLists-master/Discovery/Web-Content/raft-large-directories.txt -u https://xyz.com/FUZZ
```

/root/Desktop/SecLists-master/Discovery/Web-Content/raft-large-directories.txt this is just a path where is the wordlist is situated.

## Fuff with all domain

This is a common problem for beginners that they don’t know how to use fuff in all of their collected subdomains as fuff has no default option for list of domains like dirsearch. So here is something for you that I personally use

```
for url in $(cat targets.txt); do ffuf -ac -fc 404,403 -w wordlist.txt -u $url/FUZZ >> results.txt; done && sort -u results.txt | grep -E '^https?://' > results.txt
```

* You can also see check https://twitter.com/0xJin tweet.

```
cat live.txt | xargs -I@ sh -c 'ffuf -w wordlists.txt -u @/FUZZ -mc 200'
```

## Filtering:


Option name: -fc

If you don’t want to see any kind of specific status code then you can just filter them.

```
./ffuf -w /root/Desktop/SecLists-master/Discovery/Web-Content/raft-large-directories.txt -u https://xyz.com/FUZZ -fc 401,403,404
```
Comma-separated list of codes and ranges


## Recursion:

Option name: -recursion

With this option, it tries to find all possible dir accordingly your given wordlist. Let me explain if ffuf find /index.php dir then it fuzz it again with /index.php/wordlist. 
Suppose it finds/index.php/configtest.php then it fuzz it again like this /index.php/configtest.php/wordlist.

```
./ffuf -w /root/Desktop/SecLists-master/Discovery/Web-Content/raft-large-directories.txt -u https://xyz.com/FUZZ -recursion
```

## Recursion-Depth:

Option name: -recursion-depth

By default recursion depth level is 0.with this you set how many specific numbers of dir it find for you. Like 2,3 or 4 etc.

```
./ffuf -w /root/Desktop/SecLists-master/Discovery/Web-Content/raft-large-directories.txt -u https://xyz.com/FUZZ -recursion-depth 2
```
Here you see I set recursion-depth 2. Now ffuf find 2 dir basis of my wordlist if these dir are available on the targeted website then stop.


## Extention:

Option name: -e

```
./ffuf -w /root/Desktop/SecLists-master/Discovery/Web-Content/raft-large-directories.txt -u https://xyz.com/FUZZ -e .html,.php,.txt,.pdf
```
Sometimes it gives you valuable information. Which is maybe goldmine on your penetration testing/bug hunting.For this, you have to choose extension base on your target.


## Silent:

Option name: -s

If you just print the result and don’t see any kind of fuzzing process on your terminal then use silent option.

```
./ffuf -w /root/Desktop/SecLists-master/Discovery/Web-Content/raft-large-directories.txt -u https://xyz.com/FUZZ -s
```

## Output:

Choose one -of json, ejson, html, md, csv

I generally use | tee for result output. But if you want to get output on GUI(graphical user interface) for your better understand/client demand then your CM is.

```
./ffuf -w /root/Desktop/SecLists-master/Discovery/Web-Content/raft-large-directories.txt -u https://xyz.com/FUZZ -of html -o ffuf-result
```

## Subdomain Enumeration

```
./ffuf -w /root/Desktop/wordlist.txt -u http://FUZZ.ab.com -of html -o result
```
Remember use http:// protocol after "-u" because sometimes many subdomains do not run over https.

## Automatically calibrate filtering

Option name: -ac

So this is a very useful thing, while Directory Bruteforce sometimes we see a lot of same length status code like 403,401 etc that means the output isn’t that much useful as they treat all of our directory bruteforce wordlists at the same length. This is problematic when you have a big wordlist and the same length 403 repats 20000 or 30000 times(think about your messy output) So what should you do? should you use -fc option in your command for filtering 403 then you may miss some sensitive directory.
In this time -ac options comes into the picture. This option automatically removes the same length dir and gives you a nice and clean output.

```
./ffuf -w /root/Desktop/wordlist.txt -u http://FUZZ.ab.com -ac
```

## Throttle(Last one but an important one)

Option name: -rate 2 (set your number 2,3 etc)

This is very useful because with this you throttle/delay your request. As you know ffuf is very fast tool with that a large number of wordlist makes much noise on the server which may cause to block your IP,Dos,Slow down the server etc. To avoid this you can use -rate and your CM is.

```
./ffuf -w /root/Desktop/SecLists-master/Discovery/Web-Content/raft-large-directories.txt -u https://xyz.com/FUZZ -rate 2
```
rate 2 means two requests per second. You can also customize the number.



- Here are some other useful options on ffuf:

timeout → HTTP request timeout in seconds (default: 10)

-V → Show version information (default: false/off)

-t → Number of concurrent threads(default: 40)

-v → Verbose/details output,printing full URL and redirect location (if any) with the results (default:false/off)

-mc → Match HTTP status codes, or "all" for everything (default: 200,204,301,302,307,401,403)

mode → Multi-wordlist operation mode.Available modes: clusterbomb, pitchfork (default: clusterbomb(1 to 1,2 to 2)

Thank you💕 

### To dig deep

https://www.youtube.com/watch?v=wGX3HwCTpKE

https://youtu.be/sC1I5VsuXSk  --> My video explain in bengali Language

https://youtu.be/aN3Nayvd7FU     
                                  
https://youtu.be/iLFkxAmwXF0
                                 
https://youtu.be/IjHrwKAmGn8     



##
##


#############################################
#############################################

 2099  ffuf -c -request request.txt -request-proto http -mode clusterbomb -w users.txt:HFUZZ -w rockyou-50.txt:WFUZZ -v
 
 2101  ffuf -c -request request.txt -request-proto http -mode clusterbomb -w users.txt:HFUZZ -w rockyou-50.txt:WFUZZ -fc 401 -v

 2106  ffuf -c -request request.txt -request-proto http -mode clusterbomb -w users.txt:HFUZZ -w rockyou-50.txt:WFUZZ -fc 401 -v
 
 2107  ffuf -c -request request.txt -request-proto http -mode clusterbomb -w users.txt:HFUZZ -w rockyou-50.txt:WFUZZ -mc 200
 
 2108  ffuf -c -request request.txt -request-proto http -mode clusterbomb -w users.txt:HFUZZ -w rockyou-50.txt:WFUZZ -mc 200,301,302
 
 2109  ffuf -c -request request.txt -request-proto http -mode clusterbomb -w users.txt:HFUZZ -w rockyou-50.txt:WFUZZ -mc 200,301,302,300

 2113  ffuf -c -request request.txt -request-proto http -mode clusterbomb -w users.txt:HFUZZ -w rockyou-50.txt:WFUZZ -mc 200,301,302,300


#############################################
#############################################


ffuf -w  .../raft-small-words-lowercase.txt -H "Content-Type: application/json"
-H "Cookie: XSRF-TOKEN=eyJpdiI6IkJ....IjoiIn0%3D; thing_session=eyJpdiI6InFvQjNHM...In0%3D"
-H "X-XSRF-TOKEN: eyJpdiI6IkJtdjBoZ....idGFnIjoiIn0="
-X POST  -u http://yo.yo/things/grabs
-d '{"FUZZ": "value"}' -mc all -fr "Missing arguments" -c -v


ffuf -w  .../raft-small-words-lowercase.txt -H "Content-Type: application/json"
-H "Cookie: XSRF-TOKEN=eyJpdiI6IkJt....n0%3D; thing___session=eyJpdiI6.....GFnIjoiIn0%3D"
-H "X-XSRF-TOKEN: eyJpdiI6IkJ.......oiIn0="
-X POST  -u http://things.things/endpoint/endpoint/again
-d '{"key_here": "FUZZ"}' -mc all -fr "Unknown tablename" -c -v


ffuf -w raft-small-words-lowercase.txt -H "Content-Type: application/json" -H "Cookie: XSRF-TOKEN=eyJpdiI6IkVlS0ljdHRvNHIzamVKL3NaNmYyOXc9PSIsInZhbHVlIjoiM2JGNG5kQnVOU1lDMW5na2NxRy9VWTFkU092TDAvR2NyV3N4cDJJdEwxdVAyMkwzWGhLTGJiWVdNN3VTR3F0Z0hLeC94WUhEOEE2cE41Qm92VXphOVU2MVNHUSsvVkJKVmhvVzA4UEhJUmxZWkhORDh3bjB2dUNub3E0NytwZVUiLCJtYWMiOiI3Yjk2NWI1MGZmMGQ5NTBiMTUxN2IzOTRiZTI4YjA3ZTA1NDI3MDUwZWFhODUxYmI3MDBmNWU2NDZiNzNiYmE2IiwidGFnIjoiIn0%3D; thething_session=eyJpdiI6IllZWEF5YmFJM1dOc2RuQmttNlFmMUE9PSIsInZhbHVlIjoiTjlaRGI2UmdKMWthczNJSHdPY1VINjVUSWQxV2gxVVlTK1F2VDNKd0JGUVdSUmZUWjA3ZGRaMVpMQVFYcUlkVzhuY3BVMUFBY2R1alFZUFRmcHcxRTdBdWlMK2xkdVdRa1dsVWpKSFN1czN2ZnRsVjBMV1dXblgvWjJWK2hVb3ciLCJtYWMiOiI4MWQ2NDQyZTJlMDVmMWQ3NWNlMmJkM2ZiNmRmZDkzMmU0NjI0Mjk4NDkzZGJmY2Q0NjAxZGEwOGZiMTA5OTgyIiwidGFnIjoiIn0%3D" -H "X-XSRF-TOKEN: eyJpdiI6IkVlS0ljdHRvNHIzamVKL3NaNmYyOXc9PSIsInZhbHVlIjoiM2JGNG5kQnVOU1lDMW5na2NxRy9VWTFkU092TDAvR2NyV3N4cDJJdEwxdVAyMkwzWGhLTGJiWVdNN3VTR3F0Z0hLeC94WUhEOEE2cE41Qm92VXphOVU2MVNHUSsvVkJKVmhvVzA4UEhJUmxZWkhORDh3bjB2dUNub3E0NytwZVUiLCJtYWMiOiI3Yjk2NWI1MGZmMGQ5NTBiMTUxN2IzOTRiZTI4YjA3ZTA1NDI3MDUwZWFhODUxYmI3MDBmNWU2NDZiNzNiYmE2IiwidGFnIjoiIn0=" -X POST -u http://nope.yet/target/endpoint -d '{"FUZZ": "value"}' -mc all -fr "Missing arguments" -c -v


#############################################
#############################################



       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://interface/login
 :: Wordlist         : HFUZZ: DONE
 :: Wordlist         : WFUZZ: /usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt
 :: Header           : Accept: application/json, text/plain, */*
 :: Header           : Accept-Encoding: gzip, deflate
 :: Header           : Origin: http://interface
 :: Header           : Referer: http://interface/
 :: Header           : Host: interface
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Content-Type: application/json
 :: Header           : Connection: close
 :: Data             : {"username":"HFUZZ","password":"WFUZZ"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,301,302
________________________________________________

[Status: 200, Size: 2, Words: 1, Lines: 1, Duration: 104ms]
| URL | http://interface/logintho
    * HFUZZ: XXX
    * WFUZZ: XXX


#############################################
#############################################


ffuf -c -request request.txt -request-proto http -mode clusterbomb -w DONE:HFUZZ -w /usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt:WFUZZ -mc 200,301,302 -v

<br>

POST /login HTTP/1.1<br>
Host: interface<br>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0<br>
Accept: application/json, text/plain, */*<br>
Accept-Language: en-US,en;q=0.5<br>
Accept-Encoding: gzip, deflate<br>
Content-Type: application/json<br>
Content-Length: 47<br>
Origin: http://as;dfklna;sdflkasdfe<br>
Connection: close<br>
Referer: http://a;sldfnaskdf;nalskdfnafd<br>
<br>
{"username":"HFUZZ","password":"WFUZZ"}
<br>


#############################################
#############################################
<br>

ffuf -u http://pikaboo.htb/admin../admin_staging/index.php?page=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -t 200 -c -fs 15349

ffuf -u http://pikaboo.htb/admin../FUZZ -w /usr/share/wordlists/dirb/big.txt -t 200

ffuf -u http://10.10.10.249//admin../FUZZ/ -w /usr/share/wordlists/dirb/big.txt


#############################################
#############################################

ffuf -c -u FUZZ1 -H "FUZZ2: FUZZ3" -w alive_uber.txt:FUZZ1 -w headers.txt:FUZZ2 -w blind_xss.txt:FUZZ3 -x http://192.168.196.1:8082 -mode clusterbomb -v 


ffuf -c -u HOST/?PROT=https://webhook.site/f4494fd5-bd02-4fd2-893d-22368ac954b8/HOST/PROT -w alive_uber.txt:HOST -w ssrf_params:PROT -x http://192.168.196.1:8082 -mode clusterbomb -r -v 


ffuf -c -u HOST/?url=http://{my-server-ip}/DOMAIN/url&file=http://{my-server-ip}/DOMAIN/file -w hosts.txt:HOST -w domains.txt:DOMAIN -mode pitchfork -v 

####################################
####################################

# Basic Usage
ffuf -w wordlist.txt -u http://127.0.0.1:8000/api/FUZZ/6 -o output.txt -replay-proxy http://127.0.0.1:8080

# Basic Usage With a Cookie
ffuf -w wordlist.txt -u http://127.0.0.1:8000/api/FUZZ/6 -o output.txt -replay-proxy http://127.0.0.1:8080 -b "laravel_session=eyJpdiI6Ii8wQU11dTVlUkg2alRHUXBIVzlGSnc9PSIsInZhbHVlIjoiOWs3YllJWTdqNC9xa1pMeFRvMFh0OE1vRFpaWm9GSzFkRktVZS9yUHBDM0lIazZ4K0NsbndxWVIxQ05VZWhqZUZaR0RGQWlFdmdDc24yWllYRklGSXI5STd2b05Pam4yRXIwV1BUWkZhUnFLNUFzOWsycmRHcnlxS0FqRWNsSnEiLCJtYWMiOiI3ZTliMmM2YzIxOTExNDE0NmVjYTYyMGI4Nzg4YzJiYjNmNjVkNDI1YzEyODYwMzY5YzczNzY3NTUwZDk0OGYzIn0%3D;"

# Adding a delay
ffuf -w wordlist.txt -u http://127.0.0.1:8000/api/FUZZ/6 -o output.txt -replay-proxy http://127.0.0.1:8080 –p 1 –t 3

# Adding a delay (new method)
ffuf -w wordlist.txt -u http://127.0.0.1:8000/api/FUZZ/6 -o output.txt -replay-proxy http://127.0.0.1:8080 –rate 100

# Fuzzing 2 values
ffuf -w wordlist.txt:FUZZ -w actions-lowercase.txt:ME -u http://127.0.0.1:8000/api/FUZZ/ME -o output.txt -replay-proxy http://127.0.0.1:8080 

# Simple Filter
ffuf -w wordlist.txt:FUZZ -w actions-lowercase.txt:ME -u http://127.0.0.1:8000/api/FUZZ/ME -o output.txt -replay-proxy http://127.0.0.1:8080 -fw 1

# Simple Matcher
ffuf -w wordlist.txt:FUZZ -w actions-lowercase.txt:ME -u http://127.0.0.1:8000/api/FUZZ/ME -o output.txt -replay-proxy http://127.0.0.1:8080 -mc 302

# Custom Filters
ffuf -w wordlist.txt:FUZZ -w numbers.txt:ME -u http://127.0.0.1:8000/api/FUZZ/ME -o output.txt -replay-proxy http://127.0.0.1:8080 -fr "not found"

# Fuzzing Post Data
ffuf -w wordlist.txt -X POST -d "email=df%40fd.com&issue=dsafd&information=FUZZ" -u http://127.0.0.1:8000/vulnerability -replay-proxy http://127.0.0.1:8080

# Fuzzing Parameters (POST)
ffuf -w wordlist.txt -X POST -d "email=df%40fd.com&issue=dsafd&FUZZ=test" -u http://127.0.0.1:8000/vulnerability -replay-proxy http://127.0.0.1:8080

# Fuzzing Parameters (GET)
ffuf -w wordlist.txt -u http://127.0.0.1:8000/contact/submit?FUZZ=d%40d.com&issue=df -o output.txt -replay-proxy http://127.0.0.1:8080 

# Fuzzing JSON Post Data
ffuf -w wordlist.txt -X "PUT" -u http://127.0.0.1:8000/api/users/6 -H "Content-Type: application/json" -d "{'FUZZ':'test'}" -o output.txt -replay-proxy http://127.0.0.1:8080


###########################
###########################


(1) Basic command used to brute force website

ffuf -w <path-wordlist> -u https://test-url/FUZZ
(2) To fuzz parameters

ffuf -w <path-wordlist> -u https://test-url?id=FUZZ
(3) To fuzz headers

ffuf -w <path-wordlist> -u https://test-url -H "X-Header: FUZZ"
(4) To fuzz URL with POST method

ffuf -w <path-wordlist> -u https://test-url -X POST -d "var=FUZZ"
(5) To fuzz vhost list

ffuf -w <path-vhosts> -u https://test-url -H "Host: FUZZ"
(6) To find subdomains without DNS records

ffuf -w <path-wordlist> -u https://test-url/ -H "Host: FUZZ.site.com"
(7) To filter based on status code

ffuf -w <path-wordlist> -u https://test-url/FUZZ -fc 404,400
(8) To filter based on amount of words

ffuf -w <path-wordlist> -u https://test-url/FUZZ -fw <amount-of-words>
(9) To filter based on amount of lines

ffuf -w <path-wordlist> -u https://test-url/FUZZ -fl <amount-of-lines>
(10) To filter based on size of response

ffuf -w <path-wordlist> -u https://test-url/FUZZ -fs <size-of-response>
(11) To filter based on amount of words

ffuf -w <path-wordlist> -u https://test-url/FUZZ -fr <regex-pattern>
(12) To control rate of sending packets

ffuf -w <path-wordlist> -u https://test-url/FUZZ -rate <rate-of-sending-packets>
(13) To run scan for specific time or less than specific time (in seconds)

ffuf -w <path-wordlist> -u https://test-url/FUZZ -maxtime 60
(14) To fuzz substring

ffuf -w <path-wordlist> -u https://test-url/testFUZZ
(15) To limit maximum time (in seconds) per job.

ffuf -w <path-wordlist> -u https://test-url/FUZZ -maxtime-job 60
(16) File discovery with specific extensions

ffuf -w <path-wordlist> -u http://test-url/FUZZ -e .aspx,.php,.txt,.html
(17) To sent POST request with fuzz data

ffuf -w <path-wordlist> -X POST -d “username=admin\&password=FUZZ” -u http://test-url/FUZZ
(18) To FUZZ specific format file after directory

ffuf -w <path-wordlist> -u http://test-url/FUZZ/backup.zip
(19) Recursion is used to perform the same task again

 ffuf -u https://test-url/FUZZ -w <path-wordlist> -recursion
(20) Scan each domain with Wordlist1

ffuf -u https://codingo.io/Wordlist1 -w <path-wordlist>:Wordlist1
(21) Scan multiple domains with Wordlist1

ffuf -u https://Wordlist2/Wordlist1 -w <path-wordlist>:Wordlist1 <domain-list>:Wordlist2
(22) To introduce delay (in seconds) by using -p

ffuf -u http://test-url/FUZZ/ -w <path-wordlist> -p 1
(23) To speed or slow scan by using -t (default is 40)

ffuf -u http://test-url/FUZZ/ -w <path-wordlist> -t 1000
(24) To save output by using -o and for format -of

ffuf -u https://test-url/FUZZ/ -w <path-wordlist> -o output.html -of html
(25) To run scan in silent mode

ffuf -u https://test-url/FUZZ -w <path-wordlist> -s
 
 
######################
##########################

 
Install from Source
If you wish to install the latest stable build from the main branch of the ffuf project, you can do so with:

go get github.com/ffuf/ffuf
After installing, ffuf will be available in ~/go/bin/ffuf.

Upgrading from Source
Much like compiling from source, upgrading from source is not much more complicated, with the only change being the addition of the -u flag. Upgrading from source should be done with:

go get -u github.com/ffuf/ffuf  
Kali Linux APT Repositories
If you’re using Kali Linux you’ll find FFUF in the apt repositories, allowing you to install by running sudo apt-get install ffuf, this will present an output similar to the following:

FFUF

After installation, you can verify the version installed by using:

ffuf -V
If you also installed from source you’ll note that the version you’re operating is not the same as the version in your $GOPATH (~/go/bin). APT builds are normally older, but considered more stable builds of applications however can be less feature rich because of this.

Other Locations - Debian Unstable / SNAP, etc’
As it becomes more widely used, more ways to install FFUF are becoming available. FFUF currently flows into Debian Unstable, in addition to some flavours of Ubuntu who use those source. It’s also available in the Fedora official repositories, and a SNAP integration is currently underway as well.

Basic Usage
What is Directory Brute Forcing?
At its core, one of the main functions that people use FFUF for, is directory brute forcing. With that in mind, let’s fuzz! Without passing custom values (covered later in this course), FFUF will replace the value of FUZZ with the value of your wordlist.

What is a Wordlist?
What’s a wordlist? A wordlist is essentially a list of items in a text file, seperated by lines, that are tailor built around a purpose.

One of the best collections of wordlists, is SecLists. Curated by g0tm1lk, jhaddix and Daniel Miessler this collection has a wordlist for every occasion.

FFUF

What is SecLists?
SecLists is managed on Github, so anyone can contribute to these lists and with such an active and well known repository, this leads to a flurry of beneficial contributions. To date, over 100 people have contributed to SecLists, with no sign of it slowing. As you further build in your Security knowledge, if you’ve made the most of SecLists I recommend aiming to give back, through a contribution, or by supporting Daniel, the project owner, through Github Sponsers, here: https://github.com/sponsors/danielmiessler.

What Wordlists should I start with?
If you’re getting started in security, and you’re unsure where to start with wordlists, a good/safe collection of lists are the discovery wordlists in SecLists, specifically:

https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/directory-list-2.3-small.txt
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/directory-list-2.3-medium.txt
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/directory-list-2.3-big.txt
As you progress in your journey, be sure to revisit this and look into tooling and workflow changes that allow you to both use more tailored wordlists for the asset that you’re approaching, as well as build custom wordlists around a target as you wish to get more information from it.

Your first Directory Brute Force
For this example, let’s create a simple wordlist. In this case, we’ll put the following items into it:

test
test1
admin
panel
Save this in the same location where you intend to run FFUF from, as wordlist.txt.

For this example, we’ll also brute force against this website, codingo.io. FFUF takes two basic arguments that we need to use here, the first, -u is the target URL (in this case, codingo.io). The second, is -w, which is the path to the wordlist file(s) that we wish to make use of. You can specify multiple wordlists in a comma delimited list, if you so require. We also need to put the word FUZZ where we want our wordlist items to be placed. In this case, we’re aiming to brute force for new directories, so we put this after the URL.

Putting this altogether, the command for our first directory brute force will be:

ffuf -u https://codingo.io/FUZZ -w ./wordlist.txt
When we run this, we should receive similar to the following:

FFUF

Note that from our three results, one has come back with a result. In this case, it’s come back with a 301 response code, which indicates a redirect is present here. As none of the other endpoints responded with this, instead opting for a 404 page not found response (which we don’t have set to match and display), we should investigate this. Doing so, shows the following:

FFUF

Congratulations! You’ve just brute forced a website and discovered your first endpoint that isn’t present from the main page itself.

Recursion
Recursion is essentially performing the same task again, but in this context, at another layer. For example, in our item above, we identified an admin panel, but what if we want to scan further under that? One method, could be to scan again, but by changing our URL and fuzzing endpoint to the following:

ffuf -u https://codingo.io/admin/FUZZ -w ./wordlist.txt
Now whilst this will acheive our goal, it doesn’t scale well. When bug hunting, we may find 20, 30, or even 100 directories, all which we want to explore at another level.

Enter, recursion. By setting the flag recursion we tell FFUF to take our scan, and apply another layer to it. A second flag, recursion-depth tells FFUF how many times to perform this action (for example, if we find another layer under admin, shoud we proceed to another layer or stop?). There are some caveats, however. In FFUF you can’t use customer fuzzing keywords with recursion, and you’re limited to the use of FFUF. Whilst this won’t matter for the vast array of applications it will limit usage when using pitchfork scanning modes, which we’ll cover later. This isn’t a significant issue, however, and just something to take a mental note of for future reference.

When we run this command again, but with the recursion flag, we can see the following:

ffuf -u https://codingo.io/FUZZ -w ./wordlist -recursion
FFUF

In this case, both items “admin” and a subpage under that “panel” were discovered.

Extensions
Often when you find a directorty you’re also going to want to look for file extensions of that. This can be invaluable for finding bugs when there’s a zip file, or backup file of the same name.

Extensions in FFUF are specified with the e parameter and are essentially suffixs to your wordlist (as not all extensions start with a .). For example, expanding upon our original scan with the following:

ffuf -u https://codingo.io/FUZZ -w ./wordlist -recursion -e .bak
This now presents new hits! As shown below:

FFUF

Fuzzing Multiple Locations
By default, FFUF will only look for a single location to fuzz, donate by the term FUZZ. Reviewing our original example, this was the approach taken to FUZZ the directory name:

ffuf -u https://codingo.io/FUZZ -w ./wordlist.txt
But what if we want to fuzz multiple locations? This can be acomplished by comining the ability to define what a fuzz location would be with a wordlist, as well as using multiple wordlists.

For example, in the following we’re using the term W1 to fuzz our location, instead of FUZZ:

ffuf -u https://codingo.io/W1 -w ./wordlist.txt:W1
This runs the same scan as our previous example, except W1 is now our insert instead of FUZZ. Now, let’s assume that instead of codingo.io we had identified multiple websites we wanted to check over at the same time. For that, we could create a wordlist of all of the domains we wanted to test, and use the following:

ffuf -u https://W2/W1 -w ./wordlist.txt:W1,./domains.txt:W2
This would scan each of the domains in our domains.txt files using the wordlist from wordlist.txt, allowing us to run at scale without needing the use of outside scripting or applications.

The order of the wordlists control in what order the requests are sent. In clusterbomb mode (default) ffuf will iterate over the entire first wordlist before moving on to the second item in the second wordlist.

Why does this matter you wonder? Let me give you an example:

Lets say we have a wordlist with 1000 domains domains.txt and a wordlist with 1000 directories wordlist.txt.

If we run:

ffuf -u https://FUZZDOMAIN/FUZZDIR -w ./wordlist.txt:FUZZDIR,./domains.txt:FUZZDOMAIN
ffuf will try every directory for the first domain, then every directory on the second domain. When running with many threads, this means sending 1000 requests to the same server in a very short amount of time. This often leads to getting rate-limited or banned.

If we on the other hand swap the order of the wordlists and run:

ffuf -u https://FUZZDOMAIN/FUZZDIR -w ./domains.txt:FUZZDOMAIN,./wordlist.txt:FUZZDIR 
ffuf will try the first directory on all domains, before moving on to the next directory and trying that on all domains. This way you can send more requests without overloading the target servers.

Wordlist Parameter Bug
In older versions of FFUF there is a bug here whereby the w flag needs to be made use of multiple times for this to work as intended. If you receive the error:

Encountered error(s): 1 errors occurred.
* Keyword W1, defined, but not found in headers, method, URL or POST data.
Then you should instead either upgrade FFUF to the latest version, or use the w flag multiple times, like so:

ffuf -u https://W2/W1 -w ./wordlist.txt:W1 -w ./domains.txt:W2
More information can be found here: https://github.com/ffuf/ffuf/issues/290

Handling Authentication
Cookie Based Authentication
Often when performing a scan you will want to brute force behind an authentication point. In order to do this, FFUF provides the b flag for you to pas cookie data. These aren’t limited to authentication based cookies, and any area of the cookie (from names to values) can also be fuzzed with a wordlist for additional discovery.

Header Based Authentication
If authentication for the application is via HTTP header-based authentication then the H flag should be used. As with the b flag, this can be used to pass or fuzz any headers, and not just for passing required elements for authentication.

In addition to authentication, or fuzzing points, the H flag can also be utilised in situations where you’re required to “call your shot” by specifying a custom header for a client, or Bug Bounty engagement, so the defensive teams of those organisations can identify your traffic.

More Complex Authentication Flows
Occasionally, you’ll come accross authentication flows or fuzzing situations Burp Suite can’t provide. In those cases, I suggest creating an additional interface in Burp Suite and making use of Burp Suite Macros to acomplish this. Instructions for doing so can be found further on within this guide.

Threads
By default FFUF will use 40 threads to execute. Essentially, this means that FFUF will start 40 seperate processes to execute the commands that you’ve provided. It may be tempting to set this much higher, but this will be limited by the power of your system, and the destination system you’re scanning against. If you’re in a network environment, such as HackTheBox, or OSCP then setting this higher may not pose much of an issue. If, however, you’re working on a production system over the internet then you are likely better off spending time tailoring the flags you’re passing to FFUF, and keeping your thread count lower, than trying to acheive a quicker result merely with raw thread count. Various flags you can use to better tailor your requests can be found further throughout this guide.

Using Silent Mode for Passing Results
By default FFUF will strip colour from results (unless you enable it with the -c flag). This makes results easy to pass to other application, for additional work. One challenge here, is the header information, essentially:


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : https://codingo.io/FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________
and the footer:

:: Progress: [3/3] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:10] :: Errors: 0 ::
To remove this, and only show results that line up with the matcher filters, you can use the silent flag, -s. This flag will enforce only successful hits to be shown. For example, our command from earlier, if exapnded with -s becomes:

ffuf -u https://codingo.io/FUZZ -w ./wordlist.txt -s
Which will then only show the result:

admin
As that responds with a 301 request, which is within our matcher filters.

Error Handling and Scan Tweaks
Automatically Calibrate Filtering
The ac flag in FFUF can be used to automatically calibrate filtering of requests. This flag tells FFUF to send a number of preflight checks before brute forcing begins and to quantify common elements of those requests for further filtering. For example, FFUF may send random strings, and if each of those responses were a 200 response code, with a common content length, then that content length would be automatically filtered from future results.

Custom Automatic Calibration Filtering
In addition to the ac flag, FFUF allows you to provide the seed request to build autocalibration against, instead of using pre-flight checks. A good example where this shines, is with Virtual Host Scanning. When checking for Virtual Hosts (VHosts), you are seeking responses that don’t match the host request. If we were to do that with acc, we could use the following:

ffuf -w vhostnames.txt -u https://target -H "Host: FUZZ. target" -acc "www"
This would send a preflight check to our target to capture the content-length and response code of www, and then highlight only responses which have a different content length that return from our wordlist. This greatly helps to eliminate false positives, and in these types of cases is more accurate than ac which would use random strings to capture the response, and is unlikely to be as accurate for this type of (and other types of) fuzzing activity.

Immediately Stop on Error Case
FFUF can force stop once an error is received, using the sa flag. This overrules any of the other error condition flags (se and sf) as their thresholds would never be met.

Stop on Spurious Errors
FFUF has a flag to allow jobs to automatically stop when a percentage of the recent requests have thrown an error. This flag is se, and will end the job if the last 50 requests have thrown a 403 response code 95% of the time, or if 20% of the responses have been a 429 response code. This can be safer than the flag sf, which will only stop if a portion of the entire request pool have errored, and not just recent requests. These limits may change over time, and are referenced here, should you wish to manually review them: https://github.com/ffuf/ffuf/blob/master/pkg/ffuf/job.go#L382-L407

Request Throttling and Delays
With production hosts, or under various testing conditions you will need to throttle your responses. When these conditions are required, FFUF provides a number of options.

Delay Between Requests
The p flag specifies the seconds of delay between requests. This can be a range, or a set figure. For example, a p value of 2 would enforce a 2 second delay between each request, whilst a p value of 0.1-2.0 would enforce a random delay between 0.1-2 seconds.

Limited Max Requests/second
As FFUF is a multi threaded application, you can easily end up overwealming a destination target with too many requests. In order to control this, you can specify a maximum number of requests that can be sent per second. This can be set with the -rate flag. For example, if you wish to limit to 2 requests per second, then you would specify -rate 2.

Match Options
Match on Response Code
There are a variety of predescribed matching options in FFUF, the most common one that you’ll find yourself using is mc, which matches the response code. In many cases, you’ll want to change this to limit to only 200 requests, to help isolate the results to content that you’re seeking.

Match on Regular Expression
In some cases, however, you may be fuzzing for more complex bugs and want to filter based on a regular expression. For example, if you’re filtering for a path traversal bug you may wish to pass a value of -mr "root:" to FFUF to only identify successful responses that indicate a successful retreival of /etc/passwd. Such cases are quite common, and highlight some of the power that FFUF brings into fuzzing that competitive offerings are not yet able to match.

Filter and Matches
As useful as matches are, filters being the inverse of matches can be just as, if not more useful. When returning the results of a page that has a sink (a location where your source, or wordlist item is reflected in the page) within the response, it can be more useful to filter the number of words in a page, rather than filter by content length. For this purpose, FFUF provides fw, or filter words. If you can identify the number of words commonly in the response, you can apply this filter to remove any results that have your content length. If words aren’t specific enough, you can also filter on the number of lines within the HTTP response, using fl.

Much like filters, you can also filter based on content length (fc) to remove response types from the results. This can be especially useful where you want to first filter for all defaults, which includes the 301 response code, and then filter this response code out from the results to see more specific responses.

Sending FFUF scans via Burp Suite
For a variety of reasons, you’ll often find yourself wanting your FFUF scans to be sent via Burp Suite. Notably, there’s a few ways to acomplish this goal, and it’s important to understand each of them, and apply the right one for your use case.

Locally, Using Replay Proxy
FFUF has a command within it, replay-proxy to dictate. This will retoute successful commands (ones that hit your matches, and not your filters) to Burp Suite proxy for further investigation. Notably, this does mean that you’re doubling your requests, and this should be used in situations where it makes sense to do so.

If for whatever reason (such as engagement terms) you need to send all information via Burp Suite, and not just successful traffic, then you can instead use x which will replay all requests via a Burp Suite project, regardless of whether they line up with FFUF filters/matches or not.

Using an Interface
Occasionally, you’ll encounter situations where you need all of your FFUF (or another tools) traffic to be send via Burp Suite over a Burp Suite Interface. This could be due to engagement logging (required by the firm you’re testing for/against), or due to a complex authentication schema that Burp Suite is better positioned to handle. Personally, I’ve also found this useful for fuzzing various elements (such as CSRF tokens) in conjunction with Burp Suite Macros. Whatever the use case, the method for doing this is quite simple. Firstly, we need to go to Burp Suite and setup a second interface, you can do this under proxy->options->add

FFUF

Under binding, set a port, for the second interface I prefer to use 8181 (as 8080 is the default and I find this easy to recall).

FFUF

Under the request handling flag, set “Redirect to host” and “Redirect to port” to match that of our destination target:

FFUF

After we’ve done that, leave other settings the same and click ok. We can then target https://127.0.0.1:8181 with any of our tools, including FFUF, and it will automatically redirect to the destination target. This means, instead of using http://target.com/path/FUZZ in FFUF to focus on our target, we can use https://127.0.0.1:8181/path/FUZZ. Everything will work as it did before, except the requests are being sent to, and out from Burp Suite.

Be cautious when using this approach on large wordlists, as Burp Suite will store the history within your associated project, and passing large fuzzes via Burp Suite is likely to cause your project file to become bloated, and unwieldy quickly.

Remote VPS Traffic via a Reply Proxy
When using a remote VPS you’ll occasionally hit decisions in your testing that would be aided by using a local version of Burp Suite. To help aid in this, when fuzzing with FFUF you can open a reverse SSH tunnel and combine it with reply-proxy on your remote VPS to replay it over the remote port, to your local Burp Suite instance.

First connect to your remote VPS over SSH server using:

ssh -R 8888:localhost:8080 user@remotevps
And then run FFUF with the following:

~/go/bin/ffuf -u http://codingo.io/FUZZ -w ./wordlist -replay-proxy http://127.0.0.1:8888
Since we bound port 8888 to relay over our reverse SSH tunnel to our remote burp instance, on port 8080, this will then replay back in Burp Suite.

Advanced Wordlist Usage
When using multiple wordlists, FFUF has two modes of operation. The first, and the default, is clusterbomb. This takes both wordlists and tries all possible combinations of them, and is best for brute forcing operations. By default FFUF will use the clusterbomb attack mode, however you can specify other modes (for now, just pitchfork and clusterbomb) using the mode flag.

For example, let’s assume we had a wordlist called “users”, with two users, “codingo” and “anonymous”. In addition, we’ll assume we have a wordlist “passwords”, with two items, “hunter1”, and “password”. In clusterbomb mode, all combinations of these would be tried, resulting in the following output.

Alternatively, FFUF provides another mode called “pitchfork”. This mode is intended for when you want to use wordlists in series. For example, let’s assume that you have a list of passwords, that go with a list of users and want to fuzz via a username and parameter endpoint. In this example, the password “hunter1”, would be tried with the user “codingo”, and the password “password” would be tried with the user “anoymous”, however that would be the end of the operation, and further combinations would not be tried.

Each has its own use cases, and it’s important to know how to use both, however if you’re unsure which to use, it’s best to stick with the default, clusterbomb.

Clusterbomb
Most useful for a brute-force attack style, the clusterbomb will try all combinations of payloads. As Burp Suite Intruder operates with the same kind of wordlist approaches, I’ve found this is best explained by Sjord, here. To paraphrase Sjord, essentially the clusterbomb tries all possible combinations, while still keeping the first payload set in the first position and the second payload set in the second position. As shown in the following example:

FFUF

Here we can see that the first payload position is used in position one, 456. And the second, in postion two, <br. The first payload is then rotated, whilst the second isn’t, until the first list has been exhausted at which time the second list continues through the same operation. Operating in this style ensures that all possible permutations are tested.

Pitchfork
Much like the Clusterbomb approach, I’ve found the Pitchfork style of fuzzing is also best explained by Sjord, here. To paraphase, the pitchfork attack type uses one payload set for each position. It places the first payload in the first position, the second payload in the second position, and so on. This attack type is useful if you have data items that belong together. For example, you have usernames with corresponding passwords and want to know whether they work with this web application.

FFUF

As you can see when compared to the clusterbomb atack, the pitchfork attack works the wordlists in series. Not all combinations will be reached, but the use case for these is that they aren’t intended to and doing so would be a waste of requests.

Handling Output
HTML Output
Using Silent and Tee
If you want to print results only, without all of the padding, the s flag, or silent mode, works great for this. For example:

ffuf -request /tmp/request.txt -w ./wordlist.txt -s
With our original example, will only output admin, as it’s the only successful match. This can also be useful to pass to other tools, however when doing so I suggest also using tee. The tee command will output the results to console, whilst also redirecting it as stdout, allowing other applications to consume it. For example, the following:

ffuf -request /tmp/request.txt -w ./wordlist.txt -s | tee ./output.txt
Would output to the console and write to output.txt. This is a useful trick for a number of tools, including those that don’t stream output, to allow you to see results in realtime, whilst also streaming them to a file.

Importing Requests
On of the easiest ways to work with complex queries is to simply save the request you’re working with from your intercepting proxy (such as Burp Suite), set your fuzzing paths, and then import it into FFUF for usage. You can do this with the request flag in FFUF, as explained below.

Going back to our original fuzzing example, let’s assume we visited codingo.io in Burp Suite, and we captured the following request:

FFUF

We can right click in the request, and select Copy to File:

FFUF

Be sure not to select Save item as that will save this in a format known only to Burp Suite, and not of use to FFUF.

Once we’ve saved the file, we then need to open it in our favorite editor, and add our fuzzing points. For this example, I want to brute force items at the top level of the codingo.io domain and so I’m adding FUZZ on the top line, as shown below:

FFUF

We can then open our request in FFUF, and instead of passing cookie information or a URL, we can use request to feed it the information in our saved request. In this case, this would look like the following:

ffuf -request /tmp/request.txt -w ./wordlist.txt
                                                                                                                   
                                                           
###################
#####################
