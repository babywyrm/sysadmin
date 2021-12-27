

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
