import os,sys
import requests

from argparse import ArgumentParser

parser = ArgumentParser(description='Get the current weather for your zip')
parser.add_argument('zip', help='zip/postal code')
parser.add_argument('--country', default='us', help='country zip/postal is you, defaults to "US"')

args = parser.parse_args()

api_key = os.getenv("OWM_API_KEY")

if not api_key:
	print("Error: no 'OWM_API_KEY' found")
	sys.exit(1)

url = f"https://api.openweathermap.org/data/2.5/weather?zip={args.zip},{args.country}&appid={api_key}"

res = requests.get(url)

if res.status_code != 200:
	print(f"Cannot reach provider, sad...... {res.status_code}")
	sys.exit(1)

print(res.json())

###########################
##
##
