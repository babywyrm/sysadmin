#!/bin/python3
#
# Author ccwillem

##
##

import requests
import json
import argparse
import validators
import dns.resolver, dns.exception, dns.rdatatype
import sys
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed


parser = argparse.ArgumentParser()
parser.add_argument("-d", "--domain", action="store", help="Enter the domain you would like to search for.")
parser.add_argument("-l", "--list", action="store", help="(rel) path to file containing list with subdomains separated by newlines")
parser.add_argument("-b", "--brute", action="store_true", help="Use a wordlist to bruteforce subdomains and find CNAMES. to be used together with -d and -w")
parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose output of each subdomain, cname and ip address")
parser.add_argument("-w", "--wordlist", action="store", help="path to file with wordlist containing prefixes for subdomain breuteforcing")
parser.add_argument("-j", "--json", action="store_true", help="Show output in json format. Only dangling domains will be shown, no verbose info will be included.")

args = parser.parse_args()

search_domain = args.domain ## list of positional first arguments: domain name
input_list = []
json_dangling = {'danglingDomains': []}

if not args.json:
    print('''
     ,-""""-.
   ,'      _ `.
  /       )_)  `
 :              :
 \              /
  \            /
   `.        ,'
     `.    ,'
       `.,'
        /\`.   ,-._
            `-'     
                    By Willem, 2022

Find forgotten subdomains that are still floating in the air....
''')
          
if not search_domain and not args.list:
    print('Specify input domain or a file with subdomains')
    quit()

if args.list:
    with open(args.list, 'r') as f:
        first_line = f.readline()
        lines = f.readlines()
    non_empty_lines = [line.strip() for line in lines if line.strip() != ""] ## remove empty lines, and leading and trailing whitespace
    input_list += non_empty_lines ## append targets from input list file to targets from command line input
    uniq_input_list = list(set(input_list))
    results = uniq_input_list

if args.brute:
    with open(args.wordlist, 'r') as f:
        first_line = f.readline()
        lines = f.readlines()
    non_empty_lines = [line.strip() for line in lines if line.strip() != ""] ## remove empty lines, and leading and trailing whitespace
    input_list += non_empty_lines ## append targets from input list file to targets from command line input
    uniq_input_list = list(set(input_list))
    subs_to_check = []
    for item in uniq_input_list:
        subs_to_check.append(f"{item}.{search_domain}")
    results = subs_to_check
    if args.verbose:
        print(f"\033[93m[ + ]\033[0m   Bruteforcing subdomains for \033[92m{search_domain}\033[0m using wordlist \033[92m{args.wordlist}\033[0m\.\n")

if args.domain and not args.brute:
    crt_url = "https://crt.sh/?Identity="+search_domain+"&output=json"
    if args.verbose:
        print("\033[93m[ + ]\033[0m   Retrieving certificate information from crt.sh\n")
    try:
        response = requests.get(crt_url)
        if response.status_code == 200 and response.text:
            if args.verbose:
                print("\033[93m[ + ]\033[0m   Successfully retrieved domains and subdomains\n")
        else:
            if args.verbose:
                print("\033[91m[ - ]\033[0m   Error collecting information")
                sys.exit()
    except Exception as e:
        if args.json:
            json_dangling['danglingDomains'] = "Error collecting subdomains"
        else:
            print(f"\033[91m[ - ]\033[0m    Error: {e}")
        sys.exit()

    if response:
        json_response = json.loads(response.text)
        results = []
        for result in json_response:
            subdomain = result["common_name"]
            if validators.domain(subdomain) == True:
                results.append(subdomain)
        results = list(set(results))
        # print(results)
        if args.verbose:
            print(f"\033[93m[ + ]\033[0m   In total \033[92m{len(results)}\033[0m subdomains have been discovered for \033[92m{search_domain}\033[0m\n")
            print("\033[93m[ + ]\033[0m    Checking for CNAME's...\n")
        else:
            if not args.json:
                print(f"{len(results)} subdomains founds\n")

domain_with_cname=[]
dangling = []
json_list =[]

def cname_lookup(sub):
    try:
        answer = dns.resolver.resolve(sub, "CNAME")
        if answer:
            domain_with_cname.append(sub)
            for rdata in answer:
                cname = rdata.target
                try:
                    address = dns.resolver.resolve(cname, "A")
                    for data in address:
                        ip = data.address
                        if args.verbose:
                            tqdm.write("\033[92m{:50} {:5<} {:<50} {:<5} {:<0}\033[0m".format((str(sub)), str("--->"), str(cname), str("--->"),str(ip)))
                except dns.exception.DNSException:
                    if args.json:
                        json_list.append(sub)
                    else:
                        dangling.append("{:50} {:5<} {:<50} {:<5} {:<0}".format((str(sub)), str("--->"), str(cname), str("--->"),str("???")))
                        if args.verbose:
                            tqdm.write("\033[91m{:50} {:5<} {:<50} {:<5} {:<0}\033[0m".format((str(sub)), str("--->"), str(cname), str("--->"),str("???")))
                    continue               
    except dns.exception.DNSException:
        pass



if len(results) != 0:
    pbar = tqdm(total=len(results), colour="yellow")
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = [pool.submit(cname_lookup, sub) for sub in results]
        for _ in as_completed(futures):
            pbar.update(n=1)    
    pool.shutdown()
            
        

        

json_dangling['danglingDomains'] = json_list
if args.json:
    print(json.dumps(json_dangling, indent=4))
else:
    if len(domain_with_cname) == 0:
        tqdm.write("\n\033[93m[ + ]    No subdomains with CNAME record found. Better luck next time!\033[0m\n")
    else:
        if len(dangling) == 0:
            tqdm.write("\n\033[93m[ + ]    All CNAME's resolve to an IP address. Better luck next time!\033[0m\n")
        else:
            tqdm.write("\n\033[91m[ ! ]    Discovered the following dangling domains:\033[0m\n")
            for each in dangling:
                tqdm.write(f"\033[91m{each}\033[0m")
            tqdm.write("\n")

      
