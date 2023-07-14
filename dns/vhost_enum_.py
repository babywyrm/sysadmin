#!/usr/bin/env python3

##
##

import argparse
import hashlib
import logging
import queue
import requests
import sys
import time
import threading
import urllib3
from requests import adapters


class CustomFormatter(logging.Formatter):

    err_fmt = "[-] %(msg)s"
    wrn_fmt = "[!] %(msg)s"
    dbg_fmt = "DEBUG: %(msg)s"
    info_fmt = "[+] %(msg)s"

    def __init__(self):
        super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style='%')

    def format(self, record):
        format_orig = self._style._fmt
        if record.levelno == logging.DEBUG:
            self._style._fmt = CustomFormatter.dbg_fmt
        elif record.levelno == logging.INFO:
            self._style._fmt = CustomFormatter.info_fmt
        elif record.levelno == logging.ERROR:
            self._style._fmt = CustomFormatter.err_fmt
        elif record.levelno == logging.WARNING:
            self._style._fmt = CustomFormatter.wrn_fmt
        result = logging.Formatter.format(self, record)
        self._style._fmt = format_orig
        return result


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--wordlist", help="The wordlist to use", default="./vhosts.txt", required=False)
    parser.add_argument("-s", "--tls", action='store_true', help="Use HTTPs")
    parser.add_argument("-i", "--ip", help="The ip of the host", required=True)
    parser.add_argument("-p", "--port", help="A custom port to use")
    parser.add_argument("-d", "--domain", help="The domain to use", required=True)
    parser.add_argument('-b', "--baseline", help="The baseline subdomain to use", default="www")
    parser.add_argument('-t', "--threads", default=10, help="Number of threads to use", type=int)
    parser.add_argument('-v', "--verbose", action='store_true', help="Set loglevel to DEBUG")
    return parser.parse_args()


def get_site(ip, host, subdomain, prefix, custom_port):
    hostname = f"{subdomain}.{host}"
    headers = {'Host': hostname}
    url = f"{prefix}{ip}"
    if custom_port is not None:
        url = f"{url}:{custom_port}"
    try:
        response = http_session.get(url, verify=False, headers=headers)
    except requests.exceptions.SSLError:
        logging.error(f"{url} was requested but SSL error occurred (is the site using TLS?).")
        return None, None
    except requests.exceptions.ConnectionError as error:
        logging.error(f"Failed to connect to {ip}.\n{error}")
        return None, None
    except requests.exceptions.InvalidURL:
        logging.error(f"Url {url} is invalid.")
        return None, None
    if response.status_code == 200:
        length = len(response.content)
        hash_object = hashlib.sha256(response.content)
        hash_value = hash_object.hexdigest()
        return length, hash_value
    else:
        logging.error(f"Request to {url} failed.")
        return None, None


def consume_words(wordlist_queue, ip, port, prefix, domain, l_baseline, h_baseline, result_list):
    while not wordlist_queue.empty():
        word = wordlist_queue.get()
        length, digest = get_site(ip, domain, word.rstrip('\n'), prefix, port)
        if length is not None and digest is not None:
            if length != l_baseline and digest != h_baseline:
                logging.info(f"{word}.{domain} returns 200 and seems a different site")
                result_list.append(f"{word}.{domain}")
            else:
                logging.debug(f"{word}.{domain} returns 200, but the content seems to be the same"
                              f" as the one of main site.")


def __get_wordlist(wordlist_file):
    try:
        with open(wordlist_file) as fp:
            content = fp.read()
            words = content.split('\n')
    except FileNotFoundError:
        logging.error(f"File {wordlist_file} does not exist. Aborting.")
        exit(1)
    # Removes empty lines
    words = filter(None, words)
    # Removes duplicates
    words = [w.lower() for w in words]
    return words


def __get_wordlist_queue(words_list):
    logging.info("Generating wordlist queue...")
    words_queue = queue.Queue()
    for w in words_list:
        words_queue.put(w)
    logging.info(f"Loaded {words_queue.qsize()} words.")
    return words_queue


def main():
    args = get_args()
    if args.verbose:
        logging.root.setLevel(logging.DEBUG)
    else:
        logging.root.setLevel(logging.INFO)
    wordlist = args.wordlist
    tls = args.tls
    ip = args.ip
    port = args.port
    domain = args.domain
    baseline = args.baseline
    threads = args.threads
    words_list = __get_wordlist(wordlist)
    wordlist_queue = __get_wordlist_queue(words_list)
    if tls:
        prefix = "https://"
    else:
        prefix = "http://"
    adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=len(words_list))
    http_session.mount(prefix, adapter)
    l_baseline, h_baseline = get_site(ip, domain, baseline, prefix, port)
    if l_baseline is None or h_baseline is None:
        logging.error(f"Establishing baseline failed. Make sure that {baseline}.{domain} exists "
                      f"and that you are using the correct port.")
        exit(1)
    logging.info(f"Established baseline: {baseline}.{domain} returns a "
                 f"page of {l_baseline} bytes and with hash {h_baseline}.")
    confirmed = list()
    threads_list = list()
    logging.info(f"Spawning {threads} thread(s)...")
    timestamp_start = time.time()
    for i in range(threads):
        worker = threading.Thread(target=consume_words, args=(wordlist_queue, ip, port, prefix, domain, l_baseline,
                                                              h_baseline, confirmed))
        threads_list.append(worker)
        worker.start()
    for thread in threads_list:
        thread.join()
    logging.info(f"Job completed in {time.time()-timestamp_start} seconds.")
    if len(confirmed) > 0:
        logging.info("The following virtualhost were discovered:")
        for site in set(confirmed):
            print(f"* {site}")
    else:
        logging.warning("No virtualhosts were discovered.")


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    formatter = CustomFormatter()
    hdlr = logging.StreamHandler(sys.stdout)
    hdlr.setFormatter(formatter)
    logging.root.addHandler(hdlr)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    http_session = requests.session()
    main()


#############
##
##
