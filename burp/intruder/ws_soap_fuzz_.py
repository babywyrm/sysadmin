# Simple dirty script to fuzz a SOAP request using the Burp Sniper approach: 
#     See https://portswigger.net/burp/documentation/desktop/tools/intruder/positions 
# Dependencies: 
#     pip install lxml requests_ntlm requests tabulate tqdm

###
###

import requests
import urllib3
from requests_ntlm import HttpNtlmAuth
from lxml import etree as ET
from tabulate import tabulate
from hashlib import sha1
from tqdm import tqdm

def generate_payloads_set(soapReqStr,injectionPayload):
    # Burp Sniper approach
    payloads= []
    root = ET.fromstring(soapReqStr)
    placeholder_count=len(root.xpath("//text()"))
    for i in range(0,placeholder_count):
        root = ET.fromstring(soapReqStr)
        nodes = root.xpath("//text()")
        if nodes[i] != None and len(nodes[i].strip("\n\r\t ")) > 0:
            nodes[i].getparent().text = injectionPayload
            payloads.append(ET.tostring(root))
    return payloads

def fuzz(url,http_headers,soapRequests,identity):
    results = []
    session = requests.Session()
    session.auth = identity
    session.headers = http_headers
    print("[i] Start the fuzzing...")
    for i in tqdm(range(0,len(soapRequests))):
        soapReq = soapRequests[i]
        if soapReq == None:
            continue
        fuzz_id = sha1(soapReq).hexdigest()
        with open(fuzz_id + "-request.txt","wb") as f:
            f.write(soapReq)
        try:            
            resp = session.post(url, data=soapReq, verify=False)
            results.append([fuzz_id, resp.status_code, len(resp.text), resp.elapsed.total_seconds()])          
            with open(fuzz_id + "-response.txt","w") as f:
                f.write(resp.text)            
        except Exception as e:
            results.append([fuzz_id, "ERROR: " + str(e), "NA",-1])
            pass
    print("[i] Results:")
    print(tabulate(results,headers=["Fuzz ID", "Response code", "Response size in bytes", "Response time in seconds"], numalign="right", floatfmt=".2f"))
    print("[!] See Requests/Responses files in the current folder for details.")

if __name__== "__main__":   
    urllib3.disable_warnings() 
    # Load the sample SOAP request
    print("[i] Load the sample SOAP request and extract the parts...")
    with open("sample.raw", "r") as f:
        req = f.read().splitlines()
    # Extract the URL/SOAPAction/SOAPRequest (HTTP body)
    target_url = req[0].split(" ")[1].strip()
    xml = ""
    body_part = False
    for line in req:
        if "SOAPAction" in line:
            soapAction = line.split(" ")[1].replace("\"","").strip()
        elif len(line.strip("\n\r")) == 0:
            body_part = True
            continue
        if body_part:
            xml += line
    print("\tTarget URL: %s" % target_url)
    print("\tSOAPAction: %s" % soapAction)
    # Generate the list of test requests
    print("[i] Generate the list of test requests...")
    payloads = generate_payloads_set(xml,"T")
    # Configure and start fuzzing
    # See below for others authentication mode: 
    # https://2.python-requests.org/en/master/user/authentication/
    identity = HttpNtlmAuth("DOMAIN\\USER","PASSWORD")
    http_headers = {"SOAPAction": soapAction, "Content-Type": "text/xml; charset=utf-8"}
    fuzz(target_url, http_headers, payloads, identity)
    print("[i] Fuzzing finished.")

########
########
##
##
