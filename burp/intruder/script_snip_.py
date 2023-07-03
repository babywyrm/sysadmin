# ***********************************************replacer_for_python_scripter
##
##

import re,random

print callbacks.getToolName(toolFlag)
if(messageIsRequest):
	if (callbacks.getToolName(toolFlag) == "Proxy" or callbacks.getToolName(toolFlag) == "Intruder" or callbacks.getToolName(toolFlag) == "Repeater"):
		requestInfo = helpers.analyzeRequest(messageInfo)
		headers = requestInfo.getHeaders()
		msgBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
		msg = helpers.bytesToString(msgBody)
		randStr = random.randint(1000000,9999999)
		msg = re.sub(r'(name="hicEmail"\s+[^@]+)(@[^\s]+)',r'\g<1>' + str(randStr) + r'\g<2>',msg)
		print msg
		msgBody = helpers.stringToBytes(msg)
		message = helpers.buildHttpMessage(headers, msgBody)
		messageInfo.setRequest(message)
		print "hoy hoy"
# ***********************************************replay before sending the request-python_scripter
print "hey hey - replay me before I go away!"
if(messageIsRequest):
                if (callbacks.getToolName(toolFlag) == "Proxy" or callbacks.getToolName(toolFlag) == "Repeater"):        
                                callbacks.makeHttpRequest(messageInfo.getHttpService(), messageInfo.getRequest())


# ***********************************************request_replacer_MultipartRelated2TextXML_for_python_scripter
import re,random
import urllib

#### helpers start #### 
def overwriteHeader(allheaders, strNewHeader, isCaseInsensitive):
    isAdded = False
    newHeaderName = strNewHeader.split(':',1)[0]
    for id, item in enumerate(allheaders):
        if isCaseInsensitive:
            item = item.lower()
            newHeaderName = newHeaderName.lower()
        if newHeaderName in item:
           allheaders[id] = strNewHeader
           isAdded = True
    if not isAdded:
        allheaders.append(strNewHeader)
    return allheaders

def findHeader(allheaders,targetHeader,isCaseInsensitive):
    for id, item in enumerate(allheaders):
        if isCaseInsensitive:
            item = item.lower()
            targetHeader = targetHeader.lower()
        if targetHeader in item:
           return allheaders[id]
    return ""
####  helpers end #### 

print callbacks.getToolName(toolFlag)
if(messageIsRequest):
    if (callbacks.getToolName(toolFlag) == "Repeater"):
        requestInfo = helpers.analyzeRequest(messageInfo)
        hostname = requestInfo.getUrl().getHost()
        relPath = urllib.unquote(requestInfo.getUrl().getPath()).decode('utf8')
        headers = list(requestInfo.getHeaders())  #python list rather than java arraylist
        contentType = findHeader(headers, 'content-type', 1)
        # more granular rules for auto replace
        if (hostname == "example.com" and ("/something" in relPath or "/foobar" in relPath) and ("multipart/related" in contentType)):
            msgBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
            msg = helpers.bytesToString(msgBody)
            #randStr = random.randint(1000000,9999999)
            #msg = re.sub(r'(name="hicEmail"\s+[^@]+)(@[^\s]+)',r'\g<1>' + str(randStr) + r'\g<2>',msg)
            try:
                headers = overwriteHeader(headers, 'content-type: {type}'.format(type="text/xml"), 1)
                msg = re.search('(\<s:Envelope.*\<\/s:Envelope\>)', msg).group(0)
                msgBody = helpers.stringToBytes(msg)
                message = helpers.buildHttpMessage(headers, msgBody)
                #cookieParam = helpers.buildParameter('XSRF-TOKEN', 'test', 2) # updating a cookie parameter for CSRF
                #message = helpers.updateParameter(message, cookieParam)
                messageInfo.setRequest(message)
                print "request has been updated!"
            except AttributeError:
                # Ignore!
                print "ignored - request was not updated!"

# ***********************************************response_replacer_for_python_scripter
import re,random
import urllib

enabled = True
if(not messageIsRequest and enabled):
    if (callbacks.getToolName(toolFlag) == "Proxy"):
        requestInfo = helpers.analyzeRequest(messageInfo)
        hostname = requestInfo.getUrl().getHost()
        relPath = urllib.unquote(requestInfo.getUrl().getPath()).decode('utf8')
        # more granular rules for auto replace
        if (hostname == "example.com" and ("/something" in relPath or "/foobar" in relPath or "somethingelse" in relPath)):
            responseInfo = helpers.analyzeResponse(messageInfo.getResponse())
            headers = responseInfo.getHeaders()
            #msgRequestBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
            msgResponseBody = messageInfo.getResponse()[responseInfo.getBodyOffset():]
            msg = helpers.bytesToString(msgResponseBody)
            #randStr = random.randint(1000000,9999999)
            msg = re.sub(r'(":)(\s*false)',r'\g<1>true',msg)
            msg = re.sub('"type":"view"','"type":"edit"',msg)
            print msg
            msgBody = helpers.stringToBytes(msg)
            message = helpers.buildHttpMessage(headers, msgBody)
            messageInfo.setResponse(message)
            print "response has been updated!"

# ***********************************************header_signature_sha1-python_scripter
import re
import random
import hashlib
import base64
import datetime
import hmac
import urllib
import operator
from burp import IParameter

# coded by Soroush Dalili (@irsdl) for Burp Suite Python Scripter extension!
print "scripter starts here..."

xUserToken = "4ba75b0caaad1d569e12ac5bbcac2aabbaaa3e96"
ignorePortInURL = True

# We check these to prevent adding headers to unnecessary requests
targetHostnameCheck = "pentest.example.com"
targetPathCheck = "/api/"
targetExcludeWhenInQS = "excluded=ncc"

def overwriteHeader(allheaders, strNewHeader):
    isAdded = False
    newHeaderName = strNewHeader.split(':',1)[0]
    for id, item in enumerate(allheaders):
       if newHeaderName in item:
           allheaders[id] = strNewHeader
           isAdded = True
    if not isAdded:
        allheaders.append(strNewHeader)
    return allheaders

def readHeader(allheaders, strTargetHeader, isCaseSensitive):
    result = ""
    strTargetHeader = strTargetHeader + ":"
    if not isCaseSensitive:
        strTargetHeader = strTargetHeader.lower()

    for id, item in enumerate(allheaders):
        itemtemp = item
        if not isCaseSensitive:
            itemtemp = itemtemp.lower()
        if itemtemp.startswith(strTargetHeader):
            result = item
            break
    return result


def xstr(s):
    if s is None:
        return ''
    return str(s)

def getKey(item):
    return item[0]    

if(messageIsRequest):
    if (callbacks.getToolName(toolFlag) == "Scanner" or callbacks.getToolName(toolFlag) == "Intruder" or callbacks.getToolName(toolFlag) == "Repeater" or callbacks.getToolName(toolFlag) == "Extender"):
        requestInfo = helpers.analyzeRequest(messageInfo)
        
        # relative path & QA from URL
        url = requestInfo.getUrl().toString()
        port = xstr(requestInfo.getUrl().getPort())
        hostname = requestInfo.getUrl().getHost() 
        relPath = urllib.unquote(requestInfo.getUrl().getPath()).decode('utf8')
        QSPart = xstr(requestInfo.getUrl().getQuery()) #only Querystring - we use it to check for exclusions atm
        allParamsArray = requestInfo.getParameters() # we need GET and POST
        
        # This is to ensure we are not setting this on an unwanted request
        if ((len(targetHostnameCheck) == 0 or hostname == targetHostnameCheck) and (len(targetPathCheck) == 0 or targetPathCheck in relPath) and (len(targetExcludeWhenInQS) == 0 or len(QSPart)==0 or targetExcludeWhenInQS not in QSPart)):
            headers = list(requestInfo.getHeaders()) #python list rather than java arraylist
            msgBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
            msg = helpers.bytesToString(msgBody)
            fullHeadersBody = helpers.bytesToString(messageInfo.getRequest())

            # finding all parameters / exclude file uploads / sort on key name
            allParams = ""
            allParamsDict = {} # we can't work with Java ArrayList easily so we convert it to a Python dictionary
            content_type= readHeader(headers,"content-type",False).lower()
            isMultipart = False
            if "multipart" in content_type:
                isMultipart = True
            isJSON = False
            if "application/json" in content_type:
                isJSON = True
            
            toBeHashedVar = ""
            if isJSON or len(msg) == 0:
                # JSON, GET
                if len(QSPart)>0:
                    for p in allParamsArray:
                        if (p.getType() == IParameter.PARAM_BODY and not isMultipart) or p.getType() == IParameter.PARAM_URL:
                            #helpers.urlEncode did not work here and we have to use urllib.quote
                            allParams += "&" + urllib.quote(urllib.unquote(p.getName()).decode('utf8')) + "=" + urllib.quote(urllib.unquote(p.getValue()).decode('utf8'))
                    allParams = allParams[1:]
                    # In this special!!! app the colon character won't be encode to %3A but we are doing it :(
                    allParams = allParams.replace("%3A", ":")
                    headers[0] = headers[0].replace(QSPart, allParams) # replacing the querystring
                    url = url[:url.find('?')]+'?' + allParams
                
                if ignorePortInURL:
                    url = url.replace(hostname+":"+port+"/",hostname+"/",1)
                    
                toBeHashedVar = url + msg + xUserToken
                # we have something to hash!
                print toBeHashedVar
                m = hashlib.sha1()
                m.update(toBeHashedVar)
                headers = overwriteHeader(headers, 'x-service-request-hash: ' + m.hexdigest())
                
                message = helpers.buildHttpMessage(headers, msgBody)
                messageInfo.setRequest(message)

print "scripter ends here..."

# ***********************************************ReqResp_replacer_for_python_scripter
import re,random
import urllib

enabledResponseReplace = 0
enabledRequestReplace = 1

#### helpers start #### 
def overwriteHeader(allheaders, strNewHeader):
    isAdded = False
    newHeaderName = strNewHeader.split(':',1)[0]
    for id, item in enumerate(allheaders):
       if newHeaderName in item:
           allheaders[id] = strNewHeader
           isAdded = True
    if not isAdded:
        allheaders.append(strNewHeader)
    return allheaders

####  helpers end #### 

if(not messageIsRequest and enabledResponseReplace):
    if (callbacks.getToolName(toolFlag) == "Proxy"):
        requestInfo = helpers.analyzeRequest(messageInfo)
        hostname = requestInfo.getUrl().getHost()
        relPath = urllib.unquote(requestInfo.getUrl().getPath()).decode('utf8')
        # more granular rules for auto replace
        if (hostname == "example.com" and ("/something" in relPath or "/foobar" in relPath or "somethingelse" in relPath)):
            responseInfo = helpers.analyzeResponse(messageInfo.getResponse())
            headers = responseInfo.getHeaders()
            #msgRequestBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
            msgResponseBody = messageInfo.getResponse()[responseInfo.getBodyOffset():]
            msg = helpers.bytesToString(msgResponseBody)
            #randStr = random.randint(1000000,9999999)
            msg = re.sub(r'(":)(\s*false)',r'\g<1>true',msg)
            msg = re.sub('"type":"view"','"type":"edit"',msg)
            print msg
            msgBody = helpers.stringToBytes(msg)
            message = helpers.buildHttpMessage(headers, msgBody)
            messageInfo.setResponse(message)
            print "response has been updated!"

if(messageIsRequest and enabledRequestReplace):
    #if (callbacks.getToolName(toolFlag) == "Proxy" or callbacks.getToolName(toolFlag) == "Intruder" or callbacks.getToolName(toolFlag) == "Repeater" or callbacks.getToolName(toolFlag) == "Target" or callbacks.getToolName(toolFlag) == "Scanner"):
    if (callbacks.getToolName(toolFlag) == "Repeater" or callbacks.getToolName(toolFlag) == "Target"):
        requestInfo = helpers.analyzeRequest(messageInfo)
        hostname = requestInfo.getUrl().getHost()
        relPath = urllib.unquote(requestInfo.getUrl().getPath()).decode('utf8')
        # more granular rules for auto replace
        if (hostname == "dashboard.capitatravelandevents.co.uk"):
            headers = list(requestInfo.getHeaders())  #python list rather than java arraylist
            msgBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
            msg = helpers.bytesToString(msgBody)
            #randStr = random.randint(1000000,9999999)
            #msg = re.sub(r'(name="hicEmail"\s+[^@]+)(@[^\s]+)',r'\g<1>' + str(randStr) + r'\g<2>',msg)
            headers = overwriteHeader(headers, 'X-XSRF-TOKEN: {csrfToken}'.format(csrfToken="test"))
            msgBody = helpers.stringToBytes(msg)
            message = helpers.buildHttpMessage(headers, msgBody)
            cookieParam = helpers.buildParameter('XSRF-TOKEN', 'test', 2) # updating a cookie parameter for CSRF
            message = helpers.updateParameter(message, cookieParam)
            messageInfo.setRequest(message)
            print "request has been updated!"

# ***********************************************debug_replace_request_replace_response
import re,random
import urllib

enabledResponseReplace = 0
enabledRequestReplace = 1

#### helpers start #### 
def overwriteHeader(allheaders, strNewHeader):
    isAdded = False
    newHeaderName = strNewHeader.split(':',1)[0]
    for id, item in enumerate(allheaders):
       if newHeaderName in item:
           allheaders[id] = strNewHeader
           isAdded = True
    if not isAdded:
        allheaders.append(strNewHeader)
    return allheaders

####  helpers end #### 

if(not messageIsRequest and enabledResponseReplace):
    if (callbacks.getToolName(toolFlag) == "Proxy"):
        requestInfo = helpers.analyzeRequest(messageInfo)
        hostname = requestInfo.getUrl().getHost()
        relPath = urllib.unquote(requestInfo.getUrl().getPath()).decode('utf8')
        # more granular rules for auto replace
        if (hostname == "example.com" and ("/something" in relPath or "/foobar" in relPath or "somethingelse" in relPath)):
            responseInfo = helpers.analyzeResponse(messageInfo.getResponse())
            headers = responseInfo.getHeaders()
            #msgRequestBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
            msgResponseBody = messageInfo.getResponse()[responseInfo.getBodyOffset():]
            msg = helpers.bytesToString(msgResponseBody)
            #randStr = random.randint(1000000,9999999)
            msg = re.sub(r'(":)(\s*false)',r'\g<1>true',msg)
            msg = re.sub('"type":"view"','"type":"edit"',msg)
            print msg
            msgBody = helpers.stringToBytes(msg)
            message = helpers.buildHttpMessage(headers, msgBody)
            messageInfo.setResponse(message)
            print "response has been updated!"

if(messageIsRequest and enabledRequestReplace):
    #if (callbacks.getToolName(toolFlag) == "Proxy" or callbacks.getToolName(toolFlag) == "Intruder" or callbacks.getToolName(toolFlag) == "Repeater" or callbacks.getToolName(toolFlag) == "Target" or callbacks.getToolName(toolFlag) == "Scanner"):
    if (callbacks.getToolName(toolFlag) == "Repeater" or callbacks.getToolName(toolFlag) == "Target"):
        requestInfo = helpers.analyzeRequest(messageInfo)
        hostname = requestInfo.getUrl().getHost()
        relPath = urllib.unquote(requestInfo.getUrl().getPath()).decode('utf8')
        # more granular rules for auto replace
        if (hostname == "www.target.co.uk"):
            headers = list(requestInfo.getHeaders())  #python list rather than java arraylist
            msgBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
            msg = helpers.bytesToString(msgBody)
            #randStr = random.randint(1000000,9999999)
            #msg = re.sub(r'(name="foobar"\s+[^@]+)(@[^\s]+)',r'\g<1>' + str(randStr) + r'\g<2>',msg)
            headers[0] = "GET /logon.asp HTTP/1.1"
            newRequestMessageBody = ""
            newRequestMessage = helpers.buildHttpMessage(headers, newRequestMessageBody)
            newResponseInfo = helpers.analyzeResponse(callbacks.makeHttpRequest(messageInfo.getHttpService(), newRequestMessage).getResponse())
            msgNewResponseBody = newResponseInfo.getResponse()[newResponseInfo.getBodyOffset():]
            msgNewResponseString = helpers.bytesToString(msgResponseBody)
            tokenname_search = re.search('<input type="hidden".* ID="[a-zA-Z0-9]{11}" Name="([^"]+)"', msgNewResponseString, re.IGNORECASE)
            tokenvalue_search = re.search('<input type="hidden".* ID="[a-zA-Z0-9]{11}".* value="([^"]+)"', msgNewResponseString, re.IGNORECASE)
            if tokenname_search and tokenvalue_search:
                tokenname = tokenname_search.group(1)
                tokenvalue = tokenvalue_search.group(1)

                msg = re.sub(r'([a-zA-Z0-9]{11})=([a-zA-Z0-9]{11})',tokenname+'='+tokenvalue,msg)
                #headers = overwriteHeader(headers, 'X-XSRF-TOKEN: {csrfToken}'.format(csrfToken="test"))
                msgBody = helpers.stringToBytes(msg)
                message = helpers.buildHttpMessage(headers, msgBody)
                #cookieParam = helpers.buildParameter('XSRF-TOKEN', 'test', 2) # updating a cookie parameter for CSRF
                #message = helpers.updateParameter(message, cookieParam)
                messageInfo.setRequest(message)
                print "request has been updated!"
# ***********************************************autoURLEncode_QS
#import re,random
#import urllib
from burp import IParameter

enabledRequestReplace = 1


def aggressive_url_encode(string):
    return "".join("%{0:0>2}".format(format(ord(char), "x")) for char in string)

if(messageIsRequest and enabledRequestReplace):
    if (callbacks.getToolName(toolFlag) == "Intruder" or callbacks.getToolName(toolFlag) == "Repeater" or callbacks.getToolName(toolFlag) == "Target" or callbacks.getToolName(toolFlag) == "Scanner" or callbacks.getToolName(toolFlag) == "Extender"):
    #if (callbacks.getToolName(toolFlag) == "Proxy" or  callbacks.getToolName(toolFlag) == "Repeater" or callbacks.getToolName(toolFlag) == "Target"):
        requestInfo = helpers.analyzeRequest(messageInfo)
        hostname = requestInfo.getUrl().getHost()
        #relPath = urllib.unquote(requestInfo.getUrl().getPath()).decode('utf8')
        # more granular rules for auto replace
        #if (hostname == "www.target.co.uk"):
        print "1111"
        if (callbacks.isInScope(requestInfo.getUrl())):
            for parameter in requestInfo.getParameters():
                if (parameter.getType() == IParameter.PARAM_URL):
                    messageInfo.setRequest(helpers.updateParameter(messageInfo.getRequest(), helpers.buildParameter(parameter.getName(), aggressive_url_encode(helpers.urlDecode(parameter.getValue())), IParameter.PARAM_URL)))
            print "request has been updated!"
            
# ***********************************************header_signature-python_scripter
import re
import random
import hashlib
import base64
import datetime
import hmac
import urllib
import operator
from burp import IParameter

# coded by Soroush Dalili (@irsdl) for Burp Suite Python Scripter extension!
print "scripter starts here..."

domain = "S2"
username = "foo.bar"
#password = "SecureXXXXSomething" # we don't use the password here!
apiKey = "testme" # this is from the website
apiSecret = "]$U{xxxxxxxxxxxxxdHSODfC(yNmb" # this is from the website

# usertoken is hardcoded as it needs multi step: 
# A request to /ems/userTokens/createExternal should be made to obtain the Token
# The above request needs to have the password encrypted using the public key obtained from /ems/userTokens/publicKey
# This can be coded easily in Python as well (easier in .Net) using this: https://www.example-code.com/python/rsa_encryptModExp.asp
usertoken = "29c0caaa-8836-4216-bbb-e7b05ee22eee"

# We check these to prevent adding headers to unnecessary requests
targetHostnameCheck = "target.com"
targetPathCheck = "foo"
targetExcludeWhenInQS = "excluded=iamatester"

def overwriteHeader(allheaders, strNewHeader):
    isAdded = False
    newHeaderName = strNewHeader.split(':',1)[0]
    for id, item in enumerate(allheaders):
       if newHeaderName in item:
           allheaders[id] = strNewHeader
           isAdded = True
    if not isAdded:
        allheaders.append(strNewHeader)
    return allheaders

def readHeader(allheaders, strTargetHeader, isCaseSensitive):
    result = ""
    strTargetHeader = strTargetHeader + ":"
    if not isCaseSensitive:
        strTargetHeader = strTargetHeader.lower()

    for id, item in enumerate(allheaders):
        itemtemp = item
        if not isCaseSensitive:
            itemtemp = itemtemp.lower()
        if itemtemp.startswith(strTargetHeader):
            result = item
            break
    return result


def xstr(s):
    if s is None:
        return ''
    return str(s)

def getKey(item):
    return item[0]    

if(messageIsRequest):
    if (callbacks.getToolName(toolFlag) == "Scanner" or callbacks.getToolName(toolFlag) == "Intruder" or callbacks.getToolName(toolFlag) == "Repeater" or callbacks.getToolName(toolFlag) == "Extender"):
        requestInfo = helpers.analyzeRequest(messageInfo)
        
        # relative path & QA from URL
        hostname = requestInfo.getUrl().getHost()
        relPath = urllib.unquote(requestInfo.getUrl().getPath()).decode('utf8')
        QSPart = xstr(requestInfo.getUrl().getQuery()) #only Querystring - we use it to check for exclusions atm
        allParamsArray = requestInfo.getParameters() # we need GET and POST
        
        # This is to ensure we are not setting this on an unwanted request
        if ((len(targetHostnameCheck) == 0 or hostname == targetHostnameCheck) and (len(targetPathCheck) == 0 or targetPathCheck in relPath) and (len(targetExcludeWhenInQS) == 0 or len(QSPart)==0 or targetExcludeWhenInQS not in QSPart)):
            headers = list(requestInfo.getHeaders()) #python list rather than java arraylist
            msgBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
            msg = helpers.bytesToString(msgBody)
            fullHeadersBody = helpers.bytesToString(messageInfo.getRequest())

            # finding all parameters / exclude file uploads / sort on key name
            allParams = ""
            allParamsDict = {} # we can't work with Java ArrayList easily so we convert it to a Python dictionary
            content_type= readHeader(headers,"content-type",False).lower()
            isMultipart = False
            if "multipart" in content_type:
                isMultipart = True
            for p in allParamsArray:
                # There is no signing on xml or json parameters! Therefore, we should use QueryString only if that's the case
                if (p.getType() == IParameter.PARAM_BODY and not isMultipart) or p.getType() == IParameter.PARAM_URL:
                    allParamsDict[urllib.unquote(p.getName()).decode('utf8')] = urllib.unquote(p.getValue()).decode('utf8')
                elif p.getType() == IParameter.PARAM_BODY or p.getType() == IParameter.PARAM_MULTIPART_ATTR:
                    allParamsDict[p.getName()] = p.getValue()
            print sorted(allParamsDict.items(), key=lambda x: x[0].lower())
            matchFileParamNameObj = re.search(r'form\-data;\s*name\s*=\s*"([^"]+)";\s*filename\s*=', msg, re.M|re.I) # finding file param names
            for key, value in sorted(allParamsDict.items(), key=lambda x: x[0].lower()):
                excluded = False
                if matchFileParamNameObj:
                    for fileParamName in matchFileParamNameObj.groups():
                        if key == fileParamName or key == "filename":
                            excluded = True
                if not excluded:
                    allParams = allParams + "&" + key + "=" + value
            if len(allParams) > 0:
                allParams = allParams[1:]
                
            #finding file params and their values (sha512 base64 encoded)
            filePart = ""
            matchBoundaryObj = re.search( r'Content-Type:.*boundary=([^\r\n]+)', fullHeadersBody, re.I)
            if matchFileParamNameObj and matchFileParamNameObj.groups():
                boundary = matchBoundaryObj.group(1)
                print "boundary=" + boundary
                matchFilenameValueObj = re.findall(r'(form\-data;[^\r\n]+filename\s*="([^"]+)"([\r]{0,1}[\n]{0,1}[^\r\n]+)+(\r\n|\r|\n){2}([\s\S]*)\r\n\-\-)'+boundary, fullHeadersBody, re.M|re.I|re.U)
                allFilesDict = {}
                for fileParamName in matchFilenameValueObj:
                    allFilesDict[fileParamName[1]]=base64.b64encode(hashlib.sha512(helpers.stringToBytes(fileParamName[4])).digest())
                    
                for key, value in sorted(allFilesDict.items(), key=lambda x: x[0].lower()):
                    filePart = filePart + "&" + key + "=" + value
                
                if len(filePart) > 0:
                    filePart = filePart[1:]
                
            # creating timestampe
            # timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]+"Z"
            # instead of using miliseconds, I use random numbers to make it really random!
            randStr = str(random.randint(100,999))
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.")+randStr+"Z"
            

            # adding/replacing timestamp in headers
            headers = overwriteHeader(headers, 'Timestamp: ' + xstr(timestamp))
            
            # adding/replacing api-username and api-usertoken in headers
            headers = overwriteHeader(headers, 'api-username: ' + xstr(domain) + "\\"  + xstr(username))
            headers = overwriteHeader(headers, 'api-usertoken: ' + xstr(usertoken))
            
            # creating the message to sign - no file
            messageToSign = '{method}\n{timestamp}\n{path}\n{querystring}\n{file}'.format(method=xstr(requestInfo.getMethod()),timestamp=xstr(timestamp),path=xstr(relPath),querystring=xstr(allParams),file=xstr(filePart))
            messageToSign = messageToSign.lower()
            print messageToSign
            # Hashing the secret token
            secretTokenHash = base64.b64encode(hashlib.sha512(apiSecret).digest())
            print "secretTokenHash: "+secretTokenHash
            
            # Creating the signature
            h = hmac.new(secretTokenHash.upper(), messageToSign, hashlib.sha256)
            signature = base64.b64encode(h.digest())
            print "signature: " + xstr(signature)
            headers = overwriteHeader(headers, 'Authentication: {apikey}:{signature}'.format(apikey=xstr(apiKey),signature=xstr(signature)))
            print headers
            message = helpers.buildHttpMessage(headers, msgBody)
            messageInfo.setRequest(message)
print "scripter ends here..."

# ***********************************************
import sys

# Provides introspection into the Python Scripter API.

apis = ('extender', 'callbacks', 'helpers', 'toolFlag', 'messageIsRequest', 'messageInfo')
funcs = (type, dir)

if messageIsRequest:
    for api in apis:
        print('\n{}:\n{}'.format(api, '='*len(api)))
        for func in funcs:
            print('\n{}:\n'.format(func.__name__))
            try:
                print(func(locals()[api]))
            except Exception as e:
                print(func(globals()[api]))

# ***********************************************

from pyscripter_utils import CustomIssue
import re
import sys

# Adds custom passive audit checks.
# Requires pyscripter_utils.py to be loaded with Burp.

if not messageIsRequest:
    if toolFlag in (callbacks.TOOL_PROXY,):
        if callbacks.isInScope(messageInfo.getUrl()):
            response = messageInfo.getResponse()

            # Checks for autocomplete on text form fields.
            results = re.findall(r'(<input [^>]*>)', response)
            for result in results:
                if re.search(r'''type=['"]text['"]''', result) and not re.search(r'autocomplete', result):
                    issue = CustomIssue(
                        BasePair=messageInfo,
                        IssueName='Text field with autocomplete enabled',
                        IssueDetail='The following text field has autocomplete enabled:\n\n<ul><li>' + result.replace('<', '&lt;').replace('>', '&gt;') + '</li></ul>',
                        Severity='Low',
                    )
                    callbacks.addScanIssue(issue)

            # Checks for verbose headers.
            bad_headers = ('server', 'x-powered-by', 'x-aspnet-version')
            headers = helpers.analyzeResponse(messageInfo.getResponse()).getHeaders()
            for header in headers:
                name = header.split(':')[0]
                if name.lower() in bad_headers:
                    issue = CustomIssue(
                        BasePair=messageInfo,
                        IssueName='Verbose header',
                        IssueDetail='The following HTTP response header may disclose sensitive information:\n\n<ul><li>' + header + '</li></ul>',
                        Severity='Low',
                    )
                    callbacks.addScanIssue(issue)

# ***********************************************

import re
import sys

# Extracts multiple instances of a REGEX capture group from responses.

pattern = r'<regex>'

if not messageIsRequest:
    response = messageInfo.getResponse()
    matches = re.findall(pattern, response)
    for match in matches:
        print(match)

# ***********************************************

import re

# Replaces the body of a response from a matched URL.
# Great for swapping SPA UI build definitions between user roles.

url_pattern = r'<regex for response URL>'
body = r'''<new body>'''

if not messageIsRequest:
    url = messageInfo.url.toString()
    if re.search(url_pattern, url):
        response = messageInfo.getResponse()
        headers = helpers.analyzeResponse(response).getHeaders()
        new_response = helpers.buildHttpMessage(headers, helpers.stringToBytes(body))
        messageInfo.setResponse(new_response)
        print('Response replaced from: {}'.format(url))

# ***********************************************

import sys
import re
from hashlib import md5

# Overwrites a previously attempted password signature to bypass client-side anti-automation logic.
# Not sure why anyone would do this, but they did, or this wouldn't be a thing.

if messageIsRequest:
    if toolFlag in (callbacks.TOOL_INTRUDER,):
        request = helpers.bytesToString(messageInfo.getRequest())
        if '&nonce=' in request:
            nonce = re.search(r'&nonce=([^&]*)', request).group(1)
            password = re.search(r'&password=([^&]*)', request).group(1)
            token = md5(password+nonce).hexdigest()
            orig_token = re.search(r'&token=([^\s]*)', request).group(1)
            request = request.replace(orig_token, token)
            messageInfo.setRequest(helpers.stringToBytes(request))

# ***********************************************

# Fetches and replaces a Bearer token in the current request.

def get_new_token():

    url = '<url>'
    username = '<username>'
    password = '<password>'

    import urllib2
    import json

    data = {
        'username': username,
        'password': password,
    }
    req = urllib2.Request(url)
    req.add_header('Content-Type', 'application/json')
    response = urllib2.urlopen(req, json.dumps(data))
    data = json.load(response)
    token = data.get('token', '')
    print('New token obtained.')
    return token

# only apply to repeater
if toolFlag == callbacks.TOOL_REPEATER:
    # only apply to requests
    if messageIsRequest:
        # obtain a new token
        new_token = get_new_token()
        # remove any existing Authorization header
        request = helpers.analyzeRequest(messageInfo)
        headers = request.getHeaders()
        for header in headers:
            if header.startswith('Authorization'):
                headers.remove(header)
                break
        # add a new Authorization header with the new token
        headers.add('Authorization: Bearer {}'.format(new_token))
        body = messageInfo.getRequest()[request.getBodyOffset():]
        new_request = helpers.buildHttpMessage(headers, body)
        messageInfo.setRequest(new_request)
        print('Token replaced.')

# ***********************************************

# Removes authentication information from the current request.

header_names = ['Cookie', 'Authorization']

# only apply to target
if toolFlag == callbacks.TOOL_TARGET:
    # only apply to requests
    if messageIsRequest:
        request = helpers.analyzeRequest(messageInfo)
        headers = request.getHeaders()
        for header_name in header_names:
            for header in headers:
                if header.startswith(header_name):
                    headers.remove(header)
                    break
        body = messageInfo.getRequest()[request.getBodyOffset():]
        new_request = helpers.buildHttpMessage(headers, body)
        messageInfo.setRequest(new_request)
        print('Headers removed: {}'.format(', '.join(header_names)))

##
##
