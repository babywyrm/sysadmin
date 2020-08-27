#Declare your variables here

token = ""
### Above are vars / Below are py rules ###
## Advanved example for tracking a "CSRFtoken" token
#  * the new token length may be different from previous values
#  * makes use of Burp API to compose the request (this way "Content-Length" gets updated)

#Python rules go here
import re

if toolFlag == callbacks.TOOL_PROXY:
	exit()

if messageIsRequest:
	# Refresh the request: search if the body contains a token and replace it with the new/stored value
	log("\n Request - processing")

	# Request is decompose  in header and body
	requestInfo = helpers.analyzeRequest(messageInfo)
	#  headers are converted to a list
	headers = list(requestInfo.getHeaders())
	
	#  body is obtained in bytes and converted to string
	request_bytes = messageInfo.getRequest()
	body_bytes = request_bytes[requestInfo.getBodyOffset():]
	body = helpers.bytesToString(body_bytes)
	
	# Replace in body the old token with the new/stored one
	search = re.compile("CSRFtoken=([a-zA-Z0-9]*)")
	replace = "CSRFtoken="+token
	body = re.sub(search, replace, body)
	
	##Additional example: replace the token in CSRFtoken header
	# search = re.compile("CSRFtoken:([a-zA-Z0-9]*)")
	# replace = "CSRFtoken:"+token
	
	# for idx,header in enumerate(headers):
		# match = search.findall(header)
		# if match:
			# header = re.sub(search, replace, header)
			# headers[idx] = header
	
	# Build message from headers and body
	request_bytes = helpers.buildHttpMessage(headers, body)
	messageInfo.setRequest(request_bytes)

	
else:
	#Capture the new token: if the response contains a new value, capture it and stored it in a persistent variable
	log("\n Response - processing")

	response = helpers.bytesToString( messageInfo.getResponse() )
	search = re.compile("name=\"CSRFtoken\" value=\"([a-zA-Z0-9]*)\">")
	match = search.findall(response)

	if match:
		token = match[0]
		log("New token:")
		log(token)
	else:
		log("No token found!")
		
