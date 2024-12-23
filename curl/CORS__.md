

##
#
https://reqbin.com/req/c-taimahsa/curl-cors-request
#
https://stackoverflow.com/questions/12173990/how-can-you-debug-a-cors-request-with-curl
#
https://www.zufallsheld.de/2024/09/28/til-how-to-test-CORS-on-the-command-line-with-curl/
@
##



1. Basic Tests
1.1 Preflight Check
CORS uses an OPTIONS request to check permissions before the actual request.

```
curl -X OPTIONS http://example.com/api/resource \
  -H "Origin: http://test-origin.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Content-Type" \
  -i
```
Expected Response:

Status Code: 204 No Content or 200 OK.
Headers:

```
Access-Control-Allow-Origin: http://test-origin.com
Access-Control-Allow-Methods: GET
Access-Control-Allow-Headers: Content-Type
```

1.2 Simple Request
Perform a basic GET request with an Origin header.

```
curl -X GET http://example.com/api/resource \
  -H "Origin: http://test-origin.com" \
  -i
```

Expected Response:

The response should include:
```
Access-Control-Allow-Origin: http://test-origin.com
```

2. Intermediate Tests
2.1 Custom Headers
Send a request with custom headers.

```
curl -X POST http://example.com/api/resource \
  -H "Origin: http://test-origin.com" \
  -H "X-Custom-Header: custom-value" \
  -H "Content-Type: application/json" \
  -d '{"key":"value"}' \
  -i
```

Expected Response:
```
If Access-Control-Allow-Headers is properly configured:

Access-Control-Allow-Headers: Content-Type, X-Custom-Header
```

2.2 Methods Not Allowed
Test with HTTP methods not permitted by CORS policy.

```
curl -X DELETE http://example.com/api/resource \
  -H "Origin: http://test-origin.com" \
  -i
```
Expected Response:

Status Code: 405 Method Not Allowed.
No Access-Control-Allow-Origin header should be present.


3. Advanced Tests
3.1 Origin Reflection
Test if the server reflects the Origin header.

```
curl -X GET http://example.com/api/resource \
  -H "Origin: http://untrusted-origin.com" \
  -i
```


Expected Behavior:

If reflection is disabled: No Access-Control-Allow-Origin header.
If reflection is enabled (potential security risk):


Access-Control-Allow-Origin: http://untrusted-origin.com
3.2 Wildcard Matching
Test with a wildcard (*) in the Access-Control-Allow-Origin header.

```
curl -X GET http://example.com/api/resource \
  -H "Origin: http://wildcard-test.com" \
  -i
```

Expected Behavior:

The server should return:
Access-Control-Allow-Origin: *
Note: Wildcards should not be used with credentials.
3.3 Credentials Handling
Test requests with credentials (cookies, Authorization headers).

```
curl -X GET http://example.com/api/resource \
  -H "Origin: http://trusted-origin.com" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Cookie: sessionId=abc123" \
  -i
```

Expected Behavior:

The server should return:

Access-Control-Allow-Origin: http://trusted-origin.com
Access-Control-Allow-Credentials: true


4. Error Scenarios
4.1 Invalid Origins
Send a request from an untrusted origin.
```
curl -X GET http://example.com/api/resource \
  -H "Origin: http://untrusted-origin.com" \
  -i
```

Expected Response:

No Access-Control-Allow-Origin header.
The request should fail.
4.2 Malformed Preflight Requests
Send a malformed preflight request.
```
curl -X OPTIONS http://example.com/api/resource \
  -H "Origin: malformed" \
  -H "Access-Control-Request-Method: PUT" \
  -i
```
Expected Behavior:

Status Code: 400 Bad Request or similar error.
5. Summary
This document demonstrates a comprehensive suite of curl commands to test various CORS configurations and edge cases.
Adjust the http://example.com URL to match your API endpoint and replace headers or methods as needed.

Notes:
Check for Misconfigurations: Misconfigured CORS can lead to vulnerabilities like unauthorized access or data leakage.
Avoid Reflective Policies: Always validate the Origin header against a trusted whitelist.
Be Careful with Wildcards: Avoid * in Access-Control-Allow-Origin for sensitive endpoints.



