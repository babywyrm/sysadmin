Parse a JSON response using Python requests library
Updated on: May 14, 2021 | 2 Comments

In this article, we will learn how to parse a JSON response using the requests library. For example, we are using a requests library to send a RESTful GET call to a server, and in return, we are getting a response in the JSON format, let’s see how to parse this JSON data in Python.

We will parse JSON response into Python Dictionary so you can access JSON data using key-value pairs. Also, you can prettyPrint JSON in the readable format.

Further Reading:

Solve Python JSON Exercise to practice Python JSON skills
The response of the GET request contains information we called it as a payload. We can find this information in the message body. Use attributes and methods of Response to view payload in the different formats.


We can access payload data using the following three methods of a requests module.

response.content used to access payload data in raw bytes format.
response.text: used to access payload data in String format.
response.json() used to access payload data in the JSON serialized format.
The JSON Response Content
The requests module provides a builtin JSON decoder, we can use it when we are dealing with JSON data. Just execute response.json(), and that’s it. response.json() returns a JSON response in Python dictionary format so we can access JSON using key-value pairs.

You can get a 204 error In case the JSON decoding fails. The response.json() raises an exception in the following scenario.


The response doesn’t contain any data.
The response contains invalid JSON
You must check response.raise_for_status() or response.status_code before parsing JSON because the successful call to response.json() does not indicate the success of the request.

In the case of HTTP 500 error, some servers may return a JSON object in a failed response (e.g., error details with HTTP 500). So you should execute response.json() after checking response.raise_for_status() or check response.status_code.

Let’s see the example of how to use response.json() and parse JSON content.

In this example, I am using httpbin.org to execute a GET call. httpbin.org  is a web service that allows test requests and responds with data about the request. You can use this service to test your code.


Sponsored Video
Watch to learn more
SPONSORED BY BMW: DEALERSHIPS
import requests
from requests.exceptions import HTTPError

try:
    response = requests.get('https://httpbin.org/get')
    response.raise_for_status()
    # access JSOn content
    jsonResponse = response.json()
    print("Entire JSON response")
    print(jsonResponse)

except HTTPError as http_err:
    print(f'HTTP error occurred: {http_err}')
except Exception as err:
    print(f'Other error occurred: {err}')

Output:

Entire JSON response
{'args': {}, 'headers': {'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate', 'Host': 'httpbin.org', 'User-Agent': 'python-requests/2.21.0'}, 'origin': '49.35.214.177, 49.35.214.177', 'url': 'https://httpbin.org/get'}
Iterate JSON Response

Let’s see how to iterate all JSON key-value pairs one-by-one.

print("Print each key-value pair from JSON response")
    for key, value in jsonResponse.items():
        print(key, ":", value)
Output:

Print each key-value pair from JSON response
args : {}
headers : {'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate', 'Host': 'httpbin.org', 'User-Agent': 'python-requests/2.21.0'}
origin : 49.35.214.177, 49.35.214.177
url : https://httpbin.org/get
Access JSON key directly from the response using the key name

print("Access directly using a JSON key name")
print("URL is ")
print(jsonResponse["url"])
Output

URL is 
https://httpbin.org/get
Access Nested JSON key directly from response

print("Access nested JSON keys")
print("Host is is ")
print(jsonResponse["headers"]["Host"])
Output:

Access nested JSON keys
URL is 
httpbin.org
