

# Flask API Key Vulnerability: Partial Parameter Bypass

## Overview

This document describes a security vulnerability in Flask applications related to **API key handling** and **parameter comparison**. Specifically, 
it highlights the issue of bypassing an API key comparison using **improperly validated inputs**. This issue could lead to **unauthorized access** 
if the application logic is not implemented with proper validation.

## Problem Explanation

The issue arises from improper handling of **query parameters** in Flask, specifically when comparing values like API keys using `==` 
or any form of comparison that doesn't take edge cases into account. The vulnerability is often overlooked in source code reviews due to the misleading simplicity 
of the code, but it can have serious security implications if exploited.

### Example of Vulnerable Code:

```
python
from flask import Flask, request

app = Flask(__name__)

ENV_API_KEY = "secret123"

@app.route('/very_secure')
def very_secure():
    # Get API key from query parameters
    api_key = request.args.get('api', '')

    # Type checking
    if not isinstance(api_key, str):
        return "Invalid API key format", 400
        
    # Length checking
    if not 8 <= len(api_key) <= 64:
        return "Invalid API key length", 400
        
    # Secure comparison using hmac
    if api_key and compare_digest(api_key, ENV_API_KEY):
        return "Access granted"
    return "Access denied", 401
```

Vulnerability Overview
request.args.get('api'): This is used to retrieve the api query parameter from the URL. 
If the api parameter is not present, it returns None, but in this example, the default fallback is an empty string ("").

Partial Input Handling:

Expected Behavior: The API key is expected to match exactly with ENV_API_KEY (i.e., secret123).

However, since request.args.get('api', '') will default to an empty string ("") if no api parameter is provided, there is a potential issue where partial or malformed inputs could bypass the authentication mechanism.

Loose Comparison:

The comparison api_key == ENV_API_KEY or any string comparison using == might not account for edge cases properly.

This can result in unexpected behavior, especially when a malformed value like lolapi=test is passed, potentially bypassing the check.

Why This Happens
Lack of Proper Type Checking:

The vulnerability occurs because request.args.get('api') might return a non-string value like None, which would result in a misleading comparison against ENV_API_KEY.

Partial Matching:

An attacker might exploit this by sending incomplete or malformed API keys such as lolapi=test to bypass the logic. 
This doesn't immediately throw an error but leads to improper handling of the request.

Timing Attacks:

If you were to use == for string comparison, an attacker could attempt a timing attack, 
where the application could leak information about whether the key was valid or not. This is mitigated by using compare_digest, which performs a constant-time comparison.

How to Mitigate This Vulnerability
1. Use Secure Comparison (compare_digest)
Using hmac.compare_digest() or a similar secure method prevents timing attacks by ensuring that the comparison takes the same time regardless of the string content.
This is an important security feature when comparing sensitive data like API keys.

3. Validate Input Before Comparison
Before performing any comparison, ensure that the API key is a valid string of a correct length and format. Here's a more secure version of the code:

Fixed Code Example:

```
from flask import Flask, request
from hmac import compare_digest

app = Flask(__name__)

ENV_API_KEY = "secret123"

@app.route('/very_secure')
def very_secure():
    # Get API key with default value
    api_key = request.args.get('api', '')
    
    # Type checking
    if not isinstance(api_key, str):
        return "Invalid API key format", 400
        
    # Length checking
    if not 8 <= len(api_key) <= 64:
        return "Invalid API key length", 400
        
    # Secure comparison using hmac
    if api_key and compare_digest(api_key, ENV_API_KEY):
        return "Access granted"
    return "Access denied", 401

```



Key Fixes:


Type Checking: Ensure api_key is always a valid string.

Length Validation: Make sure the API key has a length within the expected range (e.g., between 8 and 64 characters).

Using compare_digest: Secure comparison to prevent timing attacks.

