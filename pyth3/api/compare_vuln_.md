

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


# Example, broken

```
from flask import Flask, request
import hashlib

app = Flask(__name__)

# Simulated sensitive environment variable for comparison
ENV_API_KEY = "secret123456789"

@app.route('/secure-endpoint', methods=['GET'])
def secure_endpoint():
    # Simulated user input from the query string
    api_key = request.args.get('api_key', '')

    # Check for valid length
    if not 16 <= len(api_key) <= 64:
        return "Invalid API key length", 400
    
    # Hashing the API key to mimic real-world behavior of sensitive comparisons
    hashed_api_key = hashlib.sha256(api_key.encode()).hexdigest()

    # Compare the hashed API key (vulnerable to timing attacks and incomplete checks)
    if hashed_api_key == ENV_API_KEY:
        return "Access granted", 200

    return "Access denied", 401

if __name__ == '__main__':
    app.run(debug=True)
```
Vulnerability Explanation
No Input Validation: The api_key is retrieved using request.args.get('api_key', ''), which defaults to an empty string ("") if the api_key parameter is not provided.
If the parameter is missing or empty, it will not be correctly compared to ENV_API_KEY.

Loose Comparison: The hashed_api_key == ENV_API_KEY comparison checks the hashed version of the API key against the environment variable.
If api_key is empty or incorrectly formatted, it can still pass the length check, and the comparison may fail silently, letting an attacker bypass the check.

Insecure Handling: The lack of more specific checks, such as ensuring the input is a non-empty string, leads to potential vulnerabilities.

Exploiting the Vulnerability
An attacker could bypass this check by providing a malformed API key like:

```
http://localhost:5000/secure-endpoint?api_key=
```
This would send an empty string ("") as the api_key, which would pass the length check, but since the comparison is loose, 
the application would fail to validate the key properly.



# And, fixed

```
from flask import Flask, request
import hashlib
import hmac

app = Flask(__name__)

# Simulated sensitive environment variable for comparison
ENV_API_KEY = "secret123456789"

@app.route('/secure-endpoint', methods=['GET'])
def secure_endpoint():
    # Simulated user input from the query string
    api_key = request.args.get('api_key', '').strip()  # Strip extra spaces

    # Validate input type and non-empty string
    if not isinstance(api_key, str) or not api_key:
        return "Invalid API key format", 400

    # Check for valid length
    if not 16 <= len(api_key) <= 64:
        return "Invalid API key length", 400
    
    # Hash the API key using SHA256
    hashed_api_key = hashlib.sha256(api_key.encode()).hexdigest()

    # Secure constant-time comparison (prevents timing attacks)
    if hmac.compare_digest(hashed_api_key, ENV_API_KEY):
        return "Access granted", 200

    return "Access denied", 401

if __name__ == '__main__':
    app.run(debug=True)
```


# Fixes and Improvements
Input Validation: The api_key is stripped of leading/trailing spaces and checked to ensure it is a non-empty string (if not isinstance(api_key, str) or not api_key).

Length Check: The length of the API key is validated to be between 16 and 64 characters, ensuring it meets the expected criteria.

Secure Hashing: The api_key is hashed using hashlib.sha256(), ensuring that we never directly store or compare raw API keys in a secure application.

Constant-Time Comparison: We use hmac.compare_digest() to ensure the comparison is constant-time, preventing attackers from leveraging timing attacks (where the time it takes to compare strings could leak information about the API key).

# Explaining the Fixed Code
Sanitized Input: We ensure that the api_key is a valid string and contains a value. The check if not isinstance(api_key, str) or not api_key: ensures that it is a non-empty string, rejecting any invalid or empty values before continuing.

Improved Length Check: The check for valid API key length ensures that only keys within a reasonable range (16–64 characters in this case) are accepted.
This mitigates the risk of empty or overly short API keys being accepted.

Secure Hashing: Instead of comparing raw API keys directly, we hash the api_key using hashlib.sha256() and then compare the hashed value to ENV_API_KEY. This is done to avoid storing or using plain-text keys directly in the comparison process.

Timing Attack Mitigation: By using hmac.compare_digest(), we ensure that the comparison of the hashed API key and the environment key happens in constant time, making it much harder for an attacker to infer details about the correct key based on timing variations.


