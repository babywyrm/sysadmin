
# Burp REST API

########################
https://github.com/anandtiwarics/python-burp-rest-api
########################
<br>
<br>


A burp python RESTFul API package.

## Requirements

* Burp Suite Professional

## Quick Start

- Install with pip: ``pip install PyBurprestapi``
- Build locally: ``python setup.py build``


## Example

<pre>

    # import the package
    from PyBurprestapi import burpscanner

    # setup burp connection
    host = 'http://127.0.0.1:1337/'
    
    # Burp API key
    key = '6dHyTmUB9t474JuvVAgpP7ofc2u4N2Mr'

    # importing host and key
    bi = burpscanner.BurpApi(host, key)
    
    #
    data = '{"urls":["http://zero.webappsecurity.com"]}'

    # scan Launch
    response = bi.scan(data)

    # Get the response message
    print response.message
    
    # Get response header (Scan ID found in Location)
    print response.response_headers

</pre>


## Bugs and Feature Requests

If you Found bug or have a feature request? Please open a new issue (https://github.com/anandtiwarics/python-burp-rest-api/issues).
