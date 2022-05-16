##
####################
https://www.thepythoncode.com/article/make-a-xss-vulnerability-scanner-in-python
####################
##

Cross-site scripting (also known as XSS) is a web security vulnerability that allows an attacker to compromise the interactions that users have with a vulnerable web application. The attacker aims to execute scripts in the victim's web browser by including malicious code in a normal web page. These flaws that allow these types of attacks are quite widespread in web applications that has user input.

In this tutorial, you will learn how you can write a Python script from scratch to detect this vulnerability.

RELATED: How to Build a SQL Injection Scanner in Python.

We gonna need to install these libraries:

pip3 install requests bs4
Alright, let's get started:


import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
Since this type of web vulnerabilities are exploited in user inputs and forms, as a result, we need to fill out any form we see by some javascript code. So, let's first make a function to get all the forms from the HTML content of any web page (grabbed from this tutorial):

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")
Now this function returns a list of forms as soup objects, we need a way to extract every form details and attributes (such as action, method and various input attributes), the below function does exactly that:

def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    action = form.attrs.get("action").lower()
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details
After we got the form details, we need another function to submit any given form:

def submit_form(form_details, url, value):
    """
    Submits a form given in `form_details`
    Params:
        form_details (list): a dictionary that contain form information
        url (str): the original URL that contain that form
        value (str): this will be replaced to all text and search inputs
    Returns the HTTP Response after form submission
    """
    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None, 
            # then add them to the data of form submission
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)
The above function takes form_details which is the output of get_form_details() function we just wrote as an argument, that contains all form details, it also accepts the url in which the original HTML form was put, and the value that is set to every text or search input field.


After we extract the form information, we just submit the form using requests.get() or requests.post() methods (depending on the form method).

Now that we have ready functions to extract all form details from a web page and submit them, it is easy now to scan for the XSS vulnerability now:

def scan_xss(url):
    """
    Given a `url`, it prints all XSS vulnerable forms and 
    returns True if any is vulnerable, False otherwise
    """
    # get all the forms from the URL
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<Script>alert('hi')</scripT>"
    # returning value
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            pprint(form_details)
            is_vulnerable = True
            # won't break because we want to print available vulnerable forms
    return is_vulnerable
Here is what the function does:

Given a URL, it grabs all the HTML forms and then print the number of forms detected.
It then iterates all over the forms and submit the forms with putting the value of all text and search input fields with a Javascript code.
If the Javscript code is injected and successfully executed, then this is a clear sign that the web page is XSS vulnerable.
Let's try this out:

if __name__ == "__main__":
    url = "https://xss-game.appspot.com/level1/frame"
    print(scan_xss(url))
This is an intended XSS vulnerable website, here is the result:

[+] Detected 1 forms on https://xss-game.appspot.com/level1/frame.
[+] XSS Detected on https://xss-game.appspot.com/level1/frame
[*] Form details:
{'action': '',
 'inputs': [{'name': 'query',
             'type': 'text',
             'value': "<Script>alert('hi')</scripT>"},
            {'name': None, 'type': 'submit'}],
 'method': 'get'}
True

As you may see, the XSS vulnerability is successfully detected, now this code isn't perfect for any XSS vulnerable website, if you want to detect XSS for a specific website, you may need to refactor this code for your needs. The goal of this tutorial is to make you aware of this kind of attacks and to basically learn how to detect XSS vulnerabilities.

If you really want advanced tools to detect and even exploit XSS, there are a lot out there, XSStrike is such a great tool and it is written purely in Python !

Alright, we are done with this tutorial, you can extend this code by extracting all website links and run the scanner on every link you find, this is a great challenge for you !

Learn also: How to Make a Port Scanner in Python using Socket Library.


Happy Coding ♥

Sharing is caring!

 




Read Also

How to Make a Subdomain Scanner in Python
How to Make a Subdomain Scanner in Python
Learning how to build a Python script to scan for subdomains of a given domain using requests library.

How to Make a Network Scanner using Scapy in Python
How to Make a Network Scanner using Scapy in Python
Building a simple network scanner using ARP requests and monitor the network using Scapy library in Python.

How to Build a SQL Injection Scanner in Python
How to Build a SQL Injection Scanner in Python
Learn how to write a simple Python script to detect SQL Injection vulnerability on web applications using requests and BeautifulSoup in Python.


Comment panel

kompot 2 years ago
I get 3 errors when i run the code. The first is the last line print(xss_scan(url), the second is in the scan_xss() function: form_details = get_form_details(form), and the third is in the get_form_details() function: for input_tag in form.attrs.get("input"). I think they are all because of NoneType?


Abdou Rockikz a year ago
Hello Kompot, try to debug the code, I think there isn't any input tag in that form, can you provide the whole error traceback and the target url?
If you want, contact us here: https://www.thepythoncode.com/contact 


Ben 11 months ago
Hi, I’ve been scrolling your website the last two days, lot of good tutorials are on here.

Can you kindly contact me, I need to defend my thesis and I’m to build a vulnerability scanner website. Tbh, I am finding it difficult to get started, I’ll love to ask you couple questions for guileless. Deadline is 17 of this month


Abdou Rockikz 10 months ago
Hi Ben,
Really sorry for not getting back to you earlier, you can always contact me here: https://www.thepythoncode.com/contact 
The comment queue is usually slower because I have a lot of comments to respond to.
The XSS scanner of this tutorial works great, you can always integrate it into your web app.


Noob 4 months ago
Hello Abdou Rockikz,

How can we change the script to scan a list of URLs? input from a text file.

thanks


Abdou Rockikz 4 months ago
Hey there,
Since we already have a function, it's too simple now. If you have a list of urls.txt, you can use the below code:
urls = open("urls.txt").read().splitlines()
for url in urls:
  if scan_xss(url):
    print(url, "is vulnerable")
  else:
    print(url, "is not vulnerable")

Hope this helps.

#######################
##
##
