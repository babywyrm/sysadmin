


# Modern `curl` Usage with GitHub’s API

`curl` is a powerful command-line tool for making HTTP requests. This guide covers the most common and modern ways to use `curl` with the GitHub API and other APIs.

---

## Table of Contents

- [Basic GET Request](#basic-get-request)
- [Include HTTP Headers](#include-http-headers)
- [Authentication](#authentication)
- [POST JSON Data](#post-json-data)
- [Read Data from a File](#read-data-from-a-file)
- [Downloading Files](#downloading-files)
- [Inspecting Headers](#inspecting-headers)
- [Common HTTP Methods](#common-http-methods)
- [Form Data (Legacy APIs)](#form-data-legacy-apis)
- [Handling HTTPS](#handling-https)
- [Following Redirects](#following-redirects)
- [Output Formatting](#output-formatting)
- [Useful Options](#useful-options)
- [Best Practices](#best-practices)
- [Resources](#resources)
- [Full Example: List Your GitHub Repositories](#full-example-list-your-github-repositories)

---

## Basic GET Request

```bash
curl https://api.github.com/users/octocat
```

---

## Include HTTP Headers

Include HTTP response headers in the output:

```bash
curl -i https://api.github.com/users/octocat
```

Set custom headers (e.g., Accept, Content-Type):

```bash
curl -H "Accept: application/vnd.github+json" https://api.github.com/users/octocat
```

---

## Authentication

**Recommended:** Use a [GitHub personal access token](https://github.com/settings/tokens) (never your password).

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" https://api.github.com/user
```

Or, using basic auth (deprecated):

```bash
curl -u "username:token" https://api.github.com/user
```

---

## POST JSON Data

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -H "Content-Type: application/json" \
  -d '{"description":"Created via API","public":true,"files":{"file1.txt":{"content":"Demo"}}}' \
  https://api.github.com/gists
```

---

## Read Data from a File

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d @data.json \
  https://api.github.com/gists
```

---

## Downloading Files

- To standard output:
  ```bash
  curl https://www.google.com/robots.txt
  ```
- To a file (use remote filename):
  ```bash
  curl -O https://www.google.com/robots.txt
  ```
- To a specific filename:
  ```bash
  curl -o myrobots.txt https://www.google.com/robots.txt
  ```

---

## Inspecting Headers

- Show only headers:
  ```bash
  curl -I https://api.github.com/
  ```
- Verbose output (headers + debug info):
  ```bash
  curl -v https://api.github.com/
  ```

---

## Common HTTP Methods

- GET (default):  
  `curl https://api.github.com/`
- POST:  
  `curl -X POST ...`
- PUT:  
  `curl -X PUT ...`
- DELETE:  
  `curl -X DELETE ...`
- PATCH:  
  `curl -X PATCH ...`

---

## Form Data (Legacy APIs)

```bash
curl -F "name=value" -F "file=@path/to/file.txt" https://api.example.com/upload
```

---

## Handling HTTPS

Ignore SSL certificate errors (not recommended for production):

```bash
curl --insecure https://api.github.com/
```

---

## Following Redirects

```bash
curl -L https://github.com/
```

---

## Output Formatting

Pretty-print JSON (requires [`jq`](https://stedolan.github.io/jq/)):

```bash
curl ... | jq
```

---

## Useful Options

| Option         | Description                                 |
|----------------|---------------------------------------------|
| `-i`           | Include response headers in output          |
| `-H`           | Add custom header                           |
| `-d`           | Send data (implies POST)                    |
| `-X`           | Specify HTTP method                         |
| `-o`           | Write output to file                        |
| `-O`           | Write output to file (remote name)          |
| `-L`           | Follow redirects                            |
| `-u`           | Basic auth (username:password or token)     |
| `-v`           | Verbose/debug output                        |
| `-s`           | Silent mode (no progress or errors)         |

---

## Best Practices

- **Use tokens, not passwords** for authentication.
- **Set `Accept` and `Content-Type` headers** for JSON APIs.
- **Never expose secrets** in command history or scripts.
- **Pipe to `jq`** for readable JSON output.
- **Check API docs** for required headers and request formats.

---

## Resources

- [GitHub REST API Docs](https://docs.github.com/en/rest)
- [curl Official Manual](https://curl.se/docs/manpage.html)
- [jq JSON Processor](https://stedolan.github.io/jq/)

---

## Full Example: List Your GitHub Repositories

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Accept: application/vnd.github+json" \
     https://api.github.com/user/repos | jq
```




##
##

An introduction to [`curl`](http://curl.haxx.se/) using [GitHub's API](https://developer.github.com/guides/getting-started/#overview).





snippets
curl
ダウンロード
標準出力へ出力
curl https://www.google.com/robots.txt
規定のファイル名へ出力
curl -O https://www.google.com/robots.txt
ファイル名を指定して出力
curl -o google-robots.txt https://www.google.com/robots.txt
ヘッダの確認
curlでヘッダを見る方法いろいろ
verbose
verboseな情報はSTDERRに出力される

curl --verbose https://gist.github.com/
curl --verbose https://gist.github.com/ 1> /dev/null
include
curl --include https://gist.github.com/
dump-header
–dump-header FILENAME

curl --dump-header - https://gist.github.com/
trace
–trace FILENAME

curl --trace - https://gist.github.com/
curl --trace-ascii - https://gist.github.com/
さまざまなメソッドでの接続
GET/POST/PUT/DELETE
-X オプションでメソッド名 GET/POST/PUT/DELETE を指定すればよい

curl -X PUT -d 'example[foo]=bar' -d 'example[jane]=doe' http://example.com/api/1/example/1.json
cURL で GET/POST/PUT/DELETE
HEAD
curl --head https://gist.github.com/
POST
フォーム
curl -F "name1=value1" -F "name2=value2" http://yourdomain/execute.script

curl -F "name1=value1" -F "name2=value2" -F "profile_icon=@path/to/file.png" -F "zip_file=@path/to/zipfile.zip" http://yourdomain/execute.script
JSONをBODYにいれてPOST
curl -v \
  -H 'Accept: application/json' \
  -H 'Content-type: application/json' \
  -X POST \
  -d '{"key1":"value1"}' \
  https://endpoint/
curlコマンドから HTTP POST する方法
BASIC認証
curl --basic --user user:password http://hostname/
SSL/TLS
証明書を検証しない
curl --insecure https://gist.github.com/
ヘッダの変更
User-Agent書き換え
-A, –user-agent

Referer書き換え
-e, –referer

追加リクエストヘッダ
-H, –header

curl -H "X-First-Name: Joe" http://192.168.0.1/

##
##
##

## Basics

Makes a basic GET request to the specifed URI

    curl https://api.github.com/users/caspyin

Includes HTTP-Header information in the output

    curl --include https://api.github.com/users/caspyin

Pass user credential to basic auth to access protected resources like a users starred gists, or private info associated with their profile

    curl --user "caspyin:PASSWD" https://api.github.com/gists/starred
    curl --user "caspyin:PASSWD" https://api.github.com/users/caspyin

Passing just the username without the colon (`:`) will cause you to be prompted for your account password. This avoids having your password in your command line history

    curl --user "caspyin" https://api.github.com/users/caspyin


## POST

Use the `--request` (`-X`) flag along with `--data` (`-d`) to POST data

    curl --user "caspyin" --request POST --data '{"description":"Created via API","public":"true","files":{"file1.txt":{"content":"Demo"}}' https://api.github.com/gists
    
    curl --user "caspyin" -X POST --data '{"description":"Created via API","public":"true","files":{"file1.txt":{"content":"Demo"}}' https://api.github.com/gists

Of course `--data` implies POST so you don't have to also specify the `--request` flag

    curl --user "caspyin" --data '{"description":"Created via API","public":"true","files":{"file1.txt":{"content":"Demo"}}' https://api.github.com/gists

Here is an example that uses the old GitHub API (v2). You can use multiple `--data` flags

    curl --data "login=caspyin" --data "token=TOKEN" https://github.com/api/v2/json/user/show/caspyin

The post data gets combined into one so you can also just combine them yourself into a single `--data` flag

    curl --data "login=caspyin&token=TOKEN" https://github.com/api/v2/json/user/show/caspyin

You can tell curl to read from a file (`@`) to POST data

    curl --user "caspyin" --data @data.txt https://api.github.com/gists 

Or it can read from STDIN (`@-`)

    curl --user "caspyin" --data @- https://api.github.com/gists
    {
      "description":"Test",
      "public":false,
      "files": {
        "file1.txt": {
          "content":"Demo"
        }
      }
    }
    end with ctrl+d

More POST examples [here](https://gist.github.com/joyrexus/ec24e588af35c64266ab), including examples of file uploading.  For guidance on when to POST with `--data` vs `--form`, see [this gist](https://gist.github.com/joyrexus/524c7e811e4abf9afe56).


## Headers

Often when POSTing data you'll need to add headers for things like auth tokens or setting the content type. You can set a header using `-H`.

    curl -H "Content-Type: application/json" -H "authToken: 349ab29a-xtab-423b-a5hc-5623bc39b8c8" --data '{}' https://api.example.com/endpoint


## Dealing with HTTPS

If an API doens't have an SSL cert but is using HTTPS you can tell curl to ignore the security by using `--insecure`. Be warned this is a very **"insecure"** thing to do and is only listed here for "educational purposes".

    curl --insecure https://api.example.com/endpoint

For my own reference mostly, here is where I first learned about using `--insecure` https://github.com/wayneeseguin/rvm/issues/1684


## OAuth

The first thing to know is that your API Token (found in https://github.com/settings/admin) is not the same token used by OAuth. They are different tokens and you will need to generate an OAuth token to be authorized.

Follow the API's instructions at http://developer.github.com/v3/oauth/ under the sections "Non-Web Application Flow" and "Create a new authorization" to become authorized.

Note: Use Basic Auth once to create an OAuth2 token http://developer.github.com/v3/oauth/#oauth-authorizations-api

    curl https://api.github.com/authorizations \
    --user "caspyin" \
    --data '{"scopes":["gist"],"note":"Demo"}'

This will prompt you for your GitHub password and return your OAuth token in the response. It will also create a new Authorized application in your account settings https://github.com/settings/applications

Now that you have the OAuth token there are two ways to use the token to make requests that require authentication (replace "OAUTH-TOKEN" with your actual token)

    curl https://api.github.com/gists/starred?access_token=OAUTH-TOKEN
    curl -H "Authorization: token OAUTH-TOKEN" https://api.github.com/gists/starred

List the authorizations you already have

    curl --user "caspyin" https://api.github.com/authorizations


## Resources

* [curl tutorial](http://curl.haxx.se/docs/httpscripting.html) - the official tutorial
* [httpbin](http://httpbin.org) - web service to throw http requests at (e.g., with curl) for testing
* [httpie](http://httpie.org/) - a python-based utility that's intended to be
  a more user-friendly replacement for `curl`
* [postman](https://www.getpostman.com/) - web app for building and testing http requests




Common Options
-#, --progress-bar Make curl display a simple progress bar instead of the more informational standard meter.

-b, --cookie <name=data> Supply cookie with request. If no =, then specifies the cookie file to use (see -c).

-c, --cookie-jar <file name> File to save response cookies to.

-d, --data <data> Send specified data in POST request. Details provided below.

-f, --fail Fail silently (don't output HTML error form if returned).

-F, --form <name=content> Submit form data.

-H, --header <header> Headers to supply with request.

-i, --include Include HTTP headers in the output.

-I, --head Fetch headers only.

-k, --insecure Allow insecure connections to succeed.

-L, --location Follow redirects.

-o, --output <file> Write output to . Can use --create-dirs in conjunction with this to create any directories specified in the -o path.

-O, --remote-name Write output to file named like the remote file (only writes to current directory).

-s, --silent Silent (quiet) mode. Use with -S to force it to show errors.

-v, --verbose Provide more information (useful for debugging).

-w, --write-out <format> Make curl display information on stdout after a completed transfer. See man page for more details on available variables. Convenient way to force curl to append a newline to output: -w "\n" (can add to ~/.curlrc).

-X, --request The request method to use.

POST
When sending data via a POST or PUT request, two common formats (specified via the Content-Type header) are:

application/json
application/x-www-form-urlencoded
Many APIs will accept both formats, so if you're using curl at the command line, it can be a bit easier to use the form urlencoded format instead of json because

the json format requires a bunch of extra quoting
curl will send form urlencoded by default, so for json the Content-Type header must be explicitly set
This gist provides examples for using both formats, including how to use sample data files in either format with your curl requests.

curl usage
For sending data with POST and PUT requests, these are common curl options:

request type

-X POST
-X PUT
content type header

-H "Content-Type: application/x-www-form-urlencoded"

-H "Content-Type: application/json"

data

form urlencoded: -d "param1=value1&param2=value2" or -d @data.txt
json: -d '{"key1":"value1", "key2":"value2"}' or -d @data.json
Examples
POST application/x-www-form-urlencoded
application/x-www-form-urlencoded is the default:

curl -d "param1=value1&param2=value2" -X POST http://localhost:3000/data
explicit:

curl -d "param1=value1&param2=value2" -H "Content-Type: application/x-www-form-urlencoded" -X POST http://localhost:3000/data
with a data file

curl -d "@data.txt" -X POST http://localhost:3000/data
POST application/json
curl -d '{"key1":"value1", "key2":"value2"}' -H "Content-Type: application/json" -X POST http://localhost:3000/data
with a data file

curl -d "@data.json" -X POST http://localhost:3000/data
data.json
{
  "key1":"value1",
  "key2":"value2"
}
data.txt
param1=value1&param2=value2
package.json
{
  "name": "postdemo",
  "version": "1.0.0",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "body-parser": "^1.15.0",
    "express": "^4.13.4"
  }
}
server.js
var app = require('express')();
var bodyParser = require('body-parser');

app.use(bodyParser.json()); // for parsing application/json
app.use(bodyParser.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded

app.post('/data', function (req, res) {
  console.log(req.body);
  res.end();
});

app.listen(3000);
