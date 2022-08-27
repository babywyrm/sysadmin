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
