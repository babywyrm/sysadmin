

```

one-liners
This is my cheat sheet for useful command line commands. Feel free to fork and/or PR if you have any additions.

Checking ports

Show port and PID - netstat -tulpn
Show process and listening port - ss -ltp
Show ports that are listening - ss -ltn
Show real time TCP and UDP ports - ss -stplu
Show all established connections lsof -i
Show listening connections - lsof -ni | grep LISTEN
Check a public IP

curl http://whatismyip.org/
curl ifconfig.me
curl icanhazip.com
Return the IP of an interface

ifconfig en0 | grep --word-regexp inet | awk '{print $2}'
ip add show eth0 | awk '/inet/ {print $2}' | cut -d/ -f1 | head -1
ip -br a sh eth0 | awk '{ print $3 }' (returns netmask)
ip route show dev eth0 | awk '{print $7}'
hostname -I (return ip only)
Replace all occurrences of string in a directory

Find and replace string - grep -rl "oldstring" ./ | xargs sed -i "" "s/oldstring/newstring/g"
Dig

Check domain with specific NS - dig <domain.com> @<ns-server>
Get NS records for a site - dig <domain.com> ns
Disk checks

Sort disk usage by most first - df -h | tail -n +2 | sort -rk5
Check the size of a top level dicectory - du -h --max-depth=1 /tmp/
Top 50 file sizes - du -ah / | sort -n -r | head -n 50
Show directory sizes (must not be in root directory) - du -sh *
Check disk usage per directory - du -h <dir> | grep '[0-9\.]\+G’
Look for growing directories - watch -n 10 df -ah
Ncurses based disk usage - ncdu -q
Colorized output of du - du -x --max-depth=1|sort -rn|awk -F / -v c=$COLUMNS 'NR==1{t=$1} NR>1{r=int($1/t*c+.5); b="\033[1;31m"; for (i=0; i<r; i++) b=b"#"; printf " %5.2f%% %s\033[0m %s\n", $1/t*100, b, $2}'|tac
Docker

Remove a group of images - docker images | grep "<none>" | awk '{print $3}' | xargs docker rmi
Remove all untagged containers - docker rm $(docker ps -aq --filter status=exited)
Remove all untagged images - docker rmi $(docker images -q --filter dangling=true)
Install on Ubuntu - curl -sSL https://get.docker.com/ubuntu/ | sudo sh
Get stats from all containers on a host - docker ps -q | xargs docker stats
Tail last 300 lines of logs for a container - docker logs --tail=300 -f <container_id>
Remove old (dangling) Docker volumes - docker volume rm $(docker volume ls -qf dangling=true)
Find

Exlcude directories in find - find /tmp -not \( -path /tmp/dir -prune \) -type p -o -type b
Git

Remove deleted files from repo - git rm $(git ls-files --deleted)
Reset git repo (dangerous) - git reset --hard HEAD
Reset and remove untracked changes in repo - git clean -xdf
Ignore certificates when cloning via HTTPS - git config --global http.sslVerify false
Pull changes and remove stale branches - git pull --prune
Grab the diff of a previous version of a file - git diff HEAD@{1} ../../production.hosts
Grab the diff of a staged change - git diff --cached <file>
Undo a commit to a branch - git reset --soft HEAD~1
View files changed in a commit - git log --stat
Pull latest changes stashing changes first - git pull --autostash
Make an empty commit (good for CI) - git commit --allow-empty -m "Trigger notification"
Grep

Look through all files in current dir for word “foo” - grep -R "foo” .
View last ten lines of output - grep -i -C 10 "invalid view source” /var/log/info.log
Display line number of message - grep -n “pattern” <file>
Iptables

Check nat rules for ip redirection - iptables -nvL -t nat
Nginx

Check installed modules - nginx -V
Pretty print installed modules - 2>&1 nginx -V | xargs -n1
Test a configuration without reloading - nginx -t
Stop all nginx processes - nginx -s stop
Start all nginx processes - nginx -s start
Restart all nginx processes - nginx -s restart
Realod nginx configuration (without restarting) - nginx -s reload
Nmap

Check single port on single host - nmap -p <port> <host/IP>
Intrusive port scan on a single host - nmap -sS <host/IP>
Top ten port on a single host - nmap --top-ports 10 <host/IP>
Password generation

Create hash from password - openssl passwd -crypt <password>
Generate random 8 character password (Ubuntu) - makepasswd -count 1 -minchars 8
Create .passwd file with user and random password - sudo htpasswd -c /etc/nginx/.htpasswd <user>
Removing files

Remove files over 30 days old - find . -mtime +30 | xargs rm -rf
Remove files older than 7 day starting with 'backup' - find . -type f -name "backup*" -mtime +7 -exec rm {} \;
SSH

Generate generic ssh key pair - ssh-keygen -q -t rsa -f ~/.ssh/<name> -N '' -C <name>
Tail log with colored output

grc tail -f /var/log/filename
Tmux

Kill a window - tmux kill-window -t 0
Kill stuck tmux window - tmux kill-window -t X
Create a new session - tmux new -s <name>
List all sessions - tmux ls
ps

Show process tree of all PIDs - ps auxwf
Show all process info and hierarchy (same as above)- ps -efH
Show orphaned processes for - ps -ef|awk '$3=="1" && /pandora/ { print $2 }'
Show all orphaned processes (could be daemons) - ps -elf | awk '{if ($5 == 1){print $4" "$5" "$15}}'
Show zombie processes - ps aux | grep Z



April 22, 2019
In the following, we set a variable called BearerToken using a simple curl to the contents of a bearer token. We do so by running a curl with data in the header for “userid” although sometimes we see this as just “user” or “username” and then a password. This hits an endpoint called authenticationendpoint although sometimes we see that called “auth” or “authenticate” – in this specific case we’re pulling the bearer token out of “id” and it’s nested in there with a name of “token”:
BearerToken=$(curl -s -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' --data '{"userid”:”{userid}”,”password":"{password}"}' https://krypted.com//api/authenticationendpoint | sed -E 's/\},\s*\{/\},\n\{/g' File | grep  ‘”id” : “token”’)
Once we have that token we can then pass it into another API via the Authorization header when connecting. In this example we’ll just pass the BearerToken we just captured as such, to an endpoint called EndpointName to https://krypted.com//api/EndpointName:
curl -H 'Accept: application/json' -H "Authorization: Bearer ${BearerToken}” https://krypted.com//api/EndpointName

Sending Curl Request with Bearer Token
To send a Bearer Token to the server using Curl, you can use the -H "Authorization: Bearer {token}" authorization header. The Bearer Token is an encrypted string that provides a user authentication framework to control access to protected resources. To send a Curl POST request, you need to pass the POST data with the -d command line option, and the authorization header and bearer token are passed with the -H command line option. In this Curl Request With Bearer Token Authorization Header example, we send a GET request to the ReqBin echo URL. Click Run to execute the Curl Bearer Token Authorization Header request online and see the results.
Sending Curl Request with Bearer Token
Run
curl https://reqbin.com/echo/get/json
   -H "Accept: application/json"
   -H "Authorization: Bearer {token}"
Updated: Nov 09, 2022 Viewed: 54653 times  Author: ReqBin 
What is Curl?
Curl is a well-known command-line tool for transferring data between servers, designed to work without user intervention. Curl can upload or download data using popular protocols including HTTP, HTTPS, SCP, SFTP, and FTP with Curl. Curl is used for API testing, has built-in support for proxies, SSL, HTTP cookies. Curl runs on Linux, Windows, and macOS platforms.

What is the Authorization Header?
HTTP provides a built-in framework for controlling access and authentication to protected resources. The authorization request header contains the credentials for authenticating the HTTP client to the server. The most commonly used authorization headers are Basic Auth and Bearer Token headers.

Authorization Header Syntax
Authorization: Basic {base64string}
Authorization: Bearer {token}

What is the Bearer Authorization Token?



Cheat Sheet - curl
 Sep 18, 2020
The examples in this post either show sample requests to example.com for authentication or from example.com to github.com for CORS (cross origin resource sharing).

Tipps and tricks
Helpful parameters
Parameter	Description
--connect-timeout <seconds>	Maximum time in seconds that you allow curl’s connection to take. This only limits the connection phase, so if curl connects within the given period it will continue - if not it will exit.
-s, --silent	Don’t show progress meter or error messages
-k, --insecure	This option allows curl to proceed and operate even for server connections otherwise considered insecure.
-L, --location	Follow redirects.
DNS override
The curl option --resolve helps with querying virtual hosts locally. Instead of

curl -v -H 'Host: www.example.com' http://127.0.0.1
I chose to use

curl -v --resolve 'www.example.com:80:127.0.0.1' http://www.example.com
What’s the difference, you ask?

Among other things, this works with HTTPS. Assuming your local server has a certificate for www.example.com, the first example above will fail because the www.example.com certificate doesn’t match the 127.0.0.1 hostname in the URL.

The second example works correctly with HTTPS.

In essence, passing a “Host” header via -H does hack your Host into the header set, but bypasses all of curl’s host-specific intelligence. Using --resolve leverages all of the normal logic that applies, but simply pretends the DNS lookup returned the data in your command-line option. It works just like /etc/hosts should.

Note --resolve takes a port number, so for HTTPS you would use

curl -v --resolve 'www.example.com:443:127.0.0.1' https://www.example.com/api/vi/status
rather than

curl -v --insecure -H 'Host: www.example.com' https://localhost:443/api/vi/status
This can also be used to test CDNs and redirects:

$ curl -v -L --resolve 'www.example.com:443:mpc.example.com.edgesuite-staging.net' https://www.example.com/gb/en/contact-us
$ curl -v -L -X HEAD -H 'Host: www.example.com' https://mpc.example.com.edgesuite-staging.net
Avoid repetition
If we need to send multiple requests with a set of common parameters we can shorten the commands as follows - see CURL_PARAMS:

USERNAME="john.doe"
API_TOKEN="${PORTUS_USER_API_TOKEN}"
REGISTRY_BASE_URL="https://registry.example.com"
NAMESPACE="someproject"
SERVICE="samplesvc"
 
 
CURL_PARAMS=( -X GET --silent --header 'Accept: application/json' --header "Portus-Auth: ${USERNAME}:${API_TOKEN}" )
 
NAMESPACE_ID=$(curl "${CURL_PARAMS[@]}" "${REGISTRY_BASE_URL}/api/v1/namespaces" | jq ".[] | select(.name == \"${NAMESPACE}\").id")
REPOSITORY_ID=$(curl "${CURL_PARAMS[@]}" "${REGISTRY_BASE_URL}/api/v1/namespaces/${NAMESPACE_ID}/repositories" | jq ".[] | select(.name == \"${SERVICE}\").id")
IMAGE_TAGS=$(curl "${CURL_PARAMS[@]}" "${REGISTRY_BASE_URL}/api/v1/repositories/${REPOSITORY_ID}/tags" | jq 'sort_by(.updated_at) | map(.name)')
 
echo "${IMAGE_TAGS}"
Test CORS headers
Here’s how you can debug CORS requests using curl:

Sending a regular CORS request using curl:

As HEAD request:

$ curl -i https://api.github.com \
    -H "Origin: http://example.com"
HTTP/1.1 302 Found
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: ETag, Link, X-GitHub-OTP, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-OAuth-Scopes, X-Accepted-OAuth-Scopes, X-Poll-Interval
Or with GET request:

$ curl -v https://api.github.com \
    -H "Origin: http://example.com"   
HTTP/1.1 302 Found
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: ETag, Link, X-GitHub-OTP, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-OAuth-Scopes, X-Accepted-OAuth-Scopes, X-Poll-Interval
The -H "Origin: http://example.com" flag is the third party domain making the request. Substitute in whatever your domain is.
The --verbose flag prints out the entire response so you can see the request and response headers.
The response should include the Access-Control-Allow-Origin header.
Sending a preflight request using curl:

In general a server must respond to OPTIONS requests with a 2xx success status — typically 200 or 204. A CORS preflight request requires a 204 No Content response.

This is what the CORS preflight request looks like:

$ curl -v -i https://api.github.com \
    -H "Origin: http://example.com" \
    -X OPTIONS
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: Authorization, Content-Type, If-Match, If-Modified-Since, If-None-Match, If-Unmodified-Since, X-GitHub-OTP, X-Requested-With
Access-Control-Allow-Methods: GET, POST, PATCH, PUT, DELETE
Access-Control-Expose-Headers: ETag, Link, X-GitHub-OTP, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-OAuth-Scopes, X-Accepted-OAuth-Scopes, X-Poll-Interval
Access-Control-Max-Age: 86400
And with more specific request headers:

$ curl -v https://api.github.com \
    -H "Origin: http://example.com" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: X-Requested-With" \
    -X OPTIONS
This looks similar to the regular CORS request with a few additions:

The -H flags send additional preflight request headers to the server
The -X OPTIONS flag indicates that this is an HTTP OPTIONS request.
If the preflight request is successful, the response should include the Access-Control-Allow-Origin, Access-Control-Allow-Methods, and Access-Control-Allow-Headers response headers. If the preflight request was not successful, these headers shouldn’t appear, or the HTTP response won’t be 200.

Send data from file
Instead of directly providing the request body contents as parameter you can also read it from a file. Instead of:

$ curl -X POST -d '{"key1":"value1", "key2":"value2", "array": ["a","b"]}' https://example.com

# or multiline

$ curl -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' --data '{
  "key1": "value1",
  "key2": "value2",
  "array": [
    "a",
    "b"
  ]
}' https://example.com
use:

# --data @"${FILEPATH}"
 --data @"$HOME/myinput.json"
 --data @input.json
Basic Auth (base64)
Some requests that rely on Basic authentication require you to pass a base64 encoded string in the format ${username}:${password} to the target:

# encode Linux
#
# options
#   echo
#     -n do not output the trailing newline
#     -e enable interpretation of backslash escapes
#   base64
#     -d, --decode Decode data
#     -w, --wrap=COLS Wrap encoded lines after COLS character (default 76). Use 0 to disable line wrapping
BASE64_CREDENTIAL=$(echo -ne "${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD}" | base64 --wrap 0)

# encode macOS
#
# options
#   echo
#     -n do not output the trailing newline
#   base64
#     -d, --decode Decode data
BASE64_CREDENTIAL=$(echo -n "${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD}" | base64)

# decode with 
PLAINTEXT_CREDENTIAL=$(echo -n "${BASE64_CREDENTIAL}" | base64 -d)
Alternatively you can use curl’s -u parameter - from the documentation1 page:

-u, –user <user:password>

Specify the user name and password to use for server authentication. Overrides -n, –netrc and –netrc-optional.

If you simply specify the user name, curl will prompt for a password.

The user name and passwords are split up on the first colon, which makes it impossible to use a colon in the user name with this option. The password can, still.

Usage:

$ curl -u "username" https://api.example.com
$ curl -u "username:password" https://api.example.com
Reference
Test HTTP2 connection
$ curl -v --http2 --head --silent --output /dev/null https://example.com
$ curl -v --http2 --head --silent https://example.com > /dev/null
Basic Auth
To send a POST request to an endpoint that requires basic auth use:

$ curl https://example.com/ \
    -H 'Accept: application/json' -H "Content-Type: application/json" \
    -H "Authorization: Basic ${BASE64_CREDENTIAL}" \
    --request POST \
    --data  '{"key1":"value1", "key2":"value2"}'

# or 

$ curl https://example.com/ \
    -H 'Accept: application/json' -H "Content-Type: application/json" \
    --request POST \
    --data  '{"key1":"value1", "key2":"value2"}' \
    -u "${BASIC_AUTH_USER}"
Form actions + Basic Auth
-F, –form <name=content> (HTTP) This lets curl emulate a filled-in form in which a user has pressed the submit button. This causes curl to POST data using the Content-Type multipart/form-data according to RFC 2388. This enables uploading of binary files etc. To force the ‘content’ part to be a file, prefix the file name with an @ sign. To just get the content part from a file, prefix the file name with the symbol <. The difference between @ and < is then that @ makes a file get attached in the post as a file upload, while the < makes a text field and just get the contents for that text field from a file.

Upload a file to a service:

$ curl https://crm.example.com/crx/packmgr/service.jsp \
    -u "${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD}" \
    -F file=@"${FILEPATH}/${PACKAGE_NAME}.zip" \
    -F name="${PACKAGE_NAME}" \
    -F force=true \
    -F install=false
Change some user settings:

$ curl https://crm.example.com/crx/explorer/ui/setpassword.jsp \
    -u "${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD}" \
    -Fplain="${NEW_PASSWORD}" \
    -Fverify="${NEW_PASSWORD}" \
    -Fold="${OLD_PASSWORD}" \
    -FPath="${USER_PATH}" 
Client Cert + Basic Auth
To send a GET request that requires a client certificate in addition to basic auth use:

$ curl -X GET -vvv https://cert.example.com/api/example-svc/v1/status \
    -H 'Accept: application/json' -H 'Content-Type: application/json' \
    -H "X-ApplicationName: Some Application" \
    -H "Authorization: Basic ${BASE64_CREDENTIAL}" \
    --cert /app/certs/example-svc-eu-int-cert.pem \
    --key /app/certs/example-svc-eu-int-key.pem \
    --key-type PEM
First of all you have to get the cert and the key separated from the p12 file. Given you have a example-svc-eu-int-key.pfx file execute:

$ openssl pkcs12 -in example-svc-eu-int.pfx -out example-svc-eu-int-key.pem -nocerts -nodes
$ openssl pkcs12 -in example-svc-eu-int.pfx -out example-svc-eu-int-cert.pem -clcerts -nokeys
Newer versions of curl also support P12 (PFX):

$ curl -X GET -vvv https://cert.example.com/api/example-svc/v1/status \
    -H 'Accept: application/json' -H 'Content-Type: application/json' \
    -H "X-ApplicationName: Some Application" \
    -H "Authorization: Basic ${BASE64_CREDENTIAL}" \
    --cert-type P12 --cert /app/certs/example-svc-eu-int.pfx:${KEY_PASSPHRASE}
OAuth Credentials Grant
Here’s how to request an access token via theOauth2 process called the “Resource owner password credentials grant”. In this example:

User credentials should be provided in the body as application/x-www-form-urlencoded, with grant_type=password.
A separate HTTP header “x-api-key” should be specified for all requests. This header controls rate limiting and its purpose is not to limit access.
$ curl -X POST https://auth.example.com/v1/oauth/token \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --header 'Accept: application/json' \
    --header "Authorization: Basic ${BASE64_CREDENTIAL}" \
    --header "x-api-key: ${API_KEY}" \
    -d "grant_type=password&username=${USERNAME}&password=${PASSWORD}"
This will give us a response with an access_token that will be used as an HTTP Bearer token in all following requests. It is valid for the number of seconds specified as “expirese”, after which the authentication process needs to be repeated:

{
  "access_token": "280793ec-e123-4595-9fbc-32bea948ac34",
  "token_type": "bearer",
  "expirese": 7199
}
Use as Bearer token:

$ curl -X GET https://api.example.com/example-svc/v1/users/list \
    --header 'Accept: application/json' \
    --header 'Authorization: Bearer 280793ec-e123-4595-9fbc-32bea948ac34' \
    --header "x-api-key: ${API_KEY}"
Auth with Bearer token and API key
curl -X GET https://example.com/api/v1/status \
    --header 'Accept: application/json' \
    --header "Authorization: Bearer ${ACCESS_TOKEN}" \
    --header "x-api-key: ${API_KEY}"
http://curl.haxx.se/docs/manpage.html#–basic ↩


