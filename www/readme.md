
##
https://gist.github.com/willurd/5720255
##

Each of these commands will run an ad hoc http static server in your current (or specified) directory, available at http://localhost:8000. Use this power wisely.

Discussion on reddit.

Python 2.x
$ python -m SimpleHTTPServer 8000
Python 3.x
$ python -m http.server 8000
Twisted (Python)
$ twistd -n web -p 8000 --path .
Or:

$ python -c 'from twisted.web.server import Site; from twisted.web.static import File; from twisted.internet import reactor; reactor.listenTCP(8000, Site(File("."))); reactor.run()'
Depends on Twisted.

Ruby
$ ruby -rwebrick -e'WEBrick::HTTPServer.new(:Port => 8000, :DocumentRoot => Dir.pwd).start'
Credit: Barking Iguana

Ruby 1.9.2+
$ ruby -run -ehttpd . -p8000
Credit: nobu

adsf (Ruby)
$ gem install adsf   # install dependency
$ adsf -p 8000
Credit: twome

No directory listings.

Sinatra (Ruby)
$ gem install sinatra   # install dependency
$ ruby -rsinatra -e'set :public_folder, "."; set :port, 8000'
No directory listings.

Perl
$ cpan HTTP::Server::Brick   # install dependency
$ perl -MHTTP::Server::Brick -e '$s=HTTP::Server::Brick->new(port=>8000); $s->mount("/"=>{path=>"."}); $s->start'
Credit: Anonymous Monk

Plack (Perl)
$ cpan Plack   # install dependency
$ plackup -MPlack::App::Directory -e 'Plack::App::Directory->new(root=>".");' -p 8000
Credit: miyagawa

Mojolicious (Perl)
$ cpan Mojolicious::Lite   # install dependency
$ perl -MMojolicious::Lite -MCwd -e 'app->static->paths->[0]=getcwd; app->start' daemon -l http://*:8000
No directory listings.

http-server (Node.js)
$ npm install -g http-server   # install dependency
$ http-server -p 8000
Note: This server does funky things with relative paths. For example, if you have a file /tests/index.html, it will load index.html if you go to /test, but will treat relative paths as if they were coming from /.

node-static (Node.js)
$ npm install -g node-static   # install dependency
$ static -p 8000
No directory listings.

PHP (>= 5.4)
$ php -S 127.0.0.1:8000
Credit: /u/prawnsalad and MattLicense

No directory listings.

Erlang
$ erl -s inets -eval 'inets:start(httpd,[{server_name,"NAME"},{document_root, "."},{server_root, "."},{port, 8000},{mime_types,[{"html","text/html"},{"htm","text/html"},{"js","text/javascript"},{"css","text/css"},{"gif","image/gif"},{"jpg","image/jpeg"},{"jpeg","image/jpeg"},{"png","image/png"}]}]).'
Credit: nivertech (with the addition of some basic mime types)

No directory listings.

busybox httpd
$ busybox httpd -f -p 8000
Credit: lvm

webfs
$ webfsd -F -p 8000
Depends on webfs.

IIS Express
C:\> "C:\Program Files (x86)\IIS Express\iisexpress.exe" /path:C:\MyWeb /port:8000
Depends on IIS Express.

Credit: /u/fjantomen

No directory listings. /path must be an absolute path.

Meta
If you have any suggestions, drop them in the comments below or on the reddit discussion. To get on this list, a solution must:

serve static files using your current directory (or a specified directory) as the server root,
be able to be run with a single, one line command (dependencies are fine if they're a one-time thing),
serve basic file types (html, css, js, images) with proper mime types,
require no configuration (from files or otherwise) beyond the command itself (no framework-specific servers, etc)
must run, or have a mode where it can run, in the foreground (i.e. no daemons)
Load earlier comments...
@andresvia
andresvia commented on Feb 9, 2021
socat
socat -v TCP-LISTEN:8080,crlf,reuseaddr,fork 'SYSTEM:echo HTTP/1.0 200;echo Server\: socat hack;echo Content-Type\: text/plain;echo;echo ok'
@vistun
vistun commented on Feb 28, 2021
This a good one @vandot
edited below, works with semicolons

It still oneliner :)
golang
echo 'package main; import "net/http"; func main() {fs := http.FileServer(http.Dir(".")); http.Handle("/", fs); http.ListenAndServe(":8000", nil)}' > main.go; go run main.go; rm main.go

@textprotocol
textprotocol commented on Apr 2, 2021
ucspi-tcp text://protocol server.

# tcpserver -v -c42 -o -D -H -P -l 0 -R 127.0.0.1 1961 timeout 1 ../../bin/publictext

https://github.com/textprotocol/publictext

@johnwyles
johnwyles commented on May 13, 2021
@lethalman

I'd like to request a bash http server using /dev/tcp, anybody has a one-liner for that?

https://unix.stackexchange.com/a/49947

@marin-liovic
marin-liovic commented on May 13, 2021 • 
replace all of the npm install with npx for a oneliner, e.g. npx superstatic -p 8000

@eikes
eikes commented on May 13, 2021
PowerShell

$Hso=New-Object Net.HttpListener;$Hso.Prefixes.Add("http://+:8000/");$Hso.Start();While ($Hso.IsListening){$HC=$Hso.GetContext();$HRes=$HC.Response;$HRes.Headers.Add("Content-Type","text/plain");$Buf=[Text.Encoding]::UTF8.GetBytes((GC (Join-Path $Pwd ($HC.Request).RawUrl)));$HRes.ContentLength64=$Buf.Length;$HRes.OutputStream.Write($Buf,0,$Buf.Length);$HRes.Close()};$Hso.Stop()
PowerShell from cmd.exe

PowerShell.exe -nop -enc JABIAHMAbwA9AE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAEgAdAB0AHAATABpAHMAdABlAG4AZQByADsAJABIAHMAbwAuAFAAcgBlAGYAaQB4AGUAcwAuAEEAZABkACgAIgBoAHQAdABwADoALwAvACsAOgA4ADAAMAAwAC8AIgApADsAJABIAHMAbwAuAFMAdABhAHIAdAAoACkAOwBXAGgAaQBsAGUAIAAoACQASABzAG8ALgBJAHMATABpAHMAdABlAG4AaQBuAGcAKQB7ACQASABDAD0AJABIAHMAbwAuAEcAZQB0AEMAbwBuAHQAZQB4AHQAKAApADsAJABIAFIAZQBzAD0AJABIAEMALgBSAGUAcwBwAG8AbgBzAGUAOwAkAEgAUgBlAHMALgBIAGUAYQBkAGUAcgBzAC4AQQBkAGQAKAAiAEMAbwBuAHQAZQBuAHQALQBUAHkAcABlACIALAAiAHQAZQB4AHQALwBwAGwAYQBpAG4AIgApADsAJABCAHUAZgA9AFsAVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBVAFQARgA4AC4ARwBlAHQAQgB5AHQAZQBzACgAKABHAEMAIAAoAEoAbwBpAG4ALQBQAGEAdABoACAAJABQAHcAZAAgACgAJABIAEMALgBSAGUAcQB1AGUAcwB0ACkALgBSAGEAdwBVAHIAbAApACkAKQA7ACQASABSAGUAcwAuAEMAbwBuAHQAZQBuAHQATABlAG4AZwB0AGgANgA0AD0AJABCAHUAZgAuAEwAZQBuAGcAdABoADsAJABIAFIAZQBzAC4ATwB1AHQAcAB1AHQAUwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAEIAdQBmACwAMAAsACQAQgB1AGYALgBMAGUAbgBnAHQAaAApADsAJABIAFIAZQBzAC4AQwBsAG8AcwBlACgAKQB9ADsAJABIAHMAbwAuAFMAdABvAHAAKAApAA==
What a handy one-liner!

@rjmunro
rjmunro commented on May 13, 2021
Note that if you want to share something with another machine, most of the solutions that bind to localhost or 127.0.0.1 won't work. Normally if you change localhost or 127.0.0.1 to 0, it will listen on all interfaces so you can download something from another machine.

E.g. change:

php -S 127.0.0.1:8000
to:

php -S 0:8000
@radiosilence
radiosilence commented on May 13, 2021
npx serve

Yep, this is probably the easiest

@radiosilence
radiosilence commented on May 13, 2021
npx serve

Yep, this is probably the easiest

@mmazzarolo
mmazzarolo commented on May 13, 2021
With serverino:

npx serverino --port 8000
Use --secure to automatically generate a certificate and serve on SSL (at https://localhost:8000).

@pimbrouwers
pimbrouwers commented on May 13, 2021
With Sergio - a Kestrel wrapper using Argu:

sergio
This will serve the current directory at https://[::]:8080.

To specify listener details:

sergio --listener localhost 8080
To display all options:

sergio --help
@dbohdan
dbohdan commented on May 13, 2021
Tcl
You will need Tcl 8.6 with Tcllib 1.19 or later.

echo 'package require httpd 4; ::httpd::server create HTTPD port 8000 myaddr 127.0.0.1 doc_root [pwd]; vwait forever' | tclsh
Credit to @rkeene.

@darkblue-b
darkblue-b commented on May 13, 2021
C99

klange/cgiserver

@vi
vi commented on May 13, 2021 • 
websocat can serve specific explicit list of files on explicit URLs with explicit Content-Types.

websocat -s 1234 -F /index.html:text/html:./index.html -F /script.js:text/javascript:/path/to/thescript.js
There is no ability to automatically include more files based on existence on the filesystem, but sometimes 100% explicit approach may be beneficial.

@carlosneves0
carlosneves0 commented on May 13, 2021 • 
docker run --rm --volume "$(pwd):/www:ro" --publish 80:80 docker.io/p3terx/darkhttpd:1.13 /www
docker image ls --format 'table {{.Repository}}:{{.Tag}}\t{{.Size}}' p3terx/darkhttpd:1.13
REPOSITORY:TAG          SIZE
p3terx/darkhttpd:1.13   91.7kB
docker run --rm --volume "$(pwd):/usr/share/nginx/html:ro" --publish 80:80 docker.io/library/nginx:1.20.0-alpine
docker image ls --format 'table {{.Repository}}:{{.Tag}}\t{{.Size}}' nginx:1.20.0-alpine
REPOSITORY:TAG        SIZE
nginx:1.20.0-alpine   22.6MB
@lpereira
lpereira commented on May 13, 2021
Lwan can be used as an one-liner web server, too: lwan -r /path/to/files/to/serve.

@wtarreau
wtarreau commented on May 14, 2021
Surprised that the once most universal thttpd wasn't even mentioned given how simple and convenient it is:

$ thttpd
$ netstat -ltnp | grep thttpd
tcp6       0      0 :::8080                 :::*                    LISTEN      25130/thttpd        
@nilslindemann
nilslindemann commented on May 14, 2021
Pff. How 1970, typing commands. I press buttons :-p

@wtarreau
wtarreau commented on May 14, 2021
A listening socket is exactly the type of thing I wouldn't want to see in a web browser!

@nilslindemann
nilslindemann commented on May 14, 2021
@wtarreau why?

@Offirmo
Offirmo commented on May 14, 2021 • 
Node serve https://www.npmjs.com/package/serve much more professional that the other listed node.js options at this time.

Note that npm doesn't require you to install the package, so a true one-liner would be:

npx serve  --listen 8000
npx node-static -p 8000
npx http-server -p 8000
Thanks for the page!

@wtarreau
wtarreau commented on May 14, 2021
@nilslindemann:

@wtarreau why?

Browsers' security is extremely brittle, and it's already extremely hard for them to protect themselves from abuses by rogue sites and fake ads or limiting the impact of poorly written plugins that always risk to be used to steal user information. By opening them to the outside world using an incoming connection, you're suddenly bypassing a lot of the isolation efforts made in the browser by immediately exposing the process to the outside world. You just need a small bug in the server or a small overlook in the isolation between the server and the rest of the browser and your browser's sensitive info such as passwords, cookies, certificates, or history can immediately leak, or some dummy certs and cookies, or trojans can be inserted.

@nilslindemann
nilslindemann commented on May 15, 2021
@wtarreau, Hmm, interesting. But isn't this an application which is isolated from the rest of the browser? Do you know of cases where what you described happened? Also, 400 000 users and no review which points out the dangers you described, and no attempts by google to block that app, all this indicates to me that it is not less safe than the other approaches documented here, is it?

@pfreitag
pfreitag commented on May 19, 2021
For a ColdFusion / CFML powered web server in the current directory you can use commandbox:

box server start port=8123
The box binary (dependency) can be installed by running brew install commandbox or via several other methods: https://commandbox.ortusbooks.com/setup/installation

@michal-grzejszczak
michal-grzejszczak commented on Jul 31, 2021
Winstone, a wrapper around Jetty. Install:

mvn dependency:get -Dartifact=org.jenkins-ci:winstone:5.20 -DremoteRepositories=https://repo.jenkins-ci.org/public/
and run

java -jar ~/.m2/repository/org/jenkins-ci/winstone/5.20/winstone-5.20.jar --webroot=.
@patrickhener
patrickhener commented on Nov 9, 2021
Another option in go is goshs

@meydjer
meydjer commented on Dec 17, 2021
Just found nws which supports basepath:

If you want all requests to resolve to a base path (i.e. http://localhost:3030/basepath) without having to place all files into a src/basepath sub-directory, use the -b flag:

nws -b basepath
@nahteb
nahteb commented on Mar 30 • 
In Java 18:

jwebserver -p 8080

@Object905
Object905 commented on May 20
When running in docker compose along with nominatim-docker

FROM nginx:1.21-alpine

RUN wget https://github.com/osm-search/nominatim-ui/releases/download/v3.2.4/nominatim-ui-3.2.4.tar.gz &&\
    tar -xvf nominatim-ui-3.2.4.tar.gz --strip-components=1 &&\
    cp -r dist/* /usr/share/nginx/html/ &&\
    sed -i 's/http:\/\/localhost\/nominatim\//http:\/\/nominatim:8080\//g' /usr/share/nginx/html/config.defaults.js

EXPOSE 80
@georgefst
georgefst commented on May 26
Haskell, with just Cabal:

echo 'WaiAppStatic.CmdLine.runCommandLine (const id)' | cabal repl -b wai-app-static
It's a bit verbose, but on the plus side you're in a REPL, so it's easy to modify things.

Prompted by a question on Reddit.
