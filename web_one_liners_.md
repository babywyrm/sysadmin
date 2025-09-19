


# 🌍 Static File Dev Servers (2025 Edition)

| Runtime / Tool     | Command                                                                                                                                   | Notes                                        |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **Python 3+**      | `python3 -m http.server 8000`                                                                                                             | Built‑in everywhere, easy + universal        |
| **Node.js**        | `npx http-server -p 8000`                                                                                                                 | Classic, stable                              |
|                    | `npx serve -l 8000`                                                                                                                       | Modern, SPA support (Next.js team tool)      |
|                    | `npx serverino --port 8000`                                                                                                               | Lightweight & fast                           |
| **Ruby**           | `ruby -run -ehttpd . -p 8000`                                                                                                             | Built‑in (since 1.9.2)                       |
|                    | `adsf -p 8000` (after `gem install adsf`)                                                                                                 | Simple, nice defaults                        |
| **Perl**           | `perl -MMojolicious::Lite -MCwd -e 'app->static->paths->[0]=getcwd; app->start' daemon -l http://*:8000`                                   | Mojolicious makes it easy                    |
| **PHP ≥5.4**       | `php -S 127.0.0.1:8000`                                                                                                                    | Built‑in, great for testing static/PHP sites |
| **Java ≥18**       | `jwebserver -p 8000`                                                                                                                       | New built‑in dev server                      |
| **Go**             | `go run github.com/shurcooL/goexec@latest 'http.ListenAndServe(":8000", http.FileServer(http.Dir(".")))'`                                 | Quick inline dev server                      |
|                    | `go install github.com/vercel/serve@latest && serve -l 8000`                                                                              | Server utility from Vercel                   |
| **Docker (nginx)** | `docker run --rm -p 8000:80 -v $PWD:/usr/share/nginx/html:ro nginx:alpine`                                                                 | Clean, production‑like                       |
| **Docker (tiny)**  | `docker run --rm -p 8000:80 -v "$PWD":/www:ro p3terx/darkhttpd:1.13 /www`                                                                  | Extremely small image (≈90kB)                |
| **BusyBox**        | `busybox httpd -f -p 8000`                                                                                                                 | Works on many embedded systems               |



##
##

Each of these commands will run an ad hoc http static server in your current (or specified) directory, available at http://localhost:8000. Use this power wisely.

[Discussion on reddit](http://www.reddit.com/r/webdev/comments/1fs45z/list_of_ad_hoc_http_server_oneliners/).

### Python 2.x

```shell
$ python -m SimpleHTTPServer 8000
```

### Python 3.x

```shell
$ python -m http.server 8000
```

### Twisted <sub><sup>(Python)</sup></sub>

```shell
$ twistd -n web -p 8000 --path .
```

Or:

```shell
$ python -c 'from twisted.web.server import Site; from twisted.web.static import File; from twisted.internet import reactor; reactor.listenTCP(8000, Site(File("."))); reactor.run()'
```

Depends on [Twisted](http://twistedmatrix.com/trac/wiki/Downloads).

### Ruby

```shell
$ ruby -rwebrick -e'WEBrick::HTTPServer.new(:Port => 8000, :DocumentRoot => Dir.pwd).start'
```

Credit: [Barking Iguana](http://barkingiguana.com/2010/04/11/a-one-line-web-server-in-ruby/)

### Ruby 1.9.2+

```shell
$ ruby -run -ehttpd . -p8000
```

Credit: [nobu](https://gist.github.com/willurd/5720255#comment-855952)

### adsf <sub><sup>(Ruby)</sup></sub>

```shell
$ gem install adsf   # install dependency
$ adsf -p 8000
```

Credit: [twome](https://gist.github.com/willurd/5720255/#comment-841393)

*No directory listings.*

### Sinatra <sub><sup>(Ruby)</sup></sub>

```shell
$ gem install sinatra   # install dependency
$ ruby -rsinatra -e'set :public_folder, "."; set :port, 8000'
```

*No directory listings.*

### Perl

```shell
$ cpan HTTP::Server::Brick   # install dependency
$ perl -MHTTP::Server::Brick -e '$s=HTTP::Server::Brick->new(port=>8000); $s->mount("/"=>{path=>"."}); $s->start'
```

Credit: [Anonymous Monk](http://www.perlmonks.org/?node_id=865239)

### Plack <sub><sup>(Perl)</sup></sub>

```shell
$ cpan Plack   # install dependency
$ plackup -MPlack::App::Directory -e 'Plack::App::Directory->new(root=>".");' -p 8000
```

Credit: [miyagawa](http://advent.plackperl.org/2009/12/day-5-run-a-static-file-web-server-with-plack.html)

### Mojolicious <sub><sup>(Perl)</sup></sub>

```shell
$ cpan Mojolicious::Lite   # install dependency
$ perl -MMojolicious::Lite -MCwd -e 'app->static->paths->[0]=getcwd; app->start' daemon -l http://*:8000
```

*No directory listings.*

### http-server <sub><sup>(Node.js)</sup></sub>

```shell
$ npm install -g http-server   # install dependency
$ http-server -p 8000
```

*Note: This server does funky things with relative paths. For example, if you have a file `/tests/index.html`, it will load `index.html` if you go to `/test`, but will treat relative paths as if they were coming from `/`.*

### node-static <sub><sup>(Node.js)</sup></sub>

```shell
$ npm install -g node-static   # install dependency
$ static -p 8000
```

*No directory listings.*

### PHP <sub><sup>(>= 5.4)</sup></sub>

```shell
$ php -S 127.0.0.1:8000
```

Credit: [/u/prawnsalad](http://www.reddit.com/r/webdev/comments/1fs45z/list_of_ad_hoc_http_server_oneliners/cad9ew3) and [MattLicense](https://gist.github.com/willurd/5720255#comment-841131)

*No directory listings.*

### Erlang

```shell
$ erl -s inets -eval 'inets:start(httpd,[{server_name,"NAME"},{document_root, "."},{server_root, "."},{port, 8000},{mime_types,[{"html","text/html"},{"htm","text/html"},{"js","text/javascript"},{"css","text/css"},{"gif","image/gif"},{"jpg","image/jpeg"},{"jpeg","image/jpeg"},{"png","image/png"}]}]).'
```

Credit: [nivertech](https://gist.github.com/willurd/5720255/#comment-841166) (with the addition of some basic mime types)

*No directory listings.*

### busybox httpd

```shell
$ busybox httpd -f -p 8000
```

Credit: [lvm](https://gist.github.com/willurd/5720255#comment-841915)

### webfs

```shell
$ webfsd -F -p 8000
```

Depends on [webfs](http://linux.bytesex.org/misc/webfs.html).

### IIS Express

```shell
C:\> "C:\Program Files (x86)\IIS Express\iisexpress.exe" /path:C:\MyWeb /port:8000
```

Depends on [IIS Express](http://www.iis.net/learn/extensions/introduction-to-iis-express/iis-express-overview).

Credit: [/u/fjantomen](http://www.reddit.com/r/webdev/comments/1fs45z/list_of_ad_hoc_http_server_oneliners/cada8no)

*No directory listings. `/path` must be an absolute path.*

# Meta

If you have any suggestions, drop them in the comments below or on the reddit discussion. To get on this list, a solution must:

1. serve static files using your current directory (or a specified directory) as the server root,
2. be able to be run with a single, one line command (dependencies are fine if they're a one-time thing),
3. serve basic file types (html, css, js, images) with proper mime types,
4. require no configuration (from files or otherwise) beyond the command itself (no framework-specific servers, etc)
5. must run, or have a mode where it can run, in the foreground (i.e. no daemons)

##
##
##



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

@dkorpel
dkorpel commented on Aug 7
D, with package 'serve':

dub run serve
dub run serve -- path/to/index.html
https://code.dlang.org/packages/serve

@tblaisot
tblaisot commented on Sep 9
for SPA static workload and without dependencies:
npx servor <root> <fallback> <port>
https://www.npmjs.com/package/servor

@x-yuri
x-yuri commented on Sep 16 • 
Failed to install HTTP::Server::Brick in an Alpine container:

Unimplemented: POSIX::tmpnam(): use File::Temp instead at t/serving.t line 87.
And it might be abandoned.

@fkpussys
fkpussys commented on Sep 16
This is off topic but if we upload an image to a reposiory, how do we associate it with a script, like for example a game has a character and a script, how do we do that?? also f4f?
