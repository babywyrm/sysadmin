# 🌍 Static File Dev Servers (2026 Edition) ..young adult version..

A comprehensive reference for spinning up instant HTTP servers from the command line. Perfect for testing, development, and quick file sharing.

---

## Quick Reference Table

| Runtime / Tool     | Command                                                                                                                                   | Notes                                        |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **Python 3+**      | `python3 -m http.server 8000`                                                                                                             | Built‑in everywhere, easy + universal        |
| **Node.js**        | `npx http-server -p 8000`                                                                                                                 | Classic, stable                              |
|                    | `npx serve -l 8000`                                                                                                                       | Modern, SPA support (Vercel tool)            |
|                    | `npx serverino --port 8000`                                                                                                               | Lightweight & fast                           |
|                    | `npx servor . index.html 8000`                                                                                                            | SPA fallback support                         |
| **Bun**            | `bunx serve -l 8000`                                                                                                                      | Fast runtime, compatible with serve          |
| **Deno**           | `deno run --allow-net --allow-read https://deno.land/std/http/file_server.ts -p 8000`                                                    | Secure by default, modern                    |
| **Ruby**           | `ruby -run -ehttpd . -p 8000`                                                                                                             | Built‑in (since 1.9.2)                       |
|                    | `adsf -p 8000` (after `gem install adsf`)                                                                                                 | Simple, nice defaults                        |
| **Perl**           | `perl -MMojolicious::Lite -MCwd -e 'app->static->paths->[0]=getcwd; app->start' daemon -l http://*:8000`                                 | Mojolicious makes it easy                    |
| **PHP ≥5.4**       | `php -S 127.0.0.1:8000`                                                                                                                   | Built‑in, great for testing static/PHP sites |
| **Java ≥18**       | `jwebserver -p 8000`                                                                                                                      | Built‑in dev server                          |
| **Go**             | `go run github.com/shurcooL/goexec@latest 'http.ListenAndServe(":8000", http.FileServer(http.Dir(".")))'`                                | Quick inline dev server                      |
|                    | `goshs -p 8000`                                                                                                                           | Feature-rich, auth support                   |
| **Rust**           | `cargo install miniserve && miniserve -p 8000`                                                                                            | Fast, feature-rich, directory listings       |
| **D**              | `dub run serve -- . 8000`                                                                                                                 | D language static server                     |
| **Haskell**        | `echo 'WaiAppStatic.CmdLine.runCommandLine (const id)' \| cabal repl -b wai-app-static`                                                  | REPL-based server                            |
| **Docker (nginx)** | `docker run --rm -p 8000:80 -v $PWD:/usr/share/nginx/html:ro nginx:alpine`                                                               | Clean, production‑like                       |
| **Docker (tiny)**  | `docker run --rm -p 8000:80 -v "$PWD":/www:ro p3terx/darkhttpd:1.13 /www`                                                                | Extremely small image (≈92kB)                |
| **BusyBox**        | `busybox httpd -f -p 8000`                                                                                                                | Works on many embedded systems               |
| **Caddy**          | `caddy file-server --listen :8000`                                                                                                        | Modern, automatic HTTPS capable              |
| **Lwan**           | `lwan -r .`                                                                                                                               | Lightweight, high-performance C server       |
| **thttpd**         | `thttpd -p 8000 -d .`                                                                                                                     | Tiny, efficient, time-tested                 |

---

## Detailed Examples

### Python

**Python 3.x (Recommended)**
```bash
python3 -m http.server 8000
```

**Python 2.x (Legacy)**
```bash
python -m SimpleHTTPServer 8000
```

**Twisted (Advanced)**
```bash
pip install twisted
twistd -n web -p 8000 --path .
```

---

### Node.js & Modern Runtimes

**http-server (Classic)**
```bash
npx http-server -p 8000
# Options: -c-1 (disable caching), -o (open browser)
```

**serve (Modern, by Vercel)**
```bash
npx serve -l 8000
# Supports SPA routing, CORS, and clean URLs
```

**serverino (Lightweight)**
```bash
npx serverino --port 8000
# Use --secure for automatic SSL with self-signed cert
```

**servor (SPA-focused)**
```bash
npx servor . index.html 8000
# Built for single-page applications
```

**Bun (Fastest)**
```bash
bunx serve -l 8000
# Drop-in replacement using Bun runtime
```

**Deno (Secure)**
```bash
deno run --allow-net --allow-read \
  https://deno.land/std/http/file_server.ts -p 8000
# Explicit permissions required
```

---

### Ruby

**Built-in (Ruby ≥1.9.2)**
```bash
ruby -run -ehttpd . -p 8000
```

**WEBrick (Classic)**
```bash
ruby -rwebrick -e'WEBrick::HTTPServer.new(
  :Port => 8000, :DocumentRoot => Dir.pwd).start'
```

**adsf (Gem)**
```bash
gem install adsf
adsf -p 8000
```

**Sinatra (No directory listings)**
```bash
gem install sinatra
ruby -rsinatra -e'set :public_folder, "."; set :port, 8000'
```

---

### Perl

**Mojolicious (Recommended)**
```bash
cpan Mojolicious::Lite
perl -MMojolicious::Lite -MCwd \
  -e 'app->static->paths->[0]=getcwd; app->start' \
  daemon -l http://*:8000
```

**Plack**
```bash
cpan Plack
plackup -MPlack::App::Directory \
  -e 'Plack::App::Directory->new(root=>".");' -p 8000
```

---

### PHP

**Built-in Server (PHP ≥5.4)**
```bash
php -S 127.0.0.1:8000
# Or bind to all interfaces:
php -S 0.0.0.0:8000
```

*Note: No directory listings by default.*

---

### Java

**Simple File Server (Java ≥18)**
```bash
jwebserver -p 8000
# Built-in, no dependencies required
```

**Winstone (Jetty wrapper)**
```bash
mvn dependency:get -Dartifact=org.jenkins-ci:winstone:5.20 \
  -DremoteRepositories=https://repo.jenkins-ci.org/public/
java -jar ~/.m2/repository/org/jenkins-ci/winstone/5.20/winstone-5.20.jar \
  --webroot=.
```

---

### Go

**Inline (No install)**
```bash
go run github.com/shurcooL/goexec@latest \
  'http.ListenAndServe(":8000", http.FileServer(http.Dir(".")))'
```

**goshs (Feature-rich)**
```bash
go install github.com/patrickhener/goshs@latest
goshs -p 8000
# Supports basic auth, TLS, upload capabilities
```

---

### Rust

**miniserve (Recommended)**
```bash
cargo install miniserve
miniserve -p 8000
# Features: upload, directory zip, QR codes, auth
```

**With specific features**
```bash
miniserve -p 8000 --upload-files --auth user:pass
```

---

### Other Languages

**D Language**
```bash
dub run serve -- . 8000
```

**Haskell (via Cabal)**
```bash
echo 'WaiAppStatic.CmdLine.runCommandLine (const id)' | \
  cabal repl -b wai-app-static
```

**Erlang**
```bash
erl -s inets -eval 'inets:start(httpd,[
  {server_name,"dev"},{document_root, "."},
  {server_root, "."},{port, 8000},
  {mime_types,[{"html","text/html"},{"css","text/css"},
               {"js","text/javascript"}]}]).'
```

---

### Universal Tools

**Caddy (Modern)**
```bash
caddy file-server --listen :8000
# Add --browse for directory listings
# Supports automatic HTTPS in production
```

**BusyBox (Embedded systems)**
```bash
busybox httpd -f -p 8000
```

**thttpd (Tiny, efficient)**
```bash
thttpd -p 8000 -d . -l /dev/stdout
```

**Lwan (High-performance C)**
```bash
lwan -r .
# Defaults to port 8080
```

---

### Docker Solutions

**Nginx (Production-like)**
```bash
docker run --rm -p 8000:80 \
  -v $PWD:/usr/share/nginx/html:ro \
  nginx:alpine
```

**darkhttpd (Minimal)**
```bash
docker run --rm -p 8000:80 \
  -v "$PWD":/www:ro \
  p3terx/darkhttpd:1.13 /www
```
*Image size: ~92kB*

---

## Feature Comparison

| Feature              | Python | Node serve | miniserve | Caddy | PHP |
|----------------------|--------|------------|-----------|-------|-----|
| Directory listings   | ✅     | ✅         | ✅        | ✅    | ❌  |
| SPA routing          | ❌     | ✅         | ❌        | ⚙️    | ❌  |
| File upload          | ❌     | ❌         | ✅        | ⚙️    | ⚙️  |
| Authentication       | ❌     | ⚙️         | ✅        | ⚙️    | ⚙️  |
| HTTPS/TLS            | ❌     | ⚙️         | ✅        | ✅    | ❌  |
| CORS support         | ❌     | ✅         | ✅        | ⚙️    | ⚙️  |
| Zero dependencies    | ✅     | ❌         | ❌        | ❌    | ✅  |

*Legend: ✅ Built-in, ⚙️ Configurable, ❌ Not available*

---

## Security Considerations

### Production Warning
⚠️ **These servers are for development only.** Do not use in production without:
- Proper authentication
- HTTPS/TLS encryption
- Rate limiting
- Security headers
- Input validation

### Best Practices

**Bind to localhost only** (when possible):
```bash
# Good - only accessible locally
python3 -m http.server 8000 --bind 127.0.0.1

# Risky - accessible from network
python3 -m http.server 8000 --bind 0.0.0.0
```

**Use authentication** for sensitive content:
```bash
miniserve -p 8000 --auth user:password
```

**Enable HTTPS** when sharing over network:
```bash
npx serverino --port 8000 --secure
```

---

## Common Use Cases

### Testing SPAs
```bash
# Serve with fallback to index.html for client-side routing
npx serve -l 8000 -s
```

### CORS Development
```bash
# Enable CORS for API testing
npx http-server -p 8000 --cors
```

### File Sharing (LAN)
```bash
# With upload capability
miniserve -p 8000 --upload-files --auth share:secret
```

### Static Site Preview
```bash
# Serve built static site
cd dist && python3 -m http.server 8000
```

---

## Troubleshooting

### Port Already in Use
```bash
# Check what's using the port
lsof -i :8000        # macOS/Linux
netstat -ano | findstr :8000  # Windows

# Use a different port
python3 -m http.server 8001
```

### Permission Denied
```bash
# Use port >1024 (doesn't require root)
python3 -m http.server 8080

# Or use sudo for port <1024 (not recommended)
sudo python3 -m http.server 80
```

### Firewall Blocking
```bash
# Linux (ufw)
sudo ufw allow 8000/tcp

# Linux (firewalld)
sudo firewall-cmd --add-port=8000/tcp

# macOS
# System Preferences → Security & Privacy → Firewall → Allow
```

---

## Installation Quick Reference

```bash
# Node.js tools (no install needed with npx)
npx serve
npx http-server

# Python (usually pre-installed)
python3 -m http.server

# Go tools
go install github.com/patrickhener/goshs@latest

# Rust tools
cargo install miniserve

# System package managers
brew install caddy           # macOS
apt install nginx           # Debian/Ubuntu
pacman -S thttpd           # Arch
```

---

## Meta

### Requirements for Inclusion

A solution qualifies for this list if it:

1. ✅ Serves static files from current/specified directory
2. ✅ Can run with a single command (one-time deps OK)
3. ✅ Serves basic MIME types correctly (HTML, CSS, JS, images)
4. ✅ Requires no configuration files
5. ✅ Can run in foreground (no forced daemon mode)

### Contributing

Found a better solution? Submit suggestions via:
- GitHub Issues
- Pull Requests
- Comments below

---

**Version:** 2.0.0 (2026 Edition)  
**Maintained by:** Community  
**License:** Public Domain  
**Last Updated:** February 2026

---

*Each command serves files at `http://localhost:8000` by default. Adjust ports as needed.*
