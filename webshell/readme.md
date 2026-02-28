

## Python

```bash
python3 -m http.server 8000
```

> Python 2 is EOL. Use Python 3.

---

## Node.js

### npx (no install needed)

```bash
npx serve -l 8000
```

### http-server

```bash
npm install -g http-server
http-server -p 8000
```

### Vite (modern dev server with HMR, if you need it)

```bash
npx vite --port 8000
```

---

## PHP

```bash
php -S localhost:8000
```

> PHP >= 5.4. No directory listings.

---

## Ruby

```bash
ruby -run -ehttpd . -p 8000
```

---

## Go

```bash
goexec 'http.ListenAndServe(":8000", http.FileServer(http.Dir(".")))'
```

Or with the `caddy` file server:

```bash
caddy file-server --listen :8000
```

Depends on [Caddy](https://caddyserver.com/).

---

## Rust

```bash
cargo install miniserve
miniserve . --port 8000
```

Depends on [miniserve](https://github.com/svenstaro/miniserve). Has directory listings, upload support, and auth.

---

## Deno

```bash
deno run --allow-net --allow-read https://deno.land/std/http/file_server.ts -p 8000
```

---

## BusyBox

```bash
busybox httpd -f -p 8000
```

Useful on minimal Linux environments.

---

## Caddy (standalone)

```bash
caddy file-server --listen :8000 --browse
```

Depends on [Caddy](https://caddyserver.com/). Clean UI, directory listings, HTTPS-ready.

---

## Python + CORS headers (bonus)

```bash
python3 -c "
import http.server, sys
class CORSHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()
http.server.HTTPServer(('', 8000), CORSHandler).serve_forever()
"
```

Useful for local API/fetch testing.

---

## Meta

To qualify for this list, a solution must:

1. Serve static files from the current (or specified) directory as the server root
2. Be runnable as a single command (one-time installs are fine)
3. Serve common file types (`html`, `css`, `js`, images) with correct MIME types
4. Require no config files or framework setup
5. Run in the foreground (no daemons)

---

**Removed:**
- Python 2 (EOL since 2020)
- Twisted, WEBrick, adsf, Sinatra, Plack, Mojolicious, node-static (outdated/unmaintained)
- Erlang httpd (verbose and niche)
- IIS Express (outdated)

**Added:**
- `npx serve` (most common modern choice)
- Caddy file server
- `miniserve` (Rust, feature-rich)
- Deno std file server
- Python CORS one-liner (common real-world need for webshell/dev work)
