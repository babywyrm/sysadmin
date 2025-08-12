

# Building a Secure, Lightweight Headless Chrome Container with Node.js

## Why Headless Chrome?

Headless Chrome lets you run end-to-end tests, take screenshots, crawl pages, or generate PDFs without a GUI. Using it in a container gives you:

- Fast, repeatable CI builds  
- On-demand scaling (Kubernetes, Fargate, Cloud Run)  
- Isolation and security  

Puppeteer (the official Node.js Chrome library) provides a clean API over the Chrome DevTools Protocol.

## Overview

We’ll build a Docker image that:

1. Installs Google Chrome Stable  
2. Runs a simple Express.js + Puppeteer server  
3. Exposes a `/screenshot` endpoint  
4. Locks down Chrome with `--no-sandbox`  

### server.js

```js
// server.js
const express = require('express');
const puppeteer = require('puppeteer');

const app = express();
const PORT = process.env.PORT || 3000;

app.get('/screenshot', async (req, res) => {
  console.log('Taking screenshot...');
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-gpu']
  });
  const page = await browser.newPage();
  await page.goto(req.query.url || 'https://example.com');
  const buffer = await page.screenshot({ fullPage: true });
  await browser.close();

  res.type('image/png').send(buffer);
});

app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
```

## Dockerfile

```dockerfile
# 1. Start from Node.js slim
FROM node:16-slim

# 2. Skip Puppeteer’s Chromium download
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD true

# 3. Install Chrome and fonts
RUN apt-get update && apt-get install -y \
      wget gnupg ca-certificates fonts-liberation \
    && wget -qO - https://dl-ssl.google.com/linux/linux_signing_key.pub \
       | gpg --dearmor > /usr/share/keyrings/google.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/google.gpg arch=amd64] \
       http://dl.google.com/linux/chrome/deb/ stable main" \
       > /etc/apt/sources.list.d/google.list \
    && apt-get update \
    && apt-get install -y google-chrome-stable --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# 4. App directory
WORKDIR /usr/src/app

# 5. Copy and install Node.js deps
COPY package.json package-lock.json ./
RUN npm ci --only=production

# 6. Copy app code
COPY server.js ./

# 7. Expose port & run
EXPOSE 3000
CMD ["node", "server.js"]
```

## Build & Run

```bash
# Build image (Linux/amd64)
docker build -t headless-chrome-node .

# Run locally
docker run --rm -p 3000:3000 headless-chrome-node
```

Access a screenshot at:  
```
http://localhost:3000/screenshot?url=https://www.google.com
```

## Common Gotchas

- Chrome’s sandbox requires extra permissions. In many containers you must run `--no-sandbox`.  
- Keep one browser-per-request for stability. Reusing pages in a long-lived browser can leak memory.  
- Ensure you have the necessary fonts (e.g. `fonts-liberation`) for modern web pages.  

## Security Tips

- Run Chrome under a non-root user inside the container.  
- Limit container capabilities (`--cap-drop=ALL`).  
- Pin to a specific Chrome version to avoid surprises.

## References

- NPM Puppeteer: https://github.com/puppeteer/puppeteer  
- Docker + Headless Chrome community project: https://github.com/Zenika/alpine-chrome  
- LogRocket guide: https://blog.logrocket.com/setting-headless-chrome-node-js-server-docker  
- Zenika article: https://medium.com/zenika/crafting-the-perfect-container-to-play-with-a-headless-chrome-d920ec2f3c9b

##
##
