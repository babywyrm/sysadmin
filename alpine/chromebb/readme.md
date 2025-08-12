

# 🖥️ Building a Secure, Flexible Headless Chrome Container with Node.js & Puppeteer

## Why Headless Chrome in Docker?

Headless Chrome is perfect for:

- **Automated UI testing** (Jest, Mocha, Cypress, etc.)
- **Web scraping & crawling**
- **PDF generation** from HTML
- **Screenshot capture** for monitoring or visual regression
- **Performance metrics** collection

Running it in Docker gives you:

- **Reproducibility** — same environment everywhere
- **Isolation** — sandboxed from the host
- **Scalability** — run in Kubernetes, Fargate, Cloud Run
- **Portability** — ship the same image to dev, staging, prod

---

## 📦 Project Structure

```
headless-chrome/
├── Dockerfile
├── package.json
├── server.js
└── examples/
    ├── screenshot.js
    ├── pdf.js
    ├── mobile-screenshot.js
    └── performance-metrics.js
```

---

## server.js — Express API for Headless Chrome

```js
const express = require('express');
const puppeteer = require('puppeteer');

const app = express();
const PORT = process.env.PORT || 3000;

// Screenshot endpoint
app.get('/screenshot', async (req, res) => {
  const url = req.query.url || 'https://example.com';
  console.log(`Taking screenshot of ${url}`);

  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-gpu']
  });

  const page = await browser.newPage();
  await page.goto(url, { waitUntil: 'networkidle2' });
  const buffer = await page.screenshot({ fullPage: true });
  await browser.close();

  res.type('image/png').send(buffer);
});

// PDF endpoint
app.get('/pdf', async (req, res) => {
  const url = req.query.url || 'https://example.com';
  console.log(`Generating PDF of ${url}`);

  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox']
  });

  const page = await browser.newPage();
  await page.goto(url, { waitUntil: 'networkidle2' });
  const pdfBuffer = await page.pdf({ format: 'A4' });
  await browser.close();

  res.type('application/pdf').send(pdfBuffer);
});

// Performance metrics endpoint
app.get('/metrics', async (req, res) => {
  const url = req.query.url || 'https://example.com';
  console.log(`Collecting metrics for ${url}`);

  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox']
  });

  const page = await browser.newPage();
  await page.goto(url, { waitUntil: 'networkidle2' });
  const metrics = await page.metrics();
  await browser.close();

  res.json(metrics);
});

app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
```

---

## Dockerfile

```dockerfile
FROM node:18-slim

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD true

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

WORKDIR /usr/src/app

COPY package.json package-lock.json ./
RUN npm ci --only=production

COPY server.js ./

EXPOSE 3000
CMD ["node", "server.js"]
```

---

## 🧪 Example Puppeteer Scripts

### 1. Screenshot with Mobile Emulation
```js
const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.emulate(puppeteer.devices['iPhone X']);
  await page.goto('https://example.com');
  await page.screenshot({ path: 'mobile.png', fullPage: true });
  await browser.close();
})();
```

### 2. Generate PDF
```js
const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.goto('https://example.com', { waitUntil: 'networkidle2' });
  await page.pdf({ path: 'page.pdf', format: 'A4' });
  await browser.close();
})();
```

### 3. Collect Performance Metrics
```js
const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.goto('https://example.com', { waitUntil: 'networkidle2' });
  console.log(await page.metrics());
  await browser.close();
})();
```

---

## 🔒 Security Considerations

Running a browser in a container **is not inherently safe** — here’s how to harden it:

### 1. Drop Root Privileges
```dockerfile
RUN useradd -m chromeuser
USER chromeuser
```
Run Chrome as a non-root user to limit damage if compromised.

### 2. Use `--no-sandbox` Carefully
- Chrome’s sandbox is a security feature.  
- In Docker, it often fails without extra privileges, so `--no-sandbox` is common — but it removes a layer of protection.  
- If possible, configure the container to allow the sandbox (requires `seccomp` profile adjustments).

### 3. Limit Capabilities
When running the container:
```bash
docker run --cap-drop=ALL --security-opt=no-new-privileges ...
```

### 4. Read-Only Filesystem
```bash
docker run --read-only ...
```
Prevents writes to the container FS except for tmpfs mounts.

### 5. Network Restrictions
If the browser doesn’t need outbound internet, block it:
```bash
docker network disconnect bridge <container>
```

### 6. Resource Limits
Prevent Chrome from exhausting host resources:
```bash
docker run --memory=512m --cpus=1 ...
```

---

## 🚀 Deployment Ideas

- **Kubernetes**: Deploy as a microservice, scale horizontally for parallel jobs.
- **Serverless**: Run in AWS Lambda with a custom runtime (e.g., `chrome-aws-lambda`).
- **CI/CD**: Integrate into GitHub Actions or GitLab CI for automated visual regression tests.

---

## 📚 References

- Puppeteer Docs: https://pptr.dev  
- Zenika Alpine Chrome: https://github.com/Zenika/alpine-chrome  
- LogRocket Guide: https://blog.logrocket.com/setting-headless-chrome-node-js-server-docker  
- Google Chrome DevTools Protocol: https://chromedevtools.github.io/devtools-protocol/

