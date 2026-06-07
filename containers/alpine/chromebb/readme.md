
## 📦 Enhanced Project Structure, (..lol..)

```
headless-chrome-modern/
├── Dockerfile
├── Dockerfile.dev
├── docker-compose.yml
├── package.json
├── tsconfig.json
├── .dockerignore
├── .github/workflows/ci.yml
├── src/
│   ├── server.ts
│   ├── config/
│   │   └── index.ts
│   ├── controllers/
│   │   ├── screenshot.controller.ts
│   │   ├── pdf.controller.ts
│   │   ├── metrics.controller.ts
│   │   └── health.controller.ts
│   ├── middleware/
│   │   ├── auth.middleware.ts
│   │   ├── ratelimit.middleware.ts
│   │   ├── validation.middleware.ts
│   │   └── error.middleware.ts
│   ├── services/
│   │   ├── browser.service.ts
│   │   └── cache.service.ts
│   ├── types/
│   │   └── index.ts
│   └── utils/
│       ├── logger.ts
│       └── validators.ts
├── tests/
│   ├── integration/
│   └── unit/
├── examples/
│   ├── client.js
│   └── k8s/
└── docs/
    └── api.md
```

## 🏗️ Enhanced Dockerfile with Multi-stage Build

```dockerfile
# Dockerfile
FROM node:20-alpine AS base

# Install dependencies and Chrome
RUN apk add --no-cache \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont \
    dumb-init

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser \
    CHROME_BIN=/usr/bin/chromium-browser \
    NODE_ENV=production

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S chromeuser -u 1001 -G nodejs

# Development stage
FROM base AS development
WORKDIR /app
COPY package*.json ./
RUN npm ci --include=dev
COPY . .
RUN chown -R chromeuser:nodejs /app
USER chromeuser
EXPOSE 3000
CMD ["npm", "run", "dev"]

# Build stage
FROM base AS build
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci --include=dev
COPY src/ ./src/
RUN npm run build && npm prune --production

# Production stage
FROM base AS production
WORKDIR /app

# Copy built application
COPY --from=build --chown=chromeuser:nodejs /app/dist ./dist
COPY --from=build --chown=chromeuser:nodejs /app/node_modules ./node_modules
COPY --from=build --chown=chromeuser:nodejs /app/package.json ./

# Create required directories with proper permissions
RUN mkdir -p /app/tmp /app/cache && \
    chown -R chromeuser:nodejs /app

USER chromeuser

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD node -e "fetch('http://localhost:3000/health').then(r => r.ok ? process.exit(0) : process.exit(1))"

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/server.js"]
```

## 🚀 Modern TypeScript Server

```typescript
// src/server.ts
import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import { config } from './config/index.js';
import { errorMiddleware } from './middleware/error.middleware.js';
import { authMiddleware } from './middleware/auth.middleware.js';
import { logger } from './utils/logger.js';
import { screenshotController } from './controllers/screenshot.controller.js';
import { pdfController } from './controllers/pdf.controller.js';
import { metricsController } from './controllers/metrics.controller.js';
import { healthController } from './controllers/health.controller.js';

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

app.use(compression());
app.use(cors({ origin: config.corsOrigins }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: config.rateLimitMax,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Parse JSON payloads
app.use(express.json({ limit: '10mb' }));

// Request logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
  });
  next();
});

// Health check (no auth required)
app.get('/health', healthController.healthCheck);
app.get('/ready', healthController.readinessCheck);

// API routes (with auth)
app.use('/api', authMiddleware);
app.post('/api/screenshot', screenshotController.takeScreenshot);
app.post('/api/pdf', pdfController.generatePdf);
app.post('/api/metrics', metricsController.collectMetrics);
app.post('/api/batch', screenshotController.batchScreenshots);

// Error handling
app.use(errorMiddleware);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

const server = app.listen(config.port, () => {
  logger.info(`🚀 Server running on port ${config.port}`, {
    environment: config.nodeEnv,
    version: config.version,
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

export default app;
```

## ⚙️ Configuration Management

```typescript
// src/config/index.ts
import { z } from 'zod';
import { logger } from '../utils/logger.js';

const configSchema = z.object({
  nodeEnv: z.enum(['development', 'production', 'test']).default('production'),
  port: z.coerce.number().default(3000),
  version: z.string().default('1.0.0'),
  corsOrigins: z.string().transform(val => val.split(',')).default('*'),
  rateLimitMax: z.coerce.number().default(100),
  authToken: z.string().optional(),
  puppeteer: z.object({
    maxConcurrent: z.coerce.number().default(3),
    timeout: z.coerce.number().default(30000),
    headless: z.boolean().default(true),
    args: z.array(z.string()).default([
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--disable-extensions',
      '--disable-default-apps',
      '--no-first-run',
      '--no-zygote',
      '--single-process',
      '--disable-background-timer-throttling',
      '--disable-backgrounding-occluded-windows',
      '--disable-renderer-backgrounding',
    ]),
  }),
  cache: z.object({
    ttl: z.coerce.number().default(300000), // 5 minutes
    maxSize: z.coerce.number().default(100),
  }),
});

const parseConfig = () => {
  const rawConfig = {
    nodeEnv: process.env.NODE_ENV,
    port: process.env.PORT,
    version: process.env.npm_package_version,
    corsOrigins: process.env.CORS_ORIGINS,
    rateLimitMax: process.env.RATE_LIMIT_MAX,
    authToken: process.env.AUTH_TOKEN,
    puppeteer: {
      maxConcurrent: process.env.PUPPETEER_MAX_CONCURRENT,
      timeout: process.env.PUPPETEER_TIMEOUT,
      headless: process.env.PUPPETEER_HEADLESS !== 'false',
    },
    cache: {
      ttl: process.env.CACHE_TTL,
      maxSize: process.env.CACHE_MAX_SIZE,
    },
  };

  try {
    return configSchema.parse(rawConfig);
  } catch (error) {
    logger.error('Invalid configuration', error);
    process.exit(1);
  }
};

export const config = parseConfig();
```

## 🎯 Enhanced Browser Service

```typescript
// src/services/browser.service.ts
import puppeteer, { Browser, Page, PuppeteerLifeCycleEvent } from 'puppeteer';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

class BrowserService {
  private browserPool: Browser[] = [];
  private activeSessions = 0;

  async getBrowser(): Promise<Browser> {
    if (this.activeSessions >= config.puppeteer.maxConcurrent) {
      throw new Error('Maximum concurrent sessions reached');
    }

    let browser = this.browserPool.pop();
    
    if (!browser || browser.process()?.killed) {
      browser = await puppeteer.launch({
        headless: config.puppeteer.headless,
        args: config.puppeteer.args,
        timeout: config.puppeteer.timeout,
        executablePath: process.env.PUPPETEER_EXECUTABLE_PATH,
      });
      
      logger.debug('New browser instance created');
    }

    this.activeSessions++;
    return browser;
  }

  async releaseBrowser(browser: Browser): Promise<void> {
    this.activeSessions--;
    
    // Check if browser is still healthy
    if (browser.process()?.killed) {
      return;
    }

    // Close all pages except one blank page
    const pages = await browser.pages();
    await Promise.all(pages.slice(1).map(page => page.close()));
    
    if (pages[0]) {
      await pages[0].goto('about:blank');
    }

    // Return to pool if under limit, otherwise close
    if (this.browserPool.length < 2) {
      this.browserPool.push(browser);
    } else {
      await browser.close();
    }
  }

  async withBrowser<T>(
    operation: (browser: Browser) => Promise<T>
  ): Promise<T> {
    const browser = await this.getBrowser();
    try {
      return await operation(browser);
    } finally {
      await this.releaseBrowser(browser);
    }
  }

  async withPage<T>(
    operation: (page: Page) => Promise<T>,
    options: {
      waitUntil?: PuppeteerLifeCycleEvent;
      timeout?: number;
      viewport?: { width: number; height: number };
    } = {}
  ): Promise<T> {
    return this.withBrowser(async (browser) => {
      const page = await browser.newPage();
      
      try {
        if (options.viewport) {
          await page.setViewport(options.viewport);
        }
        
        page.setDefaultTimeout(options.timeout || config.puppeteer.timeout);
        
        return await operation(page);
      } finally {
        await page.close();
      }
    });
  }

  async cleanup(): Promise<void> {
    await Promise.all(this.browserPool.map(browser => browser.close()));
    this.browserPool = [];
    this.activeSessions = 0;
  }

  getStats() {
    return {
      poolSize: this.browserPool.length,
      activeSessions: this.activeSessions,
      maxConcurrent: config.puppeteer.maxConcurrent,
    };
  }
}

export const browserService = new BrowserService();
```

## 📸 Enhanced Screenshot Controller

```typescript
// src/controllers/screenshot.controller.ts
import { Request, Response } from 'express';
import { z } from 'zod';
import { browserService } from '../services/browser.service.js';
import { cacheService } from '../services/cache.service.js';
import { logger } from '../utils/logger.js';
import { validateRequest } from '../utils/validators.js';

const screenshotSchema = z.object({
  url: z.string().url(),
  options: z.object({
    width: z.number().min(100).max(4000).default(1920),
    height: z.number().min(100).max(4000).default(1080),
    fullPage: z.boolean().default(false),
    quality: z.number().min(1).max(100).default(90),
    format: z.enum(['png', 'jpeg', 'webp']).default('png'),
    mobile: z.boolean().default(false),
    waitFor: z.string().optional(),
    delay: z.number().min(0).max(10000).default(0),
  }).default({}),
});

const batchSchema = z.object({
  urls: z.array(z.string().url()).min(1).max(10),
  options: screenshotSchema.shape.options,
});

class ScreenshotController {
  async takeScreenshot(req: Request, res: Response): Promise<void> {
    try {
      const { url, options } = validateRequest(screenshotSchema, req.body);
      
      // Check cache
      const cacheKey = `screenshot:${JSON.stringify({ url, options })}`;
      const cached = cacheService.get(cacheKey);
      if (cached) {
        logger.debug('Returning cached screenshot', { url });
        res.type(`image/${options.format}`).send(cached);
        return;
      }

      const startTime = Date.now();
      
      const buffer = await browserService.withPage(
        async (page) => {
          // Set viewport
          await page.setViewport({
            width: options.width,
            height: options.height,
            isMobile: options.mobile,
          });

          // Navigate to URL
          await page.goto(url, { 
            waitUntil: 'networkidle2',
            timeout: 30000 
          });

          // Optional wait
          if (options.waitFor) {
            await page.waitForSelector(options.waitFor, { timeout: 10000 });
          }

          if (options.delay > 0) {
            await page.waitForTimeout(options.delay);
          }

          // Take screenshot
          return await page.screenshot({
            fullPage: options.fullPage,
            type: options.format as 'png' | 'jpeg' | 'webp',
            quality: options.format === 'png' ? undefined : options.quality,
          });
        },
        {
          viewport: { width: options.width, height: options.height },
          timeout: 45000,
        }
      );

      const duration = Date.now() - startTime;
      
      // Cache result
      cacheService.set(cacheKey, buffer);

      logger.info('Screenshot captured', {
        url,
        format: options.format,
        size: buffer.length,
        duration,
      });

      res.type(`image/${options.format}`).send(buffer);
    } catch (error) {
      logger.error('Screenshot failed', { url: req.body.url, error });
      res.status(500).json({ 
        error: 'Screenshot capture failed',
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  async batchScreenshots(req: Request, res: Response): Promise<void> {
    try {
      const { urls, options } = validateRequest(batchSchema, req.body);
      
      const results = await Promise.allSettled(
        urls.map(async (url) => {
          try {
            const buffer = await browserService.withPage(
              async (page) => {
                await page.setViewport({
                  width: options.width,
                  height: options.height,
                });
                
                await page.goto(url, { waitUntil: 'networkidle2' });
                
                return await page.screenshot({
                  fullPage: options.fullPage,
                  type: options.format as 'png' | 'jpeg' | 'webp',
                  quality: options.format === 'png' ? undefined : options.quality,
                });
              }
            );
            
            return {
              url,
              success: true,
              data: buffer.toString('base64'),
              size: buffer.length,
            };
          } catch (error) {
            return {
              url,
              success: false,
              error: error instanceof Error ? error.message : 'Unknown error',
            };
          }
        })
      );

      const response = results.map((result) => result.value);
      res.json({ results: response });
    } catch (error) {
      logger.error('Batch screenshot failed', error);
      res.status(500).json({ error: 'Batch operation failed' });
    }
  }
}

export const screenshotController = new ScreenshotController();
```

## 🚨 Enhanced Security & Middleware

```typescript
// src/middleware/auth.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

export const authMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  if (!config.authToken) {
    return next(); // No auth required
  }

  const authHeader = req.headers.authorization;
  const token = authHeader?.replace('Bearer ', '');

  if (!token || token !== config.authToken) {
    logger.warn('Unauthorized request', { ip: req.ip, path: req.path });
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  next();
};

// src/middleware/validation.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';

export const validateBody = (schema: z.ZodSchema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({
          error: 'Validation failed',
          details: error.errors,
        });
        return;
      }
      next(error);
    }
  };
};
```

## 📦 Modern package.json

```json
{
  "name": "headless-chrome-modern",
  "version": "2.0.0",
  "description": "Modern, secure headless Chrome API with TypeScript",
  "type": "module",
  "scripts": {
    "dev": "tsx watch src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js",
    "test": "vitest",
    "test:coverage": "vitest --coverage",
    "lint": "eslint src/",
    "lint:fix": "eslint src/ --fix",
    "docker:build": "docker build -t headless-chrome .",
    "docker:dev": "docker-compose up -d",
    "docker:prod": "docker build --target production -t headless-chrome:prod ."
  },
  "dependencies": {
    "express": "^4.18.2",
    "puppeteer": "^21.5.2",
    "helmet": "^7.1.0",
    "compression": "^1.7.4",
    "cors": "^2.8.5",
    "express-rate-limit": "^7.1.5",
    "zod": "^3.22.4",
    "winston": "^3.11.0",
    "lru-cache": "^10.0.2"
  },
  "devDependencies": {
    "@types/express": "^4.17.21",
    "@types/compression": "^1.7.5",
    "@types/cors": "^2.8.17",
    "@typescript-eslint/eslint-plugin": "^6.13.1",
    "@typescript-eslint/parser": "^6.13.1",
    "eslint": "^8.54.0",
    "tsx": "^4.6.0",
    "typescript": "^5.3.2",
    "vitest": "^1.0.0",
    "@vitest/coverage-v8": "^1.0.0"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
```

## 🐳 Docker Compose for Development

```yaml
# docker-compose.yml
version: '3.8'

services:
  chrome-api:
    build:
      context: .
      target: development
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
      - AUTH_TOKEN=dev-token-123
      - PUPPETEER_HEADLESS=true
      - RATE_LIMIT_MAX=1000
    volumes:
      - .:/app
      - /app/node_modules
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - SYS_ADMIN  # Required for Chrome sandbox
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data

volumes:
  redis-data:
```

## 🧪 Enhanced Testing

```typescript
// tests/integration/screenshot.test.ts
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import app from '../../src/server.js';

describe('Screenshot API', () => {
  beforeAll(async () => {
    // Setup test environment
  });

  afterAll(async () => {
    // Cleanup
  });

  test('should capture screenshot', async () => {
    const response = await request(app)
      .post('/api/screenshot')
      .send({
        url: 'https://example.com',
        options: {
          width: 1280,
          height: 720,
          format: 'png'
        }
      });

    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toContain('image/png');
    expect(response.body).toBeInstanceOf(Buffer);
  });

  test('should validate request body', async () => {
    const response = await request(app)
      .post('/api/screenshot')
      .send({
        url: 'invalid-url'
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe('Validation failed');
  });
});
```

## 🚀 Key Improvements:

### 🔒 **Security Enhancements:**
- **Multi-stage Docker builds** with non-root user
- **Helmet.js** for security headers
- **Rate limiting** and request validation
- **Authentication middleware** with Bearer tokens
- **Resource limits** and security capabilities

### ⚡ **Performance & Reliability:**
- **Browser pooling** for better resource management
- **Caching** with TTL and size limits
- **Connection pooling** and graceful shutdowns
- **Health checks** and monitoring endpoints
- **Batch operations** for multiple URLs

### 🛠️ **Modern Development:**
- **TypeScript** with strict typing
- **Zod** for runtime validation
- **ESM modules** and modern Node.js
- **Comprehensive testing** with Vitest
- **Docker Compose** for development

### 📊 **Advanced Features:**
- **Multiple output formats** (PNG, JPEG, WebP)
- **Mobile device emulation**
- **Performance metrics collection**
- **Configurable wait conditions**
- **Batch screenshot processing**

##
##

##
##

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

