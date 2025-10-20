#!/usr/bin/env node

/**
 * generate_har.js
 *
 * Robust Puppeteer-based HAR generator for containerized environments... (testing)..
 * Designed for safe automation, CI, and sandboxed capture.
 *
 * Usage:
 *   node generate_har.js [url] [outputDir]
 *
 * Environment Variables:
 *   TARGET_URL    – override target URL
 *   OUTPUT_DIR    – override output directory
 *   CAPTURE_TIME  – milliseconds to wait after load (default 5000)
 *
 * Example:
 *   TARGET_URL="https://doomrocket.com" node generate_har.js
 */

const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

// ----------------------------
// Config
// ----------------------------
const targetUrl = process.argv[2] || process.env.TARGET_URL || 'https://doomrocket.com';
const outputDir = process.argv[3] || process.env.OUTPUT_DIR || '/usr/src/app/output';
const captureTime = Number(process.env.CAPTURE_TIME || 5000);
const outputFile = path.join(outputDir, new URL(targetUrl).hostname + '.har');

const timestamp = () => new Date().toISOString();

// ----------------------------
// Main Logic
// ----------------------------
(async () => {
  console.log(`[${timestamp()}] Starting HAR capture for ${targetUrl}`);

  let browser;
  try {
    browser = await puppeteer.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--ignore-certificate-errors',
      ],
    });

    const page = await browser.newPage();
    const requests = [];

    await page.setRequestInterception(true);

    page.on('request', (req) => {
      requests.push({
        method: req.method(),
        url: req.url(),
        headers: req.headers(),
        postData: req.postData() || null,
        timestamp: Date.now(),
      });
      req.continue();
    });

    page.on('response', async (res) => {
      try {
        const matched = requests.find(r => r.url === res.url());
        if (matched) {
          matched.status = res.status();
          matched.statusText = res.statusText();
          matched.responseHeaders = res.headers();
          matched.timing = res.timing();
        }
      } catch (err) {
        console.warn(`[WARN] Error processing response for ${res.url()}: ${err.message}`);
      }
    });

    console.log(`[${timestamp()}] Navigating to ${targetUrl}`);
    await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 60000 });

    console.log(`[${timestamp()}] Capturing network activity for ${captureTime}ms...`);
    await page.waitForTimeout(captureTime);

    // Generate HAR-like JSON
    const har = {
      log: {
        version: '1.2',
        creator: { name: 'Puppeteer HAR Generator', version: '2.0.0' },
        pages: [
          {
            startedDateTime: new Date(requests[0]?.timestamp || Date.now()).toISOString(),
            id: targetUrl,
            title: await page.title(),
            pageTimings: {},
          },
        ],
        entries: requests.map(r => ({
          startedDateTime: new Date(r.timestamp).toISOString(),
          request: {
            method: r.method,
            url: r.url,
            headers: r.headers,
            postData: r.postData,
          },
          response: {
            status: r.status || 0,
            statusText: r.statusText || '',
            headers: r.responseHeaders || {},
          },
          cache: {},
          timings: r.timing || {},
        })),
      },
    };

    // Ensure output dir
    fs.mkdirSync(outputDir, { recursive: true });

    // Save HAR file
    fs.writeFileSync(outputFile, JSON.stringify(har, null, 2));
    console.log(`[${timestamp()}] HAR successfully saved: ${outputFile}`);

  } catch (err) {
    console.error(`[${timestamp()}] ERROR: ${err.stack || err.message}`);
    process.exitCode = 1;
  } finally {
    if (browser) {
      console.log(`[${timestamp()}] Closing browser...`);
      await browser.close().catch(() => {});
    }
    console.log(`[${timestamp()}] Done.`);
  }
})();
