#!/usr/bin/env node

/**
 * Payload Builder Script
 *
 * This tool processes payloads__.js and outputs:
 * - payloads.min.js       → Minified JavaScript (via Terser or fallback)
 * - payloads.bmk.js       → Bookmarklet-compatible format
 * - payloads.versioned.[hash].js → Content-hashed for CDN or long-term caching
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const INPUT = path.resolve(__dirname, 'payloads__.js');
const MINIFIED = path.resolve(__dirname, 'payloads.min.js');
const BOOKMARKLET = path.resolve(__dirname, 'payloads.bmk.js');

// ------------------ HELPERS ------------------

function sha256(content) {
  return crypto.createHash('sha256').update(content).digest('hex').slice(0, 12);
}

function fallbackMinify(js) {
  console.warn('[!] Using fallback minifier (lossless but crude)');
  return js
    .replace(/\/\/.*$/gm, '') // remove single-line comments
    .replace(/\n+/g, ' ')     // collapse newlines
    .replace(/\s+/g, ' ')     // collapse whitespace
    .replace(/\s*([{};,:])\s*/g, '$1') // tighten delimiters
    .trim();
}

function ensureInputFile() {
  if (!fs.existsSync(INPUT)) {
    console.error(`Error: ${INPUT} not found.`);
    process.exit(1);
  }
}

// ------------------ MAIN BUILD ------------------

function build() {
  ensureInputFile();

  console.log(`[+] Reading ${path.basename(INPUT)}...`);
  const raw = fs.readFileSync(INPUT, 'utf-8');

  let minified = '';
  try {
    console.log('[+] Minifying with Terser...');
    minified = execSync(`npx terser "${INPUT}" --compress --mangle`, { encoding: 'utf-8' });
  } catch (err) {
    console.warn('[!] Terser failed or not found. Falling back...');
    minified = fallbackMinify(raw);
  }

  const hash = sha256(minified);
  const versionedFilename = `payloads.versioned.${hash}.js`;
  const versionedPath = path.resolve(__dirname, versionedFilename);

  // Save minified output
  fs.writeFileSync(MINIFIED, minified);
  console.log(`[+] Saved minified: ${MINIFIED}`);

  // Save bookmarklet
  const bookmarklet = 'javascript:' + encodeURIComponent(minified);
  fs.writeFileSync(BOOKMARKLET, bookmarklet);
  console.log(`[+] Saved bookmarklet: ${BOOKMARKLET}`);

  // Save versioned file
  fs.writeFileSync(versionedPath, minified);
  console.log(`[+] Saved versioned: ${versionedPath}`);

  console.log('\n[✓] Build complete.');
}

// Run it
build();
