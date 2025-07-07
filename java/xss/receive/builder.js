#!/usr/bin/env node

/**
 * JS Payload Builder
 * - Minifies payloads__.js
 * - Generates payloads.min.js and payloads.bmk.js
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const INPUT = path.resolve(__dirname, 'payloads__.js');
const MINIFIED = path.resolve(__dirname, 'payloads.min.js');
const BOOKMARKLET = path.resolve(__dirname, 'payloads.bmk.js');

function fallbackMinify(js) {
  // crude inline minification fallback
  return js
    .replace(/\/\/.*$/gm, '')
    .replace(/\s*([{};,:])\s*/g, '$1')
    .replace(/\n+/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function build() {
  if (!fs.existsSync(INPUT)) {
    console.error(`Missing file: ${INPUT}`);
    process.exit(1);
  }

  console.log(`Reading ${INPUT}...`);
  const raw = fs.readFileSync(INPUT, 'utf-8');

  let minified = '';
  try {
    console.log('Minifying with Terser...');
    minified = execSync(`npx terser "${INPUT}"`, { encoding: 'utf-8' });
  } catch (err) {
    console.warn('Terser failed or not installed. Falling back to regex-based minification...');
    minified = fallbackMinify(raw);
  }

  console.log(`Writing ${MINIFIED}`);
  fs.writeFileSync(MINIFIED, minified, 'utf-8');

  const bookmarklet = 'javascript:' + encodeURIComponent(minified);
  console.log(`Writing ${BOOKMARKLET}`);
  fs.writeFileSync(BOOKMARKLET, bookmarklet, 'utf-8');

  console.log('Done.');
}

build();
