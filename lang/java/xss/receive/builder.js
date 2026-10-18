#!/usr/bin/env node

/**
 * Payload Builder CLI Tool
 * -------------------------
 * Generates:
 *  - Minified JS
 *  - Bookmarklet string
 *  - Versioned hash-based payload file
 *  - Optional HTML injection
 *  - Optional --watch rebuild
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');
const chokidar = require('chokidar'); // npm install chokidar

const args = process.argv.slice(2);
const INPUT = path.resolve(__dirname, 'payloads__.js');
const MINIFIED = path.resolve(__dirname, 'payloads.min.js');
const BOOKMARKLET = path.resolve(__dirname, 'payloads.bmk.js');

let watchMode = args.includes('--watch');
let injectTarget = args.includes('--inject') ? args[args.indexOf('--inject') + 1] : null;

function sha256(content) {
  return crypto.createHash('sha256').update(content).digest('hex').slice(0, 12);
}

function fallbackMinify(js) {
  console.log('[~] Terser unavailable. Using fallback minifier.');
  return js
    .replace(/\/\/.*$/gm, '')
    .replace(/\n+/g, ' ')
    .replace(/\s+/g, ' ')
    .replace(/\s*([{};,:])\s*/g, '$1')
    .trim();
}

function ensureInputFile() {
  if (!fs.existsSync(INPUT)) {
    console.error(`[X] Error: ${INPUT} not found.`);
    process.exit(1);
  }
}

function minifyInput(raw) {
  try {
    console.log('[+] Using Terser to minify...');
    return execSync(`npx terser "${INPUT}" --compress --mangle`, { encoding: 'utf-8' });
  } catch (err) {
    return fallbackMinify(raw);
  }
}

function injectIntoHTML(targetFile, versionedFileName) {
  if (!fs.existsSync(targetFile)) {
    console.warn(`[!] Injection target not found: ${targetFile}`);
    return;
  }

  let html = fs.readFileSync(targetFile, 'utf-8');
  const pattern = /<script\s+src="payloads\.versioned\..*?\.js"><\/script>/;
  const newScript = `<script src="${versionedFileName}"></script>`;

  if (pattern.test(html)) {
    html = html.replace(pattern, newScript);
  } else {
    // fallback: append before closing </body>
    html = html.replace(/<\/body>/i, `  ${newScript}\n</body>`);
  }

  fs.writeFileSync(targetFile, html);
  console.log(`[+] Injected <script> into ${targetFile}`);
}

function build() {
  console.log('\n=== Payload Builder ===');
  ensureInputFile();

  const raw = fs.readFileSync(INPUT, 'utf-8');
  const minified = minifyInput(raw);
  const hash = sha256(minified);
  const versionedName = `payloads.versioned.${hash}.js`;
  const versionedPath = path.resolve(__dirname, versionedName);

  // Save minified
  fs.writeFileSync(MINIFIED, minified);
  console.log(`[✓] Wrote ${path.basename(MINIFIED)} (${minified.length} bytes)`);

  // Save bookmarklet
  const bookmarklet = 'javascript:' + encodeURIComponent(minified);
  fs.writeFileSync(BOOKMARKLET, bookmarklet);
  console.log(`[✓] Wrote ${path.basename(BOOKMARKLET)} (${bookmarklet.length} chars)`);

  // Save versioned file
  fs.writeFileSync(versionedPath, minified);
  console.log(`[✓] Wrote ${path.basename(versionedPath)}`);

  // Inject if requested
  if (injectTarget) {
    injectIntoHTML(injectTarget, versionedName);
  }

  console.log('=== Build Complete ===\n');
}

function showHelp() {
  console.log(`
Usage: node builder.js [options]

Options:
  --watch               Watch payloads__.js and rebuild on change
  --inject <file>       Inject versioned script tag into HTML
  --help                Show this help message

Example:
  node builder.js --inject ./index.html --watch
`);
}

// Entry point
if (args.includes('--help')) {
  showHelp();
  process.exit(0);
}

build();

// Watch mode
if (watchMode) {
  console.log('[~] Watching for changes in payloads__.js...');
  chokidar.watch(INPUT).on('change', () => {
    console.log('[~] Change detected. Rebuilding...');
    try {
      build();
    } catch (err) {
      console.error(`[X] Build error: ${err.message}`);
    }
  });
}
//
//
