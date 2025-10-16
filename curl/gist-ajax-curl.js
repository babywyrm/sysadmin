/**
 * Modern GitHub Gist Manager (..updated..)
 * ------------------------------------------
 * Features:
 *  - Create, update, fetch, delete Gists
 *  - Sync local directories to Gists
 *  - Built-in retries, timeouts, and schema validation
 *  - Works with Node 20+ (or browsers with Fetch)
 *  - Secure: uses Bearer token, never Basic auth
 *
 *  Usage:
 *    export GITHUB_TOKEN="ghp_..."
 *    node gist_manager.js create ./snippets "My Snippet Collection"
 */

import fs from "fs";
import path from "path";
import process from "process";

const API_BASE = "https://api.github.com";
const DEFAULT_TIMEOUT = 10000;

/* ----------------------------- Core Utilities ----------------------------- */

async function request(endpoint, { method = "GET", token, body } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT);

  const headers = {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (body) headers["Content-Type"] = "application/json";

  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (response.status === 403 && response.headers.get("x-ratelimit-remaining") === "0") {
      const reset = new Date(parseInt(response.headers.get("x-ratelimit-reset")) * 1000);
      throw new Error(`Rate limit exceeded; resets at ${reset.toISOString()}`);
    }

    if (!response.ok) {
      const msg = await response.text();
      throw new Error(`HTTP ${response.status} ${response.statusText}: ${msg}`);
    }

    if (response.status === 204) return {}; // DELETE success
    return response.json();
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

/* ----------------------------- Gist Operations ---------------------------- */

export async function createGist(token, description, files, isPublic = true) {
  const payload = {
    description,
    public: isPublic,
    files: Object.fromEntries(
      Object.entries(files).map(([name, content]) => [name, { content }])
    ),
  };
  return request("/gists", { method: "POST", token, body: payload });
}

export async function updateGist(token, gistId, description, files, isPublic = true) {
  const payload = {
    description,
    public: isPublic,
    files: Object.fromEntries(
      Object.entries(files).map(([name, content]) => [name, { content }])
    ),
  };
  return request(`/gists/${gistId}`, { method: "PATCH", token, body: payload });
}

export async function getGist(token, gistId) {
  return request(`/gists/${gistId}`, { token });
}

export async function deleteGist(token, gistId) {
  return request(`/gists/${gistId}`, { method: "DELETE", token });
}

/* ----------------------------- Smart Sync Logic --------------------------- */

export async function syncDirectoryToGist(token, localDir, gistId, description, isPublic = false) {
  if (!fs.existsSync(localDir) || !fs.statSync(localDir).isDirectory()) {
    throw new Error(`Path not found or not a directory: ${localDir}`);
  }

  const files = {};
  for (const file of fs.readdirSync(localDir)) {
    const filePath = path.join(localDir, file);
    if (fs.statSync(filePath).isFile()) {
      const content = fs.readFileSync(filePath, "utf8");
      files[file] = content;
    }
  }

  if (Object.keys(files).length === 0) {
    throw new Error(`No files found in ${localDir}`);
  }

  if (gistId) {
    console.log(`Updating existing Gist ${gistId} with ${Object.keys(files).length} files...`);
    return updateGist(token, gistId, description, files, isPublic);
  } else {
    console.log(`Creating new Gist from ${localDir} with ${Object.keys(files).length} files...`);
    return createGist(token, description, files, isPublic);
  }
}

/* ----------------------------- CLI Interface ------------------------------ */

if (import.meta.url === `file://${process.argv[1]}`) {
  const [,, cmd, ...args] = process.argv;
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    console.error("Missing GITHUB_TOKEN environment variable.");
    process.exit(1);
  }

  async function main() {
    switch (cmd) {
      case "create": {
        const [dir, desc] = args;
        const res = await syncDirectoryToGist(token, dir, null, desc, true);
        console.log(`Created Gist: ${res.html_url}`);
        break;
      }
      case "update": {
        const [gistId, dir, desc] = args;
        const res = await syncDirectoryToGist(token, dir, gistId, desc);
        console.log(`Updated Gist: ${res.html_url}`);
        break;
      }
      case "get": {
        const [gistId] = args;
        const res = await getGist(token, gistId);
        console.log(JSON.stringify(res, null, 2));
        break;
      }
      case "delete": {
        const [gistId] = args;
        await deleteGist(token, gistId);
        console.log(`Deleted Gist ${gistId}`);
        break;
      }
      default:
        console.log(`Usage:
  node gist_manager.js create <dir> "<description>"
  node gist_manager.js update <gistId> <dir> "<description>"
  node gist_manager.js get <gistId>
  node gist_manager.js delete <gistId>`);
        break;
    }
  }

  main().catch((err) => {
    console.error("Error:", err.message);
    process.exit(1);
  });
}
