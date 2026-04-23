/**
 * GistClient - Modern GitHub Gist API wrapper
 *
 * Token should come from your environment, never hardcoded.
 * Browser: inject via build tool (Vite/Webpack) using import.meta.env or process.env
 * Node:    process.env.GITHUB_TOKEN
 */
class GistClient {
  #token;
  #baseUrl = "https://api.github.com";

  constructor(token) {
    if (!token) throw new Error("GitHub PAT is required");
    this.#token = token;
  }

  #headers() {
    return {
      Authorization: `Bearer ${this.#token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": "2022-11-28",
    };
  }

  async #request(endpoint, method = "GET", body = null) {
    const res = await fetch(`${this.#baseUrl}${endpoint}`, {
      method,
      headers: this.#headers(),
      ...(body && { body: JSON.stringify(body) }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(
        `GitHub API error ${res.status}: ${err.message ?? res.statusText}`
      );
    }

    return res.json();
  }

  async create({ description = "", isPublic = false, files }) {
    return this.#request("/gists", "POST", {
      description,
      public: isPublic,
      files,
    });
  }

  async update(gistId, { description, files }) {
    return this.#request(`/gists/${gistId}`, "PATCH", { description, files });
  }

  async get(gistId) {
    return this.#request(`/gists/${gistId}`);
  }

  async delete(gistId) {
    const res = await fetch(`${this.#baseUrl}/gists/${gistId}`, {
      method: "DELETE",
      headers: this.#headers(),
    });
    if (!res.ok) throw new Error(`Failed to delete gist: ${res.status}`);
  }

  async list() {
    return this.#request("/gists");
  }
}

//
//
// Vite example — set VITE_GITHUB_TOKEN in your .env file
const client = new GistClient(import.meta.env.VITE_GITHUB_TOKEN);

async function run() {
  try {
    // Create
    const gist = await client.create({
      description: "Created via GistClient",
      isPublic: true,
      files: {
        "hello.txt": { content: "Hello from GistClient!" },
      },
    });
    console.log("Created:", gist.html_url);

    // Update
    const updated = await client.update(gist.id, {
      description: "Updated via GistClient",
      files: {
        "hello.txt": { content: "Updated content!" },
      },
    });
    console.log("Updated:", updated.updated_at);
  } catch (err) {
    console.error(err.message);
  }
}

run();
