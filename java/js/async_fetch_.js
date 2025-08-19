// Modern ES2020+ version with better error handling and flexibility
class APIFetcher {
  constructor(baseURLs = []) {
    this.baseURLs = baseURLs;
  }

  // Generic fetch with timeout and retry
  async fetchWithRetry(url, options = {}, retries = 3, timeout = 5000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    for (let i = 0; i <= retries; i++) {
      try {
        const response = await fetch(url, { 
          ...options, 
          signal: controller.signal 
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return await response.json();
      } catch (error) {
        if (i === retries) throw error;
        await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1))); // Exponential backoff
      }
    }
  }

  // Parallel fetch with individual error handling
  async fetchAll(urls = this.baseURLs) {
    const results = await Promise.allSettled(
      urls.map(url => this.fetchWithRetry(url))
    );

    return results.map((result, index) => ({
      url: urls[index],
      success: result.status === 'fulfilled',
      data: result.status === 'fulfilled' ? result.value : null,
      error: result.status === 'rejected' ? result.reason.message : null
    }));
  }

  // Process results with callback
  processResults(results, callback = console.log) {
    results.forEach(({ url, success, data, error }) => {
      if (success) {
        callback(`✓ ${url}: ${data.length} items`);
        data.slice(0, 3).forEach(item => callback(item)); // Show first 3 items
      } else {
        callback(`✗ ${url}: ${error}`);
      }
    });
  }
}

// Usage examples
const fetcher = new APIFetcher([
  'https://jsonplaceholder.typicode.com/posts',
  'https://jsonplaceholder.typicode.com/albums', 
  'https://jsonplaceholder.typicode.com/users'
]);

// Simple usage
(async () => {
  try {
    const results = await fetcher.fetchAll();
    fetcher.processResults(results);
  } catch (error) {
    console.error('Fetch failed:', error.message);
  }
})();

// One-liner for quick fetches
const quickFetch = async (urls) => 
  Promise.allSettled(urls.map(url => fetch(url).then(r => r.json())));

// Node.js version (modern)
import fetch from 'node-fetch'; // or use built-in fetch in Node 18+

const nodeFetcher = new APIFetcher();
nodeFetcher.fetchAll([
  'https://jsonplaceholder.typicode.com/posts',
  'https://jsonplaceholder.typicode.com/albums',
  'https://jsonplaceholder.typicode.com/users'
]).then(results => nodeFetcher.processResults(results));
//
