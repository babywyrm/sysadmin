const express = require("express");
const { Builder } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const logging = require("selenium-webdriver/lib/logging");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3000;
const TMP_DIR = "/tmp";
const HAR_FILE_PATH = path.join(TMP_DIR, "har", "session.har");

// Environment configurations
process.env.SELENIUM_MANAGER = "0";
process.env.TMPDIR = TMP_DIR;
process.env.HOME = TMP_DIR;

// Middleware for parsing request body
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Function to ensure the HAR directory exists
function ensureHarDirectory() {
  const harDir = path.dirname(HAR_FILE_PATH);
  if (!fs.existsSync(harDir)) {
    fs.mkdirSync(harDir, { recursive: true });
    console.log("✅ Created /tmp/har directory.");
  }
}

// Ensure the directory exists on startup
ensureHarDirectory();

// Function to clear Selenium cache
function clearSeleniumCache() {
  try {
    fs.rmSync(path.join(TMP_DIR, ".cache", "selenium"), { recursive: true, force: true });
    console.log("✅ Cleared Selenium cache.");
  } catch (err) {
    console.error("❌ Could not clear Selenium cache:", err);
  }
}
clearSeleniumCache();

// Function to generate HAR logs from performance logs
function convertPerformanceLogsToHar(logs) {
  ensureHarDirectory(); // Ensure directory exists before writing

  return {
    log: {
      version: "1.2",
      creator: { name: "Selenium HAR Converter", version: "0.1" },
      entries: logs
        .map((logEntry) => {
          try {
            const message = JSON.parse(logEntry.message).message;
            if (message.method === "Network.responseReceived") {
              const response = message.params.response;
              return {
                startedDateTime: new Date().toISOString(),
                time: 0,
                request: {
                  url: response.url,
                  method: response.requestMethod || "",
                  headers: response.headers,
                },
                response: {
                  status: response.status,
                  statusText: response.statusText,
                  headers: response.headers,
                },
                timings: {},
              };
            }
          } catch (e) {
            return null;
          }
        })
        .filter(Boolean),
    },
  };
}

// Function to configure Selenium WebDriver
async function createWebDriver() {
  const chromeDriverPath = "/app/node_modules/chromedriver/bin/chromedriver"; // Explicitly set ChromeDriver path

  const options = new chrome.Options();
  options.addArguments(
    "--headless=new",
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-web-security",
    "--disable-dev-shm-usage",
    "--remote-debugging-port=9222"
  );
  options.addArguments(
    "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
  );

  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.PERFORMANCE, logging.Level.ALL);
  options.setLoggingPrefs(loggingPrefs);

  // Use explicitly set ChromeDriver path
  const serviceBuilder = new chrome.ServiceBuilder(chromeDriverPath);

  return new Builder()
    .forBrowser("chrome")
    .setChromeService(serviceBuilder) // Force Selenium to use the correct path
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();
}

// Home page route
app.get("/", (req, res) => {
  res.send(`
    <html>
      <head><title>Synth Sandbox</title></head>
      <body>
        <h1>Synth Sandbox (Chromedriver)</h1>
        <p>Enter your JavaScript code below. It will be executed in a headless Chrome instance.</p>
        <form method="post" action="/run">
          <textarea name="script" rows="15" cols="80" placeholder="Enter your JavaScript here"></textarea><br/>
          <button type="submit">Run Code</button>
        </form>
      </body>
    </html>
  `);
});

// Script execution route
app.post("/run", async (req, res) => {
  const userScript = req.body.script || "";
  console.log("🚀 Received script:", userScript);

  let driver;
  try {
    driver = await createWebDriver();
    console.log("✅ WebDriver launched successfully.");

    await driver.get("about:blank");

    // ✅ Fix: Run user script **directly** inside the correct execution context
    let result;
    try {
      result = await eval(`(async () => { ${userScript} })()`);
    } catch (e) {
      console.error("🔥 Script error:", e);
      result = "Error: " + e.toString();
    }

    console.log("✅ Script executed, result:", result);

    // ✅ Fix: Safely fetch performance logs for HAR generation
    let perfLogs = [];
    try {
      perfLogs = await driver.manage().logs().get("performance");
    } catch (err) {
      console.warn("⚠️ Warning: Could not retrieve performance logs.", err);
    }

    const har = convertPerformanceLogsToHar(perfLogs);
    fs.writeFileSync(HAR_FILE_PATH, JSON.stringify(har, null, 2));
    console.log(`✅ HAR log saved to ${HAR_FILE_PATH}`);

    await driver.quit();

    res.send(`
      <html>
        <head><title>Script Result</title></head>
        <body>
          <h2>Result</h2>
          <pre>${result}</pre>
          <p>The HAR log has been saved to <code>${HAR_FILE_PATH}</code> (mount this directory to retrieve it).</p>
          <a href="/">Go back</a>
        </body>
      </html>
    `);
  } catch (err) {
    console.error("❌ Error executing script:", err);
    if (driver) await driver.quit();
    res.status(500).send(`Error executing script: ${err}`);
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🌍 Synth Sandbox (Chromedriver) listening on port ${PORT}`);
});
