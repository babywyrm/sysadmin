const express = require("express");
const { Builder } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const logging = require("selenium-webdriver/lib/logging");
const chromedriver = require("chromedriver");
const fs = require("fs");

const app = express();

// Disable Selenium Manager and force temporary directories to /tmp.
process.env.SELENIUM_MANAGER = "0";
process.env.TMPDIR = "/tmp";
process.env.HOME = "/tmp";

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Optionally clear any existing Selenium cache.
try {
  fs.rmSync("/tmp/.cache/selenium", { recursive: true, force: true });
  console.log("Cleared Selenium cache.");
} catch (err) {
  console.error("Could not clear Selenium cache:", err);
}

app.get("/", (req, res) => {
  res.send(`
    <html>
      <head><title>Browserbot JS Sandbox</title></head>
      <body>
        <h1>Browserbot JS Sandbox (Chromedriver)</h1>
        <p>Enter your JavaScript code below. It will be executed in a headless Chrome instance.</p>
        <form method="post" action="/run">
          <textarea name="script" rows="15" cols="80" placeholder="Enter your JavaScript here"></textarea><br/>
          <button type="submit">Run Code</button>
        </form>
      </body>
    </html>
  `);
});

// Simple HAR conversion function (basic demonstration)
function convertPerformanceLogsToHar(logs) {
  const entries = [];
  logs.forEach(logEntry => {
    try {
      const message = JSON.parse(logEntry.message).message;
      if (message.method === "Network.responseReceived") {
        const response = message.params.response;
        entries.push({
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
          timings: {}
        });
      }
    } catch (e) {
      // Ignore parsing errors.
    }
  });
  return {
    log: {
      version: "1.2",
      creator: { name: "Selenium HAR Converter", version: "0.1" },
      entries: entries
    }
  };
}

app.post("/run", async (req, res) => {
  const userScript = req.body.script || "";
  console.log("Received script:", userScript);

  let driver;
  try {
    // Configure Chrome options.
    const options = new chrome.Options();
    options.addArguments(
      "--headless=new",                   // Modern headless mode.
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-web-security",
      "--disable-dev-shm-usage",          // Force use of /tmp instead of /dev/shm.
      "--remote-debugging-port=9222"       // Required to capture performance logs.
    );
    options.addArguments(
      "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    );

    // Set performance logging preferences.
    const prefs = new logging.Preferences();
    prefs.setLevel(logging.Type.PERFORMANCE, logging.Level.ALL);
    options.setLoggingPrefs(prefs);

    // Build the Selenium WebDriver for Chrome.
    driver = await new Builder()
      .forBrowser("chrome")
      .setChromeOptions(options)
      .build();

    // Navigate to a blank page.
    await driver.get("about:blank");

    // Execute the customer-supplied JavaScript.
    const wrappedScript = `(async () => {
      try {
        return await eval(${JSON.stringify(userScript)});
      } catch (e) {
        console.error("Script error:", e);
        return "Error: " + e.toString();
      }
    })()`;
    const result = await driver.executeScript(`return ${wrappedScript};`);
    console.log("Script executed, result:", result);

    // Retrieve performance logs.
    const perfLogs = await driver.manage().logs().get("performance");
    const har = convertPerformanceLogsToHar(perfLogs);
    fs.writeFileSync("/har/session.har", JSON.stringify(har, null, 2));
    console.log("HAR log saved to /har/session.har");

    await driver.quit();

    res.send(`
      <html>
        <head><title>Script Result</title></head>
        <body>
          <h2>Result</h2>
          <pre>${result}</pre>
          <p>The HAR log has been saved to <code>/har/session.har</code> (mount this directory to retrieve it).</p>
          <a href="/">Go back</a>
        </body>
      </html>
    `);
  } catch (err) {
    console.error("Error executing script:", err);
    if (driver) await driver.quit();
    res.status(500).send(`Error executing script: ${err}`);
  }
});

app.listen(3000, () => {
  console.log("infant-sandbox (chromedriver) listening on port 3000");
});
