//
//

const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path'); // Ensure paths are handled correctly

(async () => {
    // Launch Puppeteer
    const browser = await puppeteer.launch({
        headless: true, // Run in headless mode for efficiency in container
        args: ['--no-sandbox', '--disable-setuid-sandbox'], // Security and compatibility flags
    });

    const page = await browser.newPage();

    // Enable request interception
    await page.setRequestInterception(true);

    // Array to store captured network data
    const requests = [];

    // Listen for network requests
    page.on('request', (request) => {
        requests.push({
            method: request.method(),
            url: request.url(),
        });
        request.continue(); // Continue with the intercepted request
    });

    try {
        // Navigate to the target website
        const targetUrl = 'https://doomrocket.com';
        console.log(`Navigating to ${targetUrl}...`);
        await page.goto(targetUrl, { waitUntil: 'networkidle2' });

        // Wait for a specific amount of time to capture additional network data
        console.log('Waiting to capture additional network requests...');
        await page.waitForTimeout(5000); // Adjust timeout as needed

        // Generate a HAR-like object
        const har = {
            log: {
                version: '1.2',
                creator: {
                    name: 'Puppeteer HAR Generator',
                    version: '1.0.0',
                },
                entries: requests.map(request => ({
                    method: request.method,
                    url: request.url,
                })),
            },
        };

        // Define output path
        const outputDir = '/usr/src/app/output';
        const harFilePath = path.join(outputDir, 'doomrocket.har');

        // Ensure output directory exists
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        // Save HAR file
        fs.writeFileSync(harFilePath, JSON.stringify(har, null, 2));
        console.log(`HAR file successfully saved to ${harFilePath}`);
    } catch (err) {
        console.error('Error occurred while generating HAR file:', err.message);
    } finally {
        // Ensure the browser is closed
        console.log('Closing browser...');
        await browser.close();
    }
})();

//
//
