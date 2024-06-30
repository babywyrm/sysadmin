//
//

const puppeteer = require('puppeteer');
const fs = require('fs');

(async () => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Enable request interception
    await page.setRequestInterception(true);

    // Array to store captured network data
    const requests = [];

    // Listen for network requests
    page.on('request', (request) => {
        requests.push({
            method: request.method(),
            url: request.url()
        });
        request.continue();
    });

    try {
        // Navigate to a website
        await page.goto('https://doomrocket.com');

        // Replace page.waitForTimeout with setTimeout for waiting
        await new Promise(resolve => setTimeout(resolve, 5000)); // Adjust timeout as needed

        // Generate HAR-like object
        const har = requests.map(request => ({
            method: request.method,
            url: request.url
        }));

        // Save HAR file
        fs.writeFileSync('/usr/src/app/output/doomrocket.har', JSON.stringify(har, null, 2));
        
        console.log('HAR file successfully generated.');

    } catch (err) {
        console.error('Error occurred while generating HAR file:', err);
    } finally {
        await browser.close();
    }
})();

//
//
