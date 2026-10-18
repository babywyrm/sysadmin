const puppeteer = require('puppeteer');

async function logTimestamp(message) {
  console.log(`[${new Date().toISOString()}] ${message}`);
}

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();

  logTimestamp('Before navigating to login page');
  await page.goto('http://thing.org/wp-login.php');
  logTimestamp('After navigating to login page');

  logTimestamp('Before entering credentials and clicking login');
  await page.type('#user_login', 'mama');
  await page.type('#user_pass', 'AAAAAAGasdfasdfasdfasdfas69');
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'domcontentloaded' }),
    page.click('#wp-submit')
  ]);
  logTimestamp('After entering credentials and clicking login');

  // Navigate to the user-edit page for user ID 5
  await page.goto('http://nasfasdffdsusers.org/things.php');

  // Wait for the content to be visible on the page
  await page.waitForSelector('.wrap', { visible: true, timeout: 60000 }); // Increased timeout to 60 seconds

  // Hover over all fields on the page
  const fields = await page.$$('.form-table tr');
  for (let i = 0; i < fields.length; i++) {
    const field = fields[i];
    const fieldLabel = await field.evaluate(el => el.querySelector('td:first-child')?.textContent.trim() || 'No label');
    logTimestamp(`Hovering over field ${i + 1}: ${fieldLabel}`);

    await page.evaluate((field) => {
      const boundingBox = field.getBoundingClientRect();
      const event = new MouseEvent('mouseover', {
        bubbles: true,
        cancelable: true,
        view: window,
        clientX: boundingBox.x + boundingBox.width / 2,
        clientY: boundingBox.y + boundingBox.height / 2
      });
      field.dispatchEvent(event);
    }, field);

    await new Promise(resolve => setTimeout(resolve, 3000)); // 3-second delay before moving to the next field
    // Add any additional actions or interactions you want to simulate
  }

  logTimestamp('Before closing the browser');
  await browser.close();
  logTimestamp('After closing the browser');
})();
