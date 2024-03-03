const puppeteer = require('puppeteer');

async function logTimestamp(message) {
  console.log(`[${new Date().toISOString()}] ${message}`);
}

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();

  // Listen for console messages
  page.on('console', (message) => {
    console.log(`[Console] ${message.type().toUpperCase()}: ${message.text()}`);
  });

  logTimestamp('Before navigating to login page');
  await page.goto('http://northshore.us.edu/wp-login.php');
  logTimestamp('After navigating to login page');

  logTimestamp('Before entering credentials and clicking login');
  await page.type('#user_login', 'msnorbury');
  await page.type('#user_pass', '$vLGBc492Q&(hm2lhKxxxx6969');
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'domcontentloaded' }),
    page.click('#wp-submit')
  ]);
  logTimestamp('After entering credentials and clicking login');

  // Navigate to the user-edit page for user ID 5
  await page.goto('http://northshore.us.edu/wp-admin/user-edit.php?user_id=5&wp_http_referer=%2Fwp-admin%2Fusers.php');

  // Wait for the content to be visible on the page
  await page.waitForSelector('.wrap', { visible: true, timeout: 60000 }); // Increased timeout to 60 seconds

  // Triggering onmouseover event directly on the input field
  await page.evaluate(() => {
    const inputField = document.querySelector('input[name="abh_company_url"]');
    const event = new Event('mouseover');
    inputField.dispatchEvent(event);
  });

  logTimestamp('After triggering onmouseover event');

  logTimestamp('Before closing the browser');
  await browser.close();
  logTimestamp('After closing the browser');
})();
