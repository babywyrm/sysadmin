import asyncio
from playwright.async_api import async_playwright
import time
import random

def log(msg: str):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

async def main():
    # --- Configuration (replace with your own values) ---
    base_url = "http://demo-target.local:8080/admin"
    username = "demo_user"
    password = "SuperSecret123"
    user_range = range(3, 8)  # adjust range as needed
    take_screenshots = True

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        # --- Login ---
        log("Navigating to login page")
        await page.goto(base_url)

        await page.fill("#user_login", username)
        await page.fill("#user_pass", password)
        await page.press("#user_pass", "Enter")
        log("Submitted login form")

        await page.wait_for_timeout(3000)  # wait for page load

        # --- Loop through user pages ---
        for user_id in user_range:
            user_url = f"{base_url}/user-edit.php?user_id={user_id}"
            log(f"Visiting {user_url}")
            await page.goto(user_url)
            await page.wait_for_timeout(2000)

            try:
                await page.hover("input[name='custom_field']")
                log(f"Triggered hover event on user {user_id}")
            except Exception as e:
                log(f"No hover field found for user {user_id}: {e}")

            # Random mouse move to simulate interaction
            x, y = random.randint(100, 400), random.randint(200, 500)
            await page.mouse.move(x, y)
            await page.wait_for_timeout(500)

            # Optionally take a screenshot
            if take_screenshots:
                screenshot_path = f"user_{user_id}_{int(time.time())}.png"
                await page.screenshot(path=screenshot_path)
                log(f"Saved screenshot: {screenshot_path}")

        # --- Cleanup ---
        log("Closing browser")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
