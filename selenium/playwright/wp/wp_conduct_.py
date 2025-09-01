import asyncio
import json
import random
import time
from pathlib import Path
from playwright.async_api import async_playwright

# --- CONFIGURATION ---
BASE_URL = "http://target.local:8080/admin"
ACCOUNT_FILE = "accounts.json"
TAKE_SCREENSHOTS = True

def log(user, msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}][{user}] {msg}")

async def simulate_admin(page, username):
    """Admin-specific workflow: manage users, visit settings, etc."""
    for user_id in range(2, 5):
        url = f"{BASE_URL}/user-edit.php?user_id={user_id}"
        await page.goto(url)
        await page.wait_for_timeout(2000)
        log(username, f"visited user-edit page {url}")

        # Hover field if exists
        try:
            await page.hover("input[name='custom_field']")
            log(username, "hovered on custom_field")
        except:
            log(username, "no hover field")

        if TAKE_SCREENSHOTS:
            path = f"screenshots/{username}_user{user_id}.png"
            Path("screenshots").mkdir(exist_ok=True)
            await page.screenshot(path=path)
            log(username, f"saved screenshot {path}")

async def simulate_author(page, username):
    """Author-specific workflow: add/edit posts."""
    posts_url = f"{BASE_URL}/post-new.php"
    await page.goto(posts_url)
    await page.wait_for_timeout(2000)
    log(username, "opened new post page")

    try:
        await page.fill("#title", f"Test Post {random.randint(100,999)}")
        await page.fill("#content", "Sample content...")
        log(username, "filled post fields")
    except:
        log(username, "could not fill post fields")

async def simulate_subscriber(page, username):
    """Subscriber workflow: visit profile."""
    profile_url = f"{BASE_URL}/profile.php"
    await page.goto(profile_url)
    await page.wait_for_timeout(2000)
    log(username, "visited profile page")

async def run_for_account(p, account):
    username, password, role = account["username"], account["password"], account["role"]
    browser = await p.chromium.launch(headless=True)
    context = await browser.new_context()
    page = await context.new_page()

    log(username, f"logging in as role={role}")
    await page.goto(BASE_URL)
    await page.fill("#user_login", username)
    await page.fill("#user_pass", password)
    await page.press("#user_pass", "Enter")
    await page.wait_for_timeout(3000)

    if role == "admin":
        await simulate_admin(page, username)
    elif role == "author":
        await simulate_author(page, username)
    else:
        await simulate_subscriber(page, username)

    await browser.close()
    log(username, "finished workflow")

async def orchestrator():
    # Load accounts dynamically
    with open(ACCOUNT_FILE) as f:
        accounts = json.load(f)

    async with async_playwright() as p:
        tasks = [run_for_account(p, acc) for acc in accounts]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(orchestrator())
