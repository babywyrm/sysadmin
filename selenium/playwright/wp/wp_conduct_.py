#!/usr/bin/env python3
"""
WordPress Playwright Orchestrator

This script simulates multiple WordPress users (admin, author, subscriber, etc.)
interacting with the site. It loads accounts from a JSON file and performs
different workflows depending on the user's role.

Supports CLI overrides for role, headless/headful mode, loop interval, etc.
"""

import argparse
import asyncio
import json
import random
import time
from pathlib import Path
from playwright.async_api import async_playwright

# --- CONFIG DEFAULTS ---
BASE_URL = "http://target.local:8080/admin"   # WordPress admin panel (obfuscated target)
ACCOUNT_FILE = "accounts.json"                # JSON config with accounts
DEFAULT_LOOP_INTERVAL = 60                    # seconds between runs when looping


# --- LOGGING UTILITY ---
def log(user, msg):
    """Print a timestamped log message for each user."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}][{user}] {msg}")


# --- ROLE-SPECIFIC SIMULATIONS ---
async def simulate_admin(page, username, screenshot=False):
    """Admin: edit user profiles, hover fields, take screenshots."""
    for user_id in range(2, 5):
        url = f"{BASE_URL}/user-edit.php?user_id={user_id}"
        await page.goto(url)
        await page.wait_for_timeout(2000)
        log(username, f"visited user-edit page {url}")

        try:
            await page.hover("input[name='custom_field']")
            log(username, "hovered on custom_field")
        except:
            log(username, "no hover field present")

        if screenshot:
            Path("screenshots").mkdir(exist_ok=True)
            path = f"screenshots/{username}_user{user_id}.png"
            await page.screenshot(path=path)
            log(username, f"saved screenshot {path}")


async def simulate_author(page, username, screenshot=False):
    """Author: create a new post with dummy content."""
    posts_url = f"{BASE_URL}/post-new.php"
    await page.goto(posts_url)
    await page.wait_for_timeout(2000)
    log(username, "opened new post page")

    try:
        await page.fill("#title", f"Test Post {random.randint(100,999)}")
        await page.fill("#content", "Sample content goes here...")
        log(username, "filled in post fields")

        if screenshot:
            Path("screenshots").mkdir(exist_ok=True)
            path = f"screenshots/{username}_newpost.png"
            await page.screenshot(path=path)
            log(username, f"saved screenshot {path}")

    except:
        log(username, "could not fill post fields (maybe missing selectors)")


async def simulate_subscriber(page, username, screenshot=False):
    """Subscriber: visit profile page only."""
    profile_url = f"{BASE_URL}/profile.php"
    await page.goto(profile_url)
    await page.wait_for_timeout(2000)
    log(username, "visited profile page")

    if screenshot:
        Path("screenshots").mkdir(exist_ok=True)
        path = f"screenshots/{username}_profile.png"
        await page.screenshot(path=path)
        log(username, f"saved screenshot {path}")


# --- MAIN WORKER FUNCTION ---
async def run_for_account(p, account, headless=True, force_role=None, screenshot=False):
    """
    Launch a browser session for a single account.
    Logs in and executes role-based workflow.
    """
    username = account["username"]
    password = account["password"]
    role = force_role if force_role else account.get("role", "subscriber")

    # Launch browser
    browser = await p.chromium.launch(headless=headless)
    context = await browser.new_context()
    page = await context.new_page()

    log(username, f"logging in as role={role}")
    await page.goto(BASE_URL)

    # Login form fill
    await page.fill("#user_login", username)
    await page.fill("#user_pass", password)
    await page.press("#user_pass", "Enter")
    await page.wait_for_timeout(3000)

    # Role-specific workflows
    if role == "admin":
        await simulate_admin(page, username, screenshot)
    elif role == "author":
        await simulate_author(page, username, screenshot)
    else:
        await simulate_subscriber(page, username, screenshot)

    await browser.close()
    log(username, "finished workflow")


# --- ORCHESTRATOR ---
async def orchestrator(headless=True, role=None, loop=False, interval=DEFAULT_LOOP_INTERVAL, screenshot=False):
    """Run orchestrator: load accounts and dispatch workflows (with optional loop)."""
    with open(ACCOUNT_FILE) as f:
        accounts = json.load(f)

    async with async_playwright() as p:
        while True:
            tasks = [run_for_account(p, acc, headless, role, screenshot) for acc in accounts]
            await asyncio.gather(*tasks)

            if not loop:
                break

            log("system", f"loop sleeping for {interval}s before next run")
            await asyncio.sleep(interval)


# --- CLI ENTRY POINT ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WordPress Playwright Orchestrator")
    parser.add_argument("--role", help="Force role for all accounts (admin/author/subscriber)")
    parser.add_argument("--headful", action="store_true", help="Run browsers with UI (not headless)")
    parser.add_argument("--loop", action="store_true", help="Run in continuous loop mode")
    parser.add_argument("--interval", type=int, default=DEFAULT_LOOP_INTERVAL, help="Loop interval in seconds")
    parser.add_argument("--screenshot", action="store_true", help="Enable screenshots during workflows")
    args = parser.parse_args()

    asyncio.run(orchestrator(
        headless=not args.headful,
        role=args.role,
        loop=args.loop,
        interval=args.interval,
        screenshot=args.screenshot
    ))

