# web_automation_scaffold.py
import asyncio
import time
import random
from playwright.async_api import async_playwright, TimeoutError as PWTimeoutError

# Configuration - customize these for your specific use case
CONFIG = {
    "BASE_URL": "http://localhost:8080",
    "LOGIN_PATH": "/admin/login",
    "USERNAME": "admin",
    "PASSWORD": "password123",
    
    # Target parameters
    "TARGET_START": 1,
    "TARGET_END": 10,  # exclusive range
    "TARGET_URL_TEMPLATE": "/admin/entity-edit?id={target_id}&cb={random_cb}",
    "TARGET_SELECTOR": "[name='target_field']",
    "TARGET_ACTION": "hover",  # hover, click, focus, etc.
    
    # Performance settings
    "CONCURRENCY": 4,
    "ACTION_RETRY": 2,
    "NAV_TIMEOUT": 5000,        # ms for navigation / DOM load
    "SELECTOR_TIMEOUT": 3000,   # ms for selector waits
    "LOGIN_TIMEOUT": 8000,      # ms for login flow
    "CYCLE_INTERVAL": 30,       # seconds between cycles
    "HEADLESS": True,
    
    # Login selectors
    "USERNAME_SELECTOR": "#username",
    "PASSWORD_SELECTOR": "#password",
    "LOGIN_SUBMIT_KEY": "Enter",  # or selector for submit button
}

def log(msg: str):
    """Timestamped logging"""
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {msg}")

async def perform_target_action(context, target_id, sem):
    """Visit target page and perform specified action on target element."""
    url = f"{CONFIG['BASE_URL']}{CONFIG['TARGET_URL_TEMPLATE'].format(
        target_id=target_id, 
        random_cb=random.randint(100000, 999999)
    )}"
    
    async with sem:
        page = await context.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=CONFIG["NAV_TIMEOUT"])
            
            # Wait for target element
            try:
                element = await page.wait_for_selector(
                    CONFIG["TARGET_SELECTOR"], 
                    state="attached", 
                    timeout=CONFIG["SELECTOR_TIMEOUT"]
                )
            except PWTimeoutError:
                log(f"Target {target_id}: element not found (timeout)")
                return False

            # Perform action with retries
            for attempt in range(1, CONFIG["ACTION_RETRY"] + 1):
                try:
                    action = CONFIG["TARGET_ACTION"].lower()
                    if action == "hover":
                        await element.hover(timeout=2000)
                    elif action == "click":
                        await element.click(timeout=2000)
                    elif action == "focus":
                        await element.focus(timeout=2000)
                    else:
                        log(f"Unknown action: {action}")
                        return False
                    
                    log(f"Performed '{action}' on target {target_id}")
                    return True
                    
                except Exception as e:
                    log(f"Target {target_id}: {action} attempt {attempt} failed: {e}")
                    # Re-query element if it might be detached
                    try:
                        element = await page.query_selector(CONFIG["TARGET_SELECTOR"])
                        if not element:
                            log(f"Target {target_id}: element disappeared after attempt")
                            return False
                    except Exception:
                        return False
            return False
            
        finally:
            await page.close()

async def run_automation_cycle():
    """Execute one complete automation cycle"""
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=CONFIG["HEADLESS"], 
            args=["--disable-gpu", "--no-sandbox"]
        )
        context = await browser.new_context()
        context.set_default_navigation_timeout(CONFIG["NAV_TIMEOUT"])
        context.set_default_timeout(CONFIG["SELECTOR_TIMEOUT"])

        # Login flow
        page = await context.new_page()
        login_url = f"{CONFIG['BASE_URL']}{CONFIG['LOGIN_PATH']}"
        
        log("Starting login process")
        await page.goto(login_url, wait_until="domcontentloaded", timeout=CONFIG["LOGIN_TIMEOUT"])
        await page.wait_for_selector(CONFIG["USERNAME_SELECTOR"], timeout=CONFIG["LOGIN_TIMEOUT"])
        await page.fill(CONFIG["USERNAME_SELECTOR"], CONFIG["USERNAME"])
        await page.fill(CONFIG["PASSWORD_SELECTOR"], CONFIG["PASSWORD"])
        
        if CONFIG["LOGIN_SUBMIT_KEY"].startswith("#") or CONFIG["LOGIN_SUBMIT_KEY"].startswith("."):
            # It's a selector, click it
            await page.click(CONFIG["LOGIN_SUBMIT_KEY"])
        else:
            # It's a key, press it
            await page.press(CONFIG["PASSWORD_SELECTOR"], CONFIG["LOGIN_SUBMIT_KEY"])

        # Wait for login completion
        try:
            await page.wait_for_load_state("networkidle", timeout=CONFIG["LOGIN_TIMEOUT"])
        except PWTimeoutError:
            log("Login: networkidle timeout, proceeding anyway")

        log("Login complete, starting target operations")

        # Concurrent target operations
        sem = asyncio.Semaphore(CONFIG["CONCURRENCY"])
        tasks = []
        
        for target_id in range(CONFIG["TARGET_START"], CONFIG["TARGET_END"]):
            task = asyncio.create_task(perform_target_action(context, target_id, sem))
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        success_count = sum(1 for r in results if r is True)
        log(f"Cycle complete: {success_count}/{len(results)} operations succeeded")

        await browser.close()

async def main_loop():
    """Main execution loop"""
    log("Starting automation loop")
    while True:
        start_time = time.time()
        try:
            await run_automation_cycle()
        except Exception as e:
            log(f"Cycle error: {e}")
        
        elapsed = time.time() - start_time
        sleep_duration = max(0, CONFIG["CYCLE_INTERVAL"] - elapsed)
        log(f"Sleeping {sleep_duration:.1f}s until next cycle")
        await asyncio.sleep(sleep_duration)

if __name__ == "__main__":
    log("Initializing web automation scaffold")
    asyncio.run(main_loop())
