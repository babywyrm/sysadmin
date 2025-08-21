#!/usr/bin/env python3
import logging
import os
import json
import time
from urllib.parse import urlparse, urlunparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException,
    NoSuchElementException,
    WebDriverException,
    ElementClickInterceptedException,
)

# ----------------------------
# Logging setup
# ----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("selenium_crawl.log"), logging.StreamHandler()],
)

# ----------------------------
# WebDriver setup
# ----------------------------
firefox_options = Options()
firefox_options.add_argument("--headless")
webdriver_service = Service("/usr/local/bin/geckodriver")
driver = webdriver.Firefox(service=webdriver_service, options=firefox_options)

# ----------------------------
# Config
# ----------------------------
login_url = "https://app.stg.thousandeyes.com/login?teRegion=1"
USERNAME = "tester@things.org.au"
PASSWORD = "asfasdasfasfdasfsadf"
NAMESPACES_FILE = "namespaces.txt"

results = {"dom": set(), "shadow": set(), "iframe": set(), "xhr": set()}
all_links = set()  # master set for TXT export


# ----------------------------
# Helpers
# ----------------------------
def normalize_url(url: str) -> str:
    """Return a normalized version (scheme+netloc+path)."""
    try:
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    except Exception:
        return url


def load_namespaces():
    if not os.path.exists(NAMESPACES_FILE):
        logging.warning(
            f"{NAMESPACES_FILE} not found. Using only the login URL as the starting point."
        )
        return [login_url]
    with open(NAMESPACES_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]


def inject_hooks(driver):
    """Re-inject fetch/XHR/history hooks after every navigation."""
    try:
        driver.execute_script("""
            (function() {
              if (!window._hooksInstalled) {
                window._hooksInstalled = true;
                window.collectedRequests = [];
              }
              var origOpen = XMLHttpRequest.prototype.open;
              if (!XMLHttpRequest.prototype._openPatched) {
                XMLHttpRequest.prototype._openPatched = true;
                XMLHttpRequest.prototype.open = function(method, url) {
                  try { window.collectedRequests.push(url); } catch(e){}
                  return origOpen.apply(this, arguments);
                };
              }
              var origFetch = window.fetch;
              if (!window._fetchPatched) {
                window._fetchPatched = true;
                window.fetch = function() {
                  try { window.collectedRequests.push(arguments[0]); } catch(e){}
                  return origFetch.apply(this, arguments);
                };
              }
              var origPush = history.pushState;
              if (!window._pushPatched) {
                window._pushPatched = true;
                history.pushState = function(state, title, url) {
                  try { window.collectedRequests.push(url.toString()); } catch(e){}
                  return origPush.apply(this, arguments);
                };
              }
            })();
        """)
    except Exception:
        pass


def login_to_app():
    logging.info("Starting login process...")
    try:
        driver.get(login_url)
        WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.ID, "email")))
        email_input = driver.find_element(By.ID, "email")
        email_input.clear()
        email_input.send_keys(USERNAME + Keys.RETURN)
        logging.info("Email submitted.")

        WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.ID, "password")))
        password_input = driver.find_element(By.ID, "password")
        password_input.clear()
        password_input.send_keys(PASSWORD + Keys.RETURN)
        logging.info("Password submitted.")

        WebDriverWait(driver, 20).until(EC.title_contains("Dashboard"))
        logging.info("Login successful.")
        inject_hooks(driver)
    except TimeoutException:
        logging.error("Login timed out. Page structure may have changed.")
    except NoSuchElementException as e:
        logging.error(f"Error locating elements during login: {e}")


def wait_for_ajax(driver, timeout=10):
    try:
        WebDriverWait(driver, timeout).until(
            lambda d: d.execute_script(
                "return (window.jQuery && jQuery.active === 0) || (typeof window.jQuery === 'undefined')"
            )
        )
    except Exception:
        pass


def auto_scroll(driver, pause_time=1.0, max_scrolls=5):
    """Scroll to load lazy content."""
    last_height = driver.execute_script("return document.body.scrollHeight")
    for _ in range(max_scrolls):
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(pause_time)
        new_height = driver.execute_script("return document.body.scrollHeight")
        if new_height == last_height:
            break
        last_height = new_height
    logging.info("[SCROLL] Auto-scroll complete.")


def click_expandable_menus(driver):
    """Click menus and buttons to reveal hidden links."""
    try:
        candidates = driver.find_elements(By.CSS_SELECTOR, "button, [role='button'], [aria-expanded]")
        for el in candidates:
            try:
                if el.is_displayed() and el.is_enabled():
                    el.click()
                    logging.info("[CLICK] Clicked expandable/menu item")
                    time.sleep(0.3)
            except (ElementClickInterceptedException, WebDriverException):
                continue
    except Exception:
        pass


def record_link(link, category, visited_links):
    """Record link into results and all_links (dedup normalized but preserve full)."""
    if link and link.startswith("https://app.stg.thousandeyes.com"):
        norm = normalize_url(link)
        if norm not in visited_links:
            results[category].add(link)   # store raw link
            all_links.add(link)           # preserve all variants
            visited_links.add(norm)
            logging.info(f"[{category.upper()}] Found new link: {link}")


def find_shadow_links_recursive(driver, host, visited_links):
    try:
        shadow_root = driver.execute_script("return arguments[0].shadowRoot", host)
        if shadow_root:
            all_nodes = shadow_root.find_elements(By.CSS_SELECTOR, "*")
            for node in all_nodes:
                for attr in ["href","src","action","data-url","data-href"]:
                    val = node.get_attribute(attr)
                    if val:
                        record_link(val, "shadow", visited_links)
                find_shadow_links_recursive(driver, node, visited_links)
    except Exception:
        pass


def extract_links(visited_links, depth=0, max_depth=3):
    inject_hooks(driver)  # ensure hooks are active
    try:
        WebDriverWait(driver, 10).until(lambda d: d.execute_script("return document.readyState") == "complete")
        wait_for_ajax(driver)
        auto_scroll(driver)
        click_expandable_menus(driver)

        # DOM links
        for el in driver.find_elements(By.CSS_SELECTOR, "a, form, button, [role='link'], *"):
            for attr in ["href","src","action","data-url","data-href"]:
                try:
                    val = el.get_attribute(attr)
                    if val:
                        record_link(val, "dom", visited_links)
                except Exception:
                    continue

        # shadow DOM
        for host in driver.find_elements(By.CSS_SELECTOR, "*"):
            find_shadow_links_recursive(driver, host, visited_links)

        # XHR / fetch / pushState
        try:
            api_links = driver.execute_script("return window.collectedRequests || []")
            for url in api_links:
                record_link(url, "xhr", visited_links)
        except Exception:
            pass

        # iframes
        if depth < max_depth:
            for i, iframe in enumerate(driver.find_elements(By.TAG_NAME, "iframe")):
                try:
                    driver.switch_to.frame(iframe)
                    logging.info(f"[IFRAME] Entered iframe {i+1} at depth {depth+1}")
                    iframe_links = extract_links(visited_links, depth+1, max_depth)
                    for link in iframe_links:
                        results["iframe"].add(link)
                        all_links.add(link)
                    driver.switch_to.parent_frame()
                    logging.info(f"[IFRAME] Exited iframe {i+1} at depth {depth+1}")
                except WebDriverException:
                    logging.warning(f"[IFRAME] Cross-origin or inaccessible iframe {i+1}")
                    driver.switch_to.parent_frame()
    except Exception as e:
        logging.error(f"Error extracting links: {e}")
    return all_links


def crawl_links(urls, visited_links, depth=0, max_depth=3, max_visits=200):
    count = 0
    for url in urls:
        if normalize_url(url) not in visited_links and count < max_visits:
            logging.info(f"Visiting {url}")
            try:
                driver.get(url)
                extract_links(visited_links, depth, max_depth)
                crawl_links(list(all_links), visited_links, depth+1, max_depth, max_visits)
                count += 1
            except Exception as e:
                logging.error(f"Error visiting {url}: {e}")


# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    try:
        login_to_app()
        namespaces = load_namespaces()
        visited_links = set()
        crawl_links(namespaces, visited_links, max_depth=3)

        with open("crawled_links.txt","w") as f:
            for link in sorted(all_links):
                f.write(link+"\n")

        with open("crawled_links.json","w") as jf:
            json.dump({k: sorted(list(v)) for k,v in results.items()}, jf, indent=2)

        logging.info("Crawling complete. Links saved to crawled_links.txt and crawled_links.json.")
    finally:
        driver.quit()
        logging.info("Browser closed.")
