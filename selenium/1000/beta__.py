#!/usr/bin/env python3
from __future__ import annotations

"""
Highlights:
- Deeper dynamic coverage:
  - MutationObserver collects late-added link-ish attributes
  - Global click capture surfaces lazy menus / router links
  - window.open hook catches popup navigations
  - XHR/fetch hooks include response bodies (size-capped) for URL mining
  - Wait-for-network-idle to let AJAX finish before scraping
- Aggressiveness profiles (--profile LOW|BALANCED|AGGRESSIVE)
- Full typing, masked credentials, hardened Firefox prefs
"""

import argparse
import json
import logging
import os
import random
import re
import signal
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

from selenium import webdriver
from selenium.common.exceptions import (
    NoSuchElementException,
    StaleElementReferenceException,
    TimeoutException,
    WebDriverException,
)
from selenium.webdriver import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

# ----------------------------
# Constants
# ----------------------------
LOGIN_URL: str = "https://app.stg.thousandeyes.com/login?teRegion=1"
NAMESPACES_FILE: str = "namespaces.txt"
VISITED_LINKS_FILE: str = "visited_links_cache.json"

MAX_VISITS: int = int(os.getenv("MAX_VISITS", "500"))
MAX_DEPTH: int = int(os.getenv("MAX_DEPTH", "4"))

# asset extensions to skip
SKIP_EXT: Set[str] = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".mp4", ".webm", ".mp3", ".wav"
}

# attributes that often contain URLs
URL_ATTRS: Tuple[str, ...] = (
    "href", "src", "action", "formaction",
    "data-url", "data-href", "data-link", "data-route",
    "data-nav", "data-target", "data-path",
    "routerlink", "ng-href"
)

# CSS selectors likely to hide navigations
HARVEST_SELECTORS: Tuple[str, ...] = (
    "a[href], area[href], link[href]",
    "[role='link'], [role='menuitem'], [data-route], [data-link], [data-href], [data-url], [routerlink], [ng-href]",
    "button[formaction], [onclick*='location'], [onclick*='href']",
)

# conservative URL regex for mining AJAX/HTML bodies
URL_RE: re.Pattern[str] = re.compile(
    r"""(?xi)
    \b
    (?:https?://|/)[^\s"'<>)\]}{,]+
    """
)

# ----------------------------
# CLI
# ----------------------------
def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enhanced Selenium Web Crawler (dynamic harvest)")
    parser.add_argument(
        "--target-domain",
        default="app.stg.thousandeyes.com",
        help="Target domain to crawl (default: app.stg.thousandeyes.com)",
    )
    parser.add_argument("--allow-external", action="store_true", help="Allow crawling external domains")
    parser.add_argument(
        "--external-domains",
        nargs="*",
        default=[],
        help="Additional allowed domains when --allow-external is used",
    )
    parser.add_argument("--no-headless", action="store_true", help="Run browser with GUI (for debugging)")

    # New (optional) tuning — defaults chosen to preserve behavior
    parser.add_argument(
        "--profile",
        choices=["LOW", "BALANCED", "AGGRESSIVE"],
        default=os.getenv("CRAWL_PROFILE", "BALANCED"),
        help="Tuning preset for depth/scrolls/iframes/shadow/etc. (default: BALANCED)"
    )
    parser.add_argument("--max-body-bytes", type=int, default=int(os.getenv("MAX_BODY_BYTES", "500000")),
                        help="Max bytes of each AJAX/HTML body to store and mine (default: 500k)")
    parser.add_argument("--network-idle-ms", type=int, default=int(os.getenv("NETWORK_IDLE_MS", "400")),
                        help="How long pending requests must stay at 0 to consider idle (default: 400ms)")
    parser.add_argument("--extra-wait-ms", type=int, default=int(os.getenv("EXTRA_WAIT_MS", "250")),
                        help="Small settle delay after idle to let DOM finalize (default: 250ms)")

    return parser.parse_args()


args = parse_arguments()

# ----------------------------
# Logging
# ----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("selenium_crawl.log", mode="a"), logging.StreamHandler()],
)

# ----------------------------
# Credentials (masked)
# ----------------------------
def _mask(s: Optional[str]) -> str:
    if not s:
        return ""
    return s[:2] + "*" * max(0, len(s) - 4) + s[-2:] if len(s) > 4 else "*" * len(s)

USERNAME: str = os.getenv("TE_USERNAME", "x@x.com.org")
PASSWORD: str = os.getenv("TE_PASSWORD", "xxxxxxxxxxx")

if not USERNAME or not PASSWORD:
    logging.error("Credentials not found. Set TE_USERNAME and TE_PASSWORD environment variables.")
    sys.exit(1)
if USERNAME == "tschaffner+tester@thousandeyes.com":
    logging.warning("SECURITY: default username in use (consider exporting TE_USERNAME)")
if PASSWORD == "7res=0u2aJateGaDrOdr":
    logging.warning("SECURITY: default password in use (consider exporting TE_PASSWORD)")

# ----------------------------
# Domain configuration
# ----------------------------
TARGET_DOMAIN: str = args.target_domain
ALLOW_EXTERNAL: bool = args.allow_external
EXTERNAL_DOMAINS: Set[str] = set(args.external_domains)

ALLOWED_DOMAINS: Set[str] = {TARGET_DOMAIN}
if ALLOW_EXTERNAL:
    ALLOWED_DOMAINS.update(EXTERNAL_DOMAINS)
    ALLOWED_DOMAINS.update(
        {
            "www.thousandeyes.com",
            "docs.thousandeyes.com",
            "status.thousandeyes.com",
            "app.thousandeyes.com",
        }
    )

logging.info(f"Target domain: {TARGET_DOMAIN}")
logging.info(f"Allow external: {ALLOW_EXTERNAL}")
if ALLOW_EXTERNAL:
    logging.info(f"Allowed domains: {sorted(ALLOWED_DOMAINS)}")

# ----------------------------
# Profiles
# ----------------------------
@dataclass(frozen=True)
class CrawlProfile:
    max_scrolls: int
    pause_time_s: float
    max_iframes_per_page: int
    max_shadow_hosts: int
    click_menu_cap: int
    click_tab_cap: int
    expand_cap: int

PROFILES: Dict[str, CrawlProfile] = {
    "LOW": CrawlProfile(
        max_scrolls=1, pause_time_s=0.8, max_iframes_per_page=1, max_shadow_hosts=20, click_menu_cap=1, click_tab_cap=1, expand_cap=1
    ),
    "BALANCED": CrawlProfile(
        max_scrolls=3, pause_time_s=1.2, max_iframes_per_page=3, max_shadow_hosts=50, click_menu_cap=3, click_tab_cap=3, expand_cap=5
    ),
    "AGGRESSIVE": CrawlProfile(
        max_scrolls=6, pause_time_s=1.5, max_iframes_per_page=6, max_shadow_hosts=120, click_menu_cap=8, click_tab_cap=6, expand_cap=10
    ),
}
PROFILE: CrawlProfile = PROFILES.get(args.profile.upper(), PROFILES["BALANCED"])
logging.info("Initialized crawler | profile=%s | target=%s", args.profile.upper(), TARGET_DOMAIN)

# ----------------------------
# Results
# ----------------------------
results: Dict[str, Set[str]] = {
    "dom": set(),
    "shadow": set(),
    "iframe": set(),
    "xhr": set(),
    "dynamic": set(),  # used for mutation/click/window.open finds
    "forms": set(),
    "spa_routes": set(),
    "external": set(),
}
visited_links_cache: Set[str] = set()

# ----------------------------
# WebDriver
# ----------------------------
def create_driver() -> WebDriver:
    firefox_options = Options()
    if not args.no_headless:
        firefox_options.add_argument("--headless")
    firefox_options.add_argument("--no-sandbox")
    firefox_options.add_argument("--disable-dev-shm-usage")
    firefox_options.add_argument("--disable-gpu")
    firefox_options.add_argument("--window-size=1920,1080")

    # Hardening / privacy prefs
    firefox_options.set_preference("dom.webnotifications.enabled", False)
    firefox_options.set_preference("media.navigator.enabled", False)
    firefox_options.set_preference("geo.enabled", False)
    firefox_options.set_preference("signon.rememberSignons", False)
    firefox_options.set_preference("browser.formfill.enable", False)
    firefox_options.set_preference("network.cookie.cookieBehavior", 0)  # default; explicit

    webdriver_service = Service("/usr/local/bin/geckodriver")
    driver: WebDriver = webdriver.Firefox(service=webdriver_service, options=firefox_options)
    driver.set_page_load_timeout(30)
    return driver

# ----------------------------
# Helpers
# ----------------------------
def normalize_url(url: str, base_url: Optional[str] = None) -> str:
    try:
        if base_url and not url.startswith(("http://", "https://")):
            url = urljoin(base_url, url)
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    except Exception:
        return url

def _should_skip_by_ext(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in SKIP_EXT)
    except Exception:
        return False

def is_valid_target_url(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]
        if not domain and parsed.path.startswith("/"):
            # relative path; allow, will be normalized by caller
            pass
        if ALLOW_EXTERNAL:
            allowed = any(domain == allowed or domain.endswith("." + allowed) for allowed in ALLOWED_DOMAINS) if domain else True
        else:
            allowed = (domain == TARGET_DOMAIN) or (domain.endswith("." + TARGET_DOMAIN) if domain else True)
        if not allowed:
            if parsed.netloc.endswith("thousandeyes.com"):
                results["external"].add(url)
            return False
        if _should_skip_by_ext(url):
            return False
        return True
    except Exception:
        return False

def load_visited_cache() -> None:
    global visited_links_cache
    if os.path.exists(VISITED_LINKS_FILE):
        try:
            with open(VISITED_LINKS_FILE, "r") as f:
                data = json.load(f)
            visited_links_cache = set(data.get("visited", []))
            logging.info(f"Loaded {len(visited_links_cache)} previously visited links")
        except Exception as e:
            logging.warning(f"Could not load visited cache: {e}")

def save_visited_cache() -> None:
    try:
        with open(VISITED_LINKS_FILE, "w") as f:
            json.dump({"visited": list(visited_links_cache)}, f, indent=2)
    except Exception as e:
        logging.error(f"Could not save visited cache: {e}")

def load_namespaces() -> List[str]:
    if not os.path.exists(NAMESPACES_FILE):
        logging.warning(f"{NAMESPACES_FILE} not found. Using only the login URL.")
        return [LOGIN_URL]
    with open(NAMESPACES_FILE, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
    if not ALLOW_EXTERNAL and TARGET_DOMAIN != "app.stg.thousandeyes.com":
        valid: List[str] = []
        for url in urls:
            if is_valid_target_url(url):
                valid.append(url)
            else:
                logging.warning(f"Skipping namespace outside target domain: {url}")
        if not valid:
            logging.warning("No valid namespaces found, using login URL")
            return [LOGIN_URL]
        return valid
    return urls

def random_delay(min_delay: float = 0.5, max_delay: float = 2.0) -> None:
    time.sleep(random.uniform(min_delay, max_delay))

# ----------------------------
# Login
# ----------------------------
def login_to_app(driver: WebDriver) -> None:
    logging.info("Logging in as %s", _mask(USERNAME))
    logging.info("Starting login process...")
    try:
        driver.get(LOGIN_URL)
        WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.ID, "email")))
        email_input = driver.find_element(By.ID, "email")
        email_input.clear()
        for char in USERNAME:
            email_input.send_keys(char)
            time.sleep(random.uniform(0.05, 0.15))
        email_input.send_keys(Keys.RETURN)
        logging.info("Email submitted.")

        WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.ID, "password")))
        password_input = driver.find_element(By.ID, "password")
        password_input.clear()
        for char in PASSWORD:
            password_input.send_keys(char)
            time.sleep(random.uniform(0.05, 0.15))
        password_input.send_keys(Keys.RETURN)
        logging.info("Password submitted.")

        WebDriverWait(driver, 20).until(EC.title_contains("Dashboard"))
        logging.info("Login successful.")

        # Install advanced hooks (f-string; JS braces escaped).... lol
        driver.execute_script(
            f"""
            (function() {{
              if (window._hooksInstalledV2) return;
              window._hooksInstalledV2 = true;
              window.collectedRequests = [];
              window.collectedRoutes = [];
              window.collectedBodies = [];
              window.collectedDomLinks = new Set();
              window.pendingRequests = 0;

              function pushLink(u) {{
                try {{
                  var s = (typeof u === 'string') ? u : (u && u.url) || '';
                  if (!s) return;
                  window.collectedDomLinks.add(s);
                }} catch(e) {{}} 
              }}

              // Seed initial DOM
              try {{
                document.querySelectorAll("[href],[src],[action],[data-url],[data-href],[data-link],[data-route],[formaction],[routerlink],[ng-href]").forEach(function(el){{
                  ["href","src","action","data-url","data-href","data-link","data-route","formaction","routerlink","ng-href"].forEach(function(a){{
                    var v = el.getAttribute(a);
                    if (v) pushLink(v);
                  }});
                }});
              }} catch(_) {{}} 

              // Observe mutations
              try {{
                var mo = new MutationObserver(function(muts){{
                  muts.forEach(function(m){{
                    (m.addedNodes||[]).forEach(function(n){{
                      try {{
                        if (n.querySelectorAll) {{
                          n.querySelectorAll("[href],[src],[action],[data-url],[data-href],[data-link],[data-route],[formaction],[routerlink],[ng-href]").forEach(function(el){{
                            ["href","src","action","data-url","data-href","data-link","data-route","formaction","routerlink","ng-href"].forEach(function(a){{
                              var v = el.getAttribute(a);
                              if (v) pushLink(v);
                            }});
                          }});
                        }}
                      }} catch(e) {{}} 
                    }});
                  }});
                }});
                mo.observe(document.documentElement, {{subtree:true, childList:true}});
              }} catch(_) {{}} 

              // Click capture (useCapture true)
              document.addEventListener('click', function(e){{
                try {{
                  var el = e.target;
                  var hops=5;
                  while (el && hops--) {{
                    ["href","src","action","data-url","data-href","data-link","data-route","formaction","routerlink","ng-href"].forEach(function(a){{
                      var v = el.getAttribute && el.getAttribute(a);
                      if (v) pushLink(v);
                    }});
                    el = el.parentElement;
                  }}
                }} catch(_){{}} 
              }}, true);

              // window.open
              try {{
                var _open = window.open;
                window.open = function(u,n,f) {{
                  try {{ pushLink(u); }} catch(e) {{}} 
                  return _open.apply(window, arguments);
                }}
              }} catch(_){{}} 

              // XHR hook
              var origOpen = XMLHttpRequest.prototype.open;
              XMLHttpRequest.prototype.open = function(method, url) {{
                try {{
                  window.collectedRequests.push({{url: url, method: method, type: 'xhr'}});
                }} catch(e) {{}} 
                this._te_url = url;
                return origOpen.apply(this, arguments);
              }};
              var origSend = XMLHttpRequest.prototype.send;
              XMLHttpRequest.prototype.send = function() {{
                try {{ window.pendingRequests++; }} catch(_){{}} 
                var self=this;
                this.addEventListener('loadend', function(){{
                  try {{
                    window.pendingRequests--;
                    var ct = (self.getResponseHeader && self.getResponseHeader('content-type')) || '';
                    var body = '';
                    try {{ body = self.responseText || ''; }} catch(_){{}} 
                    if (body && body.length < {args.max_body_bytes}) {{
                      window.collectedBodies.push({{url: self._te_url || '', ct: ct, body: body}});
                    }}
                  }} catch(_){{}} 
                }});
                return origSend.apply(this, arguments);
              }};

              // fetch hook
              var origFetch = window.fetch;
              window.fetch = function(url, options) {{
                try {{
                  window.collectedRequests.push({{
                    url: typeof url === 'string' ? url : (url && url.url),
                    method: (options && options.method) || 'GET',
                    type: 'fetch'
                  }});
                  window.pendingRequests++;
                }} catch(e) {{}} 
                return origFetch.apply(this, arguments).then(function(resp){{
                  try {{
                    window.pendingRequests--;
                    var ct = (resp.headers && resp.headers.get('content-type')) || '';
                    var copy = resp.clone();
                    copy.text().then(function(txt){{
                      if (txt && txt.length < {args.max_body_bytes}) {{
                        window.collectedBodies.push({{url: resp.url, ct: ct, body: txt}});
                      }}
                    }}).catch(function(){{}});
                  }} catch(_){{}} 
                  return resp;
                }});
              }};

              // SPA routes
              var origPush = history.pushState;
              history.pushState = function(state, title, url) {{
                try {{ window.collectedRoutes.push(url ? url.toString() : window.location.href); }} catch(e) {{}} 
                return origPush.apply(this, arguments);
              }};
              var origReplace = history.replaceState;
              history.replaceState = function(state, title, url) {{
                try {{ window.collectedRoutes.push(url ? url.toString() : window.location.href); }} catch(e) {{}} 
                return origReplace.apply(this, arguments);
              }};
              window.addEventListener('hashchange', function() {{
                try {{ window.collectedRoutes.push(window.location.href); }} catch(e) {{}} 
              }});
            }})();
            """
        )
    except TimeoutException:
        logging.error("Login timed out. Page structure may have changed.")
        raise
    except NoSuchElementException as e:
        logging.error(f"Error locating elements during login: {e}")
        raise

# ----------------------------
# Waiting for page/network to settle
# ----------------------------
def wait_for_page_load(driver: WebDriver, timeout: int = 20) -> None:
    try:
        WebDriverWait(driver, timeout).until(lambda d: d.execute_script("return document.readyState") == "complete")
        # If jQuery present, wait until idle
        WebDriverWait(driver, 5).until(
            lambda d: d.execute_script(
                "return (window.jQuery && jQuery.active === 0) || (typeof window.jQuery === 'undefined')"
            )
        )
        # Common loading indicators
        try:
            WebDriverWait(driver, 5).until_not(
                EC.presence_of_element_located((By.CSS_SELECTOR, ".loading, .spinner, [data-loading='true']"))
            )
        except TimeoutException:
            pass
    except TimeoutException:
        logging.warning("Page load timeout - continuing anyway")

def wait_for_network_idle(driver: WebDriver, idle_ms: int, extra_ms: int, total_timeout_s: float = 20.0) -> None:
    """
    Uses the injected pendingRequests counter to wait for 'network idle'
    for idle_ms, then a small settle (extra_ms).
    """
    start = time.time()
    last_zero: Optional[float] = None
    idle_s = idle_ms / 1000.0
    while (time.time() - start) < total_timeout_s:
        try:
            pending = int(driver.execute_script("return window.pendingRequests || 0") or 0)
        except WebDriverException:
            break
        if pending == 0:
            if last_zero is None:
                last_zero = time.time()
            elif (time.time() - last_zero) >= idle_s:
                break
        else:
            last_zero = None
        time.sleep(0.05)
    # settle a hair
    time.sleep(max(0, extra_ms) / 1000.0)

# ----------------------------
# Interactions
# ----------------------------
def enhanced_scroll_and_interact(driver: WebDriver) -> None:
    try:
        last_height: int = int(driver.execute_script("return document.body.scrollHeight") or 0)
        for i in range(PROFILE.max_scrolls):
            for pos in (
                "window.scrollTo(0, document.body.scrollHeight * 0.25);",
                "window.scrollTo(0, document.body.scrollHeight * 0.5);",
                "window.scrollTo(0, document.body.scrollHeight * 0.75);",
                "window.scrollTo(0, document.body.scrollHeight);",
            ):
                driver.execute_script(pos)
                random_delay(0.25, 0.6)
            time.sleep(PROFILE.pause_time_s)
            new_height: int = int(driver.execute_script("return document.body.scrollHeight") or 0)
            if new_height == last_height:
                break
            last_height = new_height
        logging.info(f"[SCROLL] Enhanced scroll complete - {i+1} iterations")
    except Exception as e:
        logging.warning(f"Scroll error: {e}")

def interact_with_dynamic_elements(driver: WebDriver) -> None:
    interactions: int = 0
    try:
        # Tabs
        for el in driver.find_elements(By.CSS_SELECTOR, "[role='tab'], .tab, .nav-tab")[: PROFILE.click_tab_cap]:
            try:
                if el.is_displayed() and el.is_enabled():
                    ActionChains(driver).move_to_element(el).click().perform()
                    random_delay(0.35, 0.8)
                    interactions += 1
                    logging.info("[INTERACT] Clicked tab")
            except Exception:
                continue
        # Accordions / expanders
        for el in driver.find_elements(By.CSS_SELECTOR, "[aria-expanded='false'], .collapsed, .accordion-toggle, .expand-btn")[: PROFILE.expand_cap]:
            try:
                if el.is_displayed() and el.is_enabled():
                    ActionChains(driver).move_to_element(el).click().perform()
                    random_delay(0.35, 0.8)
                    interactions += 1
                    logging.info("[INTERACT] Expanded element")
            except Exception:
                continue
        # Menus / menuitems
        for el in driver.find_elements(By.CSS_SELECTOR, ".menu-item, .dropdown-toggle, [role='menuitem']")[: PROFILE.click_menu_cap]:
            try:
                if el.is_displayed():
                    ActionChains(driver).move_to_element(el).perform()
                    random_delay(0.25, 0.6)
                    interactions += 1
            except Exception:
                continue
        logging.info(f"[INTERACT] Performed {interactions} dynamic interactions")
    except Exception as e:
        logging.warning(f"Dynamic interaction error: {e}")

# ----------------------------
# Extraction
# ----------------------------
def _add_link(candidate: str, current_url: str, visited_links: Set[str], bucket: str, into: Set[str]) -> None:
    if not candidate:
        return
    normalized = normalize_url(candidate, current_url)
    if is_valid_target_url(normalized) and normalized not in visited_links:
        into.add(normalized)
        if bucket in results:
            results[bucket].add(normalized)
        logging.info("[%s] Found: %s", bucket.upper(), normalized)

def _mine_urls_from_text(text: str) -> Set[str]:
    if not text:
        return set()
    found = set(URL_RE.findall(text))
    return found

def find_shadow_links_recursive(driver: WebDriver, host: Any, visited_links: Set[str], current_url: str) -> Set[str]:
    links: Set[str] = set()
    try:
        shadow_root = driver.execute_script("return arguments[0].shadowRoot", host)
        if shadow_root:
            all_nodes = shadow_root.find_elements(By.CSS_SELECTOR, "*")
            for node in all_nodes:
                for attr in URL_ATTRS:
                    try:
                        val = node.get_attribute(attr)
                        if val:
                            _add_link(val, current_url, visited_links, "shadow", links)
                    except Exception:
                        continue
                try:
                    links.update(find_shadow_links_recursive(driver, node, visited_links, current_url))
                except Exception:
                    continue
    except Exception:
        pass
    return links

def extract_form_actions(driver: WebDriver, current_url: str, visited_links: Set[str]) -> Set[str]:
    links: Set[str] = set()
    try:
        for form in driver.find_elements(By.TAG_NAME, "form"):
            try:
                action = form.get_attribute("action")
                if action:
                    _add_link(action, current_url, visited_links, "forms", links)
            except Exception:
                continue
    except Exception as e:
        logging.warning(f"Form extraction error: {e}")
    return links

def extract_links(driver: WebDriver, visited_links: Set[str], depth: int = 0, max_depth: int = 4) -> Set[str]:
    links: Set[str] = set()
    current_url: str = driver.current_url
    try:
        wait_for_page_load(driver)
        # Let AJAX kick off
        wait_for_network_idle(driver, args.network_idle_ms, args.extra_wait_ms)
        enhanced_scroll_and_interact(driver)
        # Let lazy content request more data
        wait_for_network_idle(driver, args.network_idle_ms, args.extra_wait_ms)
        interact_with_dynamic_elements(driver)
        wait_for_network_idle(driver, args.network_idle_ms, args.extra_wait_ms)

        # 1) DOM selectors
        for selector in HARVEST_SELECTORS:
            try:
                elements = driver.find_elements(By.CSS_SELECTOR, selector)
                for el in elements:
                    for attr in URL_ATTRS:
                        try:
                            val = el.get_attribute(attr)
                            if val:
                                _add_link(val, current_url, visited_links, "dom", links)
                        except StaleElementReferenceException:
                            break
                        except Exception:
                            continue
            except Exception:
                continue

        # 2) Shadow DOM
        try:
            shadow_hosts = driver.find_elements(By.CSS_SELECTOR, "*")
            for host in shadow_hosts[: PROFILE.max_shadow_hosts]:
                try:
                    shadow_links = find_shadow_links_recursive(driver, host, visited_links, current_url)
                    links.update(shadow_links)
                except Exception:
                    continue
        except Exception:
            pass

        # 3) Forms
        links.update(extract_form_actions(driver, current_url, visited_links))

        # 4) Dynamic (MutationObserver / click / window.open)
        try:
            collected_dynamic: List[str] = driver.execute_script("return Array.from(window.collectedDomLinks || [])") or []
            for cand in collected_dynamic:
                _add_link(cand, current_url, visited_links, "dynamic", links)
        except Exception:
            pass

        # 5) XHR/Fetch URLs and SPA routes
        try:
            collected = driver.execute_script(
                "return {req:(window.collectedRequests||[]), rt:(window.collectedRoutes||[]), bodies:(window.collectedBodies||[])};"
            ) or {}
            for req in (collected.get("req") or []):
                try:
                    url = req.get("url") if isinstance(req, dict) else req
                    if url:
                        _add_link(url, current_url, visited_links, "xhr", links)
                except Exception:
                    continue
            for route in (collected.get("rt") or []):
                try:
                    _add_link(route, current_url, visited_links, "spa_routes", links)
                except Exception:
                    continue

            # 6) Mine bodies for more URLs (JSON or HTML fragments)
            for body_item in (collected.get("bodies") or []):
                try:
                    ct = (body_item.get("ct") or "").lower()
                    body = body_item.get("body") or ""
                    if not body:
                        continue

                    # JSON: try structured keys first
                    if "json" in ct:
                        try:
                            data = json.loads(body)
                            # naive walk for url-like values
                            stack: List[Any] = [data]
                            while stack:
                                cur = stack.pop()
                                if isinstance(cur, dict):
                                    for k, v in cur.items():
                                        if isinstance(v, (dict, list)):
                                            stack.append(v)
                                        elif isinstance(v, str) and ("/" in v or "http" in v):
                                            for candidate in _mine_urls_from_text(v):
                                                _add_link(candidate, current_url, visited_links, "xhr", links)
                                elif isinstance(cur, list):
                                    stack.extend(cur)
                        except Exception:
                            # fall back to regex
                            for candidate in _mine_urls_from_text(body):
                                _add_link(candidate, current_url, visited_links, "xhr", links)
                    else:
                        # text/html or other: regex
                        for candidate in _mine_urls_from_text(body):
                            _add_link(candidate, current_url, visited_links, "xhr", links)
                except Exception:
                    continue
        except Exception as e:
            logging.warning(f"XHR/SPA extraction error: {e}")

        # 7) Iframes (profile-driven cap)
        if depth < max_depth:
            try:
                iframes = driver.find_elements(By.TAG_NAME, "iframe")
                for i, iframe in enumerate(iframes[: PROFILE.max_iframes_per_page]):
                    try:
                        driver.switch_to.frame(iframe)
                        logging.info(f"[IFRAME] Entered iframe {i+1} at depth {depth+1}")
                        iframe_links = extract_links(driver, visited_links, depth + 1, max_depth)
                        for link in iframe_links:
                            results["iframe"].add(link)
                        links.update(iframe_links)
                    except Exception as e:
                        logging.warning(f"Iframe {i+1} error: {e}")
                    finally:
                        try:
                            driver.switch_to.parent_frame()
                        except Exception:
                            pass
            except Exception:
                pass

    except Exception as e:
        logging.error(f"Link extraction error: {e}")

    return links

# ----------------------------
# Crawl
# ----------------------------
def crawl_links(
    driver: WebDriver,
    urls: Iterable[str],
    visited_links: Set[str],
    depth: int = 0,
    max_depth: int = 4,
    max_visits: int = 500,
) -> None:
    count: int = 0
    for url in list(urls):
        if url in visited_links or count >= max_visits:
            continue
        if url in visited_links_cache:
            logging.info(f"[CACHE] Skipping previously visited: {url}")
            continue

        logging.info(f"[CRAWL] Visiting ({count+1}/{max_visits}): {url}")
        try:
            driver.get(url)
            visited_links.add(url)
            visited_links_cache.add(url)

            random_delay(0.8, 1.8)

            new_links = extract_links(driver, visited_links, depth, max_depth)

            if depth < max_depth and new_links:
                # keep breadth-first feel but capped
                limited_new_links = list(new_links)[: 10 if args.profile != "AGGRESSIVE" else 25]
                crawl_links(driver, limited_new_links, visited_links, depth + 1, max_depth, max_visits - count)

            count += 1
            if count % 50 == 0:
                save_visited_cache()
        except Exception as e:
            logging.error(f"Error visiting {url}: {e}")
            continue

# ----------------------------
# Save
# ----------------------------
def save_results(visited_links: Set[str]) -> None:
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    with open(f"crawled_links_{timestamp}.txt", "w") as f:
        for link in sorted(visited_links):
            f.write(link + "\n")

    results_data: Dict[str, Any] = {
        "metadata": {
            "timestamp": timestamp,
            "target_domain": TARGET_DOMAIN,
            "allow_external": ALLOW_EXTERNAL,
            "profile": args.profile,
            "total_links": len(visited_links),
            "categorized_counts": {k: len(v) for k, v in results.items()},
        },
        "results": {k: sorted(list(v)) for k, v in results.items()},
    }

    with open(f"crawled_links_{timestamp}.json", "w") as jf:
        json.dump(results_data, jf, indent=2)

    with open("crawled_links_latest.txt", "w") as f:
        for link in sorted(visited_links):
            f.write(link + "\n")

    with open("crawled_links_latest.json", "w") as jf:
        json.dump(results_data, jf, indent=2)

    logging.info(f"Results saved with timestamp {timestamp}")
    logging.info(f"Total unique links found: {len(visited_links)}")
    for category, links_set in results.items():
        if links_set:
            logging.info(f"  {category.upper()}: {len(links_set)} links")

# ----------------------------
# Main & graceful exit
# ----------------------------
def main() -> int:
    driver: Optional[WebDriver] = None

    def _graceful_exit(signum: int, frame: Any) -> None:
        logging.info(f"Signal {signum} received, saving progress...")
        try:
            if "visited_links" in locals():
                save_results(locals()["visited_links"])
            save_visited_cache()
        finally:
            try:
                if driver:
                    driver.quit()
                    logging.info("Browser closed.")
            except Exception:
                pass
        os._exit(0)

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _graceful_exit)

    try:
        load_visited_cache()
        driver = create_driver()
        login_to_app(driver)
        namespaces: List[str] = load_namespaces()
        visited_links: Set[str] = set()
        crawl_links(driver, namespaces, visited_links, max_depth=MAX_DEPTH, max_visits=MAX_VISITS)
        save_results(visited_links)
        save_visited_cache()
        logging.info("Crawling complete!")
        return 0

    except KeyboardInterrupt:
        logging.info("Crawling interrupted by user")
        if "visited_links" in locals():
            save_results(locals()["visited_links"])
        save_visited_cache()
        return 130
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        return 2
    finally:
        if driver:
            try:
                driver.quit()
                logging.info("Browser closed.")
            except Exception:
                pass

if __name__ == "__main__":
    sys.exit(main())
