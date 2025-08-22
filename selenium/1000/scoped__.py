#!/usr/bin/env python3
import logging
import os
import json
import time
import hashlib
import random
import argparse
from urllib.parse import urlparse, urlunparse, urljoin
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import (
    TimeoutException,
    NoSuchElementException,
    WebDriverException,
    ElementClickInterceptedException,
    StaleElementReferenceException,
)

# ----------------------------
# Argument parsing (optional - defaults to original behavior)
# ----------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(description='Enhanced Selenium Web Crawler')
    parser.add_argument('--target-domain', 
                       default='app.stg.thousandeyes.com',
                       help='Target domain to crawl (default: app.stg.thousandeyes.com)')
    parser.add_argument('--allow-external', 
                       action='store_true',
                       help='Allow crawling external domains')
    parser.add_argument('--external-domains', 
                       nargs='*',
                       default=[],
                       help='Additional allowed domains when --allow-external is used')
    parser.add_argument('--no-headless', 
                       action='store_true',
                       help='Run browser with GUI (for debugging)')
    
    return parser.parse_args()

# Parse arguments
args = parse_arguments()

# ----------------------------
# Logging setup
# ----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("selenium_crawl.log", mode='a'),
        logging.StreamHandler()
    ],
)

# ----------------------------
# Security: Environment variables for credentials
# ----------------------------
USERNAME = os.getenv("TE_USERNAME", "things@things.org")
PASSWORD = os.getenv("TE_PASSWORD", "asfasdfass=asfasf")

if not USERNAME or not PASSWORD:
    logging.error("Credentials not found. Set TE_USERNAME and TE_PASSWORD environment variables.")
    exit(1)

# ----------------------------
# Domain configuration
# ----------------------------
TARGET_DOMAIN = args.target_domain
ALLOW_EXTERNAL = args.allow_external
EXTERNAL_DOMAINS = set(args.external_domains)

# Build allowed domains set
ALLOWED_DOMAINS = {TARGET_DOMAIN}
if ALLOW_EXTERNAL:
    ALLOWED_DOMAINS.update(EXTERNAL_DOMAINS)
    # Add common ThousandEyes domains if external is allowed
    te_domains = {
        'www.thousandeyes.com',
        'docs.thousandeyes.com', 
        'status.thousandeyes.com',
        'app.thousandeyes.com'
    }
    ALLOWED_DOMAINS.update(te_domains)

logging.info(f"Target domain: {TARGET_DOMAIN}")
logging.info(f"Allow external: {ALLOW_EXTERNAL}")
if ALLOW_EXTERNAL:
    logging.info(f"Allowed domains: {sorted(ALLOWED_DOMAINS)}")

# ----------------------------
# Enhanced WebDriver setup
# ----------------------------
def create_driver():
    firefox_options = Options()
    if not args.no_headless:  # Only add headless if not debugging
        firefox_options.add_argument("--headless")
    firefox_options.add_argument("--no-sandbox")
    firefox_options.add_argument("--disable-dev-shm-usage")
    firefox_options.add_argument("--disable-gpu")
    firefox_options.add_argument("--window-size=1920,1080")
    
    # Enhanced security headers
    firefox_options.set_preference("dom.webnotifications.enabled", False)
    firefox_options.set_preference("media.navigator.enabled", False)
    firefox_options.set_preference("geo.enabled", False)
    
    webdriver_service = Service("/usr/local/bin/geckodriver")
    return webdriver.Firefox(service=webdriver_service, options=firefox_options)

# ----------------------------
# Config
# ----------------------------
login_url = "https://app.stg.thousandeyes.com/login?teRegion=1"
NAMESPACES_FILE = "namespaces.txt"
VISITED_LINKS_FILE = "visited_links_cache.json"
MAX_VISITS = int(os.getenv("MAX_VISITS", "500"))
MAX_DEPTH = int(os.getenv("MAX_DEPTH", "4"))

results = {
    "dom": set(), 
    "shadow": set(), 
    "iframe": set(), 
    "xhr": set(),
    "dynamic": set(),
    "forms": set(),
    "spa_routes": set(),
    "external": set()  # Track external links when found
}

visited_links_cache = set()

# ----------------------------
# Enhanced Helpers
# ----------------------------
def normalize_url(url: str, base_url: str = None) -> str:
    try:
        if base_url and not url.startswith(('http://', 'https://')):
            url = urljoin(base_url, url)
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    except Exception:
        return url

def is_valid_target_url(url: str) -> bool:
    """Enhanced URL validation with domain scoping"""
    if not url or not isinstance(url, str):
        return False
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove port numbers for comparison
        domain = domain.split(':')[0]
        
        # Check if domain is allowed
        domain_allowed = False
        if ALLOW_EXTERNAL:
            domain_allowed = any(domain == allowed or domain.endswith('.' + allowed) 
                               for allowed in ALLOWED_DOMAINS)
        else:
            # Strict domain matching for target domain only
            domain_allowed = (domain == TARGET_DOMAIN or 
                            domain.endswith('.' + TARGET_DOMAIN))
        
        if not domain_allowed:
            # Track external links when found (but only if they're ThousandEyes related)
            if parsed.netloc.endswith('thousandeyes.com'):
                results["external"].add(url)
                logging.debug(f"[EXTERNAL] Found external ThousandEyes domain: {domain}")
            return False
        
        # Skip common asset files
        skip_extensions = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf'}
        if any(parsed.path.lower().endswith(ext) for ext in skip_extensions):
            return False
            
        return True
    except Exception:
        return False

def load_visited_cache():
    """Load previously visited links to avoid re-crawling"""
    global visited_links_cache
    if os.path.exists(VISITED_LINKS_FILE):
        try:
            with open(VISITED_LINKS_FILE, 'r') as f:
                data = json.load(f)
                visited_links_cache = set(data.get('visited', []))
                logging.info(f"Loaded {len(visited_links_cache)} previously visited links")
        except Exception as e:
            logging.warning(f"Could not load visited cache: {e}")

def save_visited_cache():
    """Save visited links cache"""
    try:
        with open(VISITED_LINKS_FILE, 'w') as f:
            json.dump({'visited': list(visited_links_cache)}, f, indent=2)
    except Exception as e:
        logging.error(f"Could not save visited cache: {e}")

def load_namespaces():
    if not os.path.exists(NAMESPACES_FILE):
        logging.warning(f"{NAMESPACES_FILE} not found. Using only the login URL.")
        return [login_url]
    with open(NAMESPACES_FILE, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
        
    # Filter namespaces to only include allowed domains (if scoping is enabled)
    if not ALLOW_EXTERNAL and TARGET_DOMAIN != 'app.stg.thousandeyes.com':
        valid_urls = []
        for url in urls:
            if is_valid_target_url(url):
                valid_urls.append(url)
            else:
                logging.warning(f"Skipping namespace outside target domain: {url}")
        
        if not valid_urls:
            logging.warning("No valid namespaces found, using login URL")
            return [login_url]
        
        return valid_urls
    
    return urls

def random_delay(min_delay=0.5, max_delay=2.0):
    """Add random delay to avoid detection"""
    time.sleep(random.uniform(min_delay, max_delay))

def login_to_app(driver):
    logging.info("Starting login process...")
    try:
        driver.get(login_url)
        WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.ID, "email")))
        
        email_input = driver.find_element(By.ID, "email")
        email_input.clear()
        # Simulate human typing
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

        # Enhanced JavaScript hooks
        driver.execute_script("""
            (function() {
              if (window._hooksInstalled) return;
              window._hooksInstalled = true;
              window.collectedRequests = [];
              window.collectedRoutes = [];
              
              // XHR/Fetch hooks
              var origOpen = XMLHttpRequest.prototype.open;
              XMLHttpRequest.prototype.open = function(method, url) {
                try { 
                  window.collectedRequests.push({url: url, method: method, type: 'xhr'}); 
                } catch(e){}
                return origOpen.apply(this, arguments);
              };
              
              var origFetch = window.fetch;
              window.fetch = function(url, options) {
                try { 
                  window.collectedRequests.push({
                    url: typeof url === 'string' ? url : url.url, 
                    method: (options && options.method) || 'GET',
                    type: 'fetch'
                  }); 
                } catch(e){}
                return origFetch.apply(this, arguments);
              };
              
              // History API hooks
              var origPush = history.pushState;
              history.pushState = function(state, title, url) {
                try { 
                  window.collectedRoutes.push(url ? url.toString() : window.location.href); 
                } catch(e){}
                return origPush.apply(this, arguments);
              };
              
              var origReplace = history.replaceState;
              history.replaceState = function(state, title, url) {
                try { 
                  window.collectedRoutes.push(url ? url.toString() : window.location.href); 
                } catch(e){}
                return origReplace.apply(this, arguments);
              };
              
              // Listen for hashchange
              window.addEventListener('hashchange', function() {
                try {
                  window.collectedRoutes.push(window.location.href);
                } catch(e){}
              });
            })();
        """)
        
    except TimeoutException:
        logging.error("Login timed out. Page structure may have changed.")
        raise
    except NoSuchElementException as e:
        logging.error(f"Error locating elements during login: {e}")
        raise

def wait_for_page_load(driver, timeout=15):
    """Enhanced page load waiting"""
    try:
        # Wait for document ready
        WebDriverWait(driver, timeout).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )
        
        # Wait for jQuery if present
        WebDriverWait(driver, 5).until(
            lambda d: d.execute_script(
                "return (window.jQuery && jQuery.active === 0) || (typeof window.jQuery === 'undefined')"
            )
        )
        
        # Wait for common loading indicators to disappear
        try:
            WebDriverWait(driver, 5).until_not(
                EC.presence_of_element_located((By.CSS_SELECTOR, ".loading, .spinner, [data-loading='true']"))
            )
        except TimeoutException:
            pass
            
    except TimeoutException:
        logging.warning("Page load timeout - continuing anyway")

def enhanced_scroll_and_interact(driver, pause_time=1.5, max_scrolls=8):
    """Enhanced scrolling with interaction simulation"""
    try:
        last_height = driver.execute_script("return document.body.scrollHeight")
        
        for i in range(max_scrolls):
            # Scroll to different positions
            scroll_positions = [
                "window.scrollTo(0, document.body.scrollHeight * 0.25);",
                "window.scrollTo(0, document.body.scrollHeight * 0.5);",
                "window.scrollTo(0, document.body.scrollHeight * 0.75);",
                "window.scrollTo(0, document.body.scrollHeight);"
            ]
            
            for pos in scroll_positions:
                driver.execute_script(pos)
                random_delay(0.3, 0.8)
            
            time.sleep(pause_time)
            new_height = driver.execute_script("return document.body.scrollHeight")
            
            if new_height == last_height:
                break
            last_height = new_height
            
        logging.info(f"[SCROLL] Enhanced scroll complete - {i+1} iterations")
        
    except Exception as e:
        logging.warning(f"Scroll error: {e}")

def interact_with_dynamic_elements(driver):
    """Interact with dropdowns, tabs, accordions, etc."""
    interactions = 0
    
    try:
        # Click tabs
        tabs = driver.find_elements(By.CSS_SELECTOR, "[role='tab'], .tab, .nav-tab")
        for tab in tabs[:5]:  # Limit to avoid infinite loops
            try:
                if tab.is_displayed() and tab.is_enabled():
                    ActionChains(driver).move_to_element(tab).click().perform()
                    random_delay(0.5, 1.0)
                    interactions += 1
                    logging.info("[INTERACT] Clicked tab")
            except Exception:
                continue
        
        # Expand accordions/collapsibles
        expandables = driver.find_elements(By.CSS_SELECTOR, 
            "[aria-expanded='false'], .collapsed, .accordion-toggle, .expand-btn")
        for elem in expandables[:5]:
            try:
                if elem.is_displayed() and elem.is_enabled():
                    ActionChains(driver).move_to_element(elem).click().perform()
                    random_delay(0.5, 1.0)
                    interactions += 1
                    logging.info("[INTERACT] Expanded element")
            except Exception:
                continue
                
        # Hover over menu items
        menus = driver.find_elements(By.CSS_SELECTOR, 
            ".menu-item, .dropdown-toggle, [role='menuitem']")
        for menu in menus[:3]:
            try:
                if menu.is_displayed():
                    ActionChains(driver).move_to_element(menu).perform()
                    random_delay(0.3, 0.7)
                    interactions += 1
            except Exception:
                continue
                
        logging.info(f"[INTERACT] Performed {interactions} dynamic interactions")
        
    except Exception as e:
        logging.warning(f"Dynamic interaction error: {e}")

def find_shadow_links_recursive(driver, host, visited_links, current_url):
    """Enhanced shadow DOM traversal"""
    links = set()
    try:
        shadow_root = driver.execute_script("return arguments[0].shadowRoot", host)
        if shadow_root:
            all_nodes = shadow_root.find_elements(By.CSS_SELECTOR, "*")
            for node in all_nodes:
                # Check multiple attributes
                attrs_to_check = ["href", "src", "action", "data-url", "data-href", 
                                "data-link", "data-route", "formaction"]
                
                for attr in attrs_to_check:
                    try:
                        val = node.get_attribute(attr)
                        if val:
                            normalized = normalize_url(val, current_url)
                            if is_valid_target_url(normalized) and normalized not in visited_links:
                                links.add(normalized)
                                results["shadow"].add(normalized)
                                logging.info(f"[SHADOW] Found: {normalized}")
                    except Exception:
                        continue
                        
                # Recursively check child shadow roots
                try:
                    links.update(find_shadow_links_recursive(driver, node, visited_links, current_url))
                except Exception:
                    continue
                    
    except Exception as e:
        logging.debug(f"Shadow DOM error: {e}")
    return links

def extract_form_actions(driver, current_url, visited_links):
    """Extract form action URLs"""
    links = set()
    try:
        forms = driver.find_elements(By.TAG_NAME, "form")
        for form in forms:
            try:
                action = form.get_attribute("action")
                if action:
                    normalized = normalize_url(action, current_url)
                    if is_valid_target_url(normalized) and normalized not in visited_links:
                        links.add(normalized)
                        results["forms"].add(normalized)
                        logging.info(f"[FORM] Found action: {normalized}")
            except Exception:
                continue
    except Exception as e:
        logging.warning(f"Form extraction error: {e}")
    return links

def extract_links(driver, visited_links, depth=0, max_depth=4):
    """Enhanced link extraction with better coverage"""
    links = set()
    current_url = driver.current_url
    
    try:
        wait_for_page_load(driver)
        enhanced_scroll_and_interact(driver)
        interact_with_dynamic_elements(driver)
        
        # Extract DOM links with enhanced selectors
        selectors = [
            "a[href]", "area[href]", "link[href]", 
            "[data-url]", "[data-href]", "[data-link]", "[data-route]",
            "button[formaction]", "[onclick*='location']", "[onclick*='href']"
        ]
        
        for selector in selectors:
            try:
                elements = driver.find_elements(By.CSS_SELECTOR, selector)
                for el in elements:
                    attrs_to_check = ["href", "data-url", "data-href", "data-link", 
                                    "data-route", "formaction"]
                    
                    for attr in attrs_to_check:
                        try:
                            val = el.get_attribute(attr)
                            if val:
                                normalized = normalize_url(val, current_url)
                                if is_valid_target_url(normalized) and normalized not in visited_links:
                                    links.add(normalized)
                                    results["dom"].add(normalized)
                                    logging.info(f"[DOM] Found: {normalized}")
                        except StaleElementReferenceException:
                            break
                        except Exception:
                            continue
            except Exception:
                continue

        # Extract shadow DOM links
        try:
            shadow_hosts = driver.find_elements(By.CSS_SELECTOR, "*")
            for host in shadow_hosts[:50]:  # Limit to avoid performance issues
                try:
                    shadow_links = find_shadow_links_recursive(driver, host, visited_links, current_url)
                    links.update(shadow_links)
                except Exception:
                    continue
        except Exception:
            pass

        # Extract form actions
        form_links = extract_form_actions(driver, current_url, visited_links)
        links.update(form_links)

        # Extract XHR/Fetch and SPA routes
        try:
            collected_data = driver.execute_script("""
                return {
                    requests: window.collectedRequests || [],
                    routes: window.collectedRoutes || []
                };
            """)
            
            # Process API requests
            for req in collected_data.get('requests', []):
                try:
                    url = req.get('url') if isinstance(req, dict) else req
                    if url:
                        normalized = normalize_url(url, current_url)
                        if is_valid_target_url(normalized) and normalized not in visited_links:
                            links.add(normalized)
                            results["xhr"].add(normalized)
                            logging.info(f"[XHR] Found: {normalized}")
                except Exception:
                    continue
            
            # Process SPA routes
            for route in collected_data.get('routes', []):
                try:
                    normalized = normalize_url(route, current_url)
                    if is_valid_target_url(normalized) and normalized not in visited_links:
                        links.add(normalized)
                        results["spa_routes"].add(normalized)
                        logging.info(f"[SPA] Found route: {normalized}")
                except Exception:
                    continue
                    
        except Exception as e:
            logging.warning(f"XHR/SPA extraction error: {e}")

        # Handle iframes with depth limiting
        if depth < max_depth:
            try:
                iframes = driver.find_elements(By.TAG_NAME, "iframe")
                for i, iframe in enumerate(iframes[:3]):  # Limit iframe processing
                    try:
                        driver.switch_to.frame(iframe)
                        logging.info(f"[IFRAME] Entered iframe {i+1} at depth {depth+1}")
                        
                        iframe_links = extract_links(driver, visited_links, depth+1, max_depth)
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

def crawl_links(driver, urls, visited_links, depth=0, max_depth=4, max_visits=500):
    """Enhanced crawling with better error handling and limits"""
    count = 0
    
    for url in list(urls):  # Convert to list to avoid modification during iteration
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
            
            random_delay(1.0, 3.0)  # Be respectful to the server
            
            new_links = extract_links(driver, visited_links, depth, max_depth)
            
            if depth < max_depth and new_links:
                # Recursively crawl new links (limited)
                limited_new_links = list(new_links)[:10]  # Limit recursive crawling
                crawl_links(driver, limited_new_links, visited_links, 
                          depth+1, max_depth, max_visits - count)
            
            count += 1
            
            # Periodic cache save
            if count % 50 == 0:
                save_visited_cache()
                
        except Exception as e:
            logging.error(f"Error visiting {url}: {e}")
            continue

def save_results(visited_links):
    """Enhanced result saving with metadata"""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    
    # Save all links
    with open(f"crawled_links_{timestamp}.txt", "w") as f:
        for link in sorted(visited_links):
            f.write(link + "\n")
    
    # Save categorized results
    results_data = {
        "metadata": {
            "timestamp": timestamp,
            "target_domain": TARGET_DOMAIN,
            "allow_external": ALLOW_EXTERNAL,
            "total_links": len(visited_links),
            "categorized_counts": {k: len(v) for k, v in results.items()}
        },
        "results": {k: sorted(list(v)) for k, v in results.items()}
    }
    
    with open(f"crawled_links_{timestamp}.json", "w") as jf:
        json.dump(results_data, jf, indent=2)
    
    # Also save latest versions
    with open("crawled_links_latest.txt", "w") as f:
        for link in sorted(visited_links):
            f.write(link + "\n")
    
    with open("crawled_links_latest.json", "w") as jf:
        json.dump(results_data, jf, indent=2)
    
    logging.info(f"Results saved with timestamp {timestamp}")
    logging.info(f"Total unique links found: {len(visited_links)}")
    for category, links in results.items():
        if links:
            logging.info(f"  {category.upper()}: {len(links)} links")

# ----------------------------
# Main execution
# ----------------------------
if __name__ == "__main__":
    driver = None
    try:
        load_visited_cache()
        driver = create_driver()
        
        login_to_app(driver)
        namespaces = load_namespaces()
        visited_links = set()
        
        crawl_links(driver, namespaces, visited_links, max_depth=MAX_DEPTH, max_visits=MAX_VISITS)
        
        save_results(visited_links)
        save_visited_cache()
        
        logging.info("Crawling complete!")
        
    except KeyboardInterrupt:
        logging.info("Crawling interrupted by user")
        if 'visited_links' in locals():
            save_results(visited_links)
            save_visited_cache()
    except Exception as e:
        logging.error(f"Fatal error: {e}")
    finally:
        if driver:
            try:
                driver.quit()
                logging.info("Browser closed.")
            except Exception:
                pass
