import logging
import os
import time
import threading
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
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("selenium_crawl.log"), logging.StreamHandler()],
)

# Initialize Firefox WebDriver
firefox_options = Options()
firefox_options.add_argument("--headless")  # Run in headless mode for faster execution
webdriver_service = Service("/usr/local/bin/geckodriver")
driver = webdriver.Firefox(service=webdriver_service, options=firefox_options)

# URL and credentials
login_url = "https://app.stg.thousandeyes.com/login?teRegion=1"
USERNAME = "tester__@things.com"
PASSWORD = "lololol"

# Configurable retry count for AJAX content loads
AJAX_RETRY_COUNT = 3
AJAX_RETRY_DELAY = 2  # seconds

# Path to namespaces file
NAMESPACES_FILE = "namespaces.txt"


def load_namespaces():
    """Loads starting URLs from the namespaces file."""
    if not os.path.exists(NAMESPACES_FILE):
        logging.warning(
            f"{NAMESPACES_FILE} not found. Using only the login URL as the starting point."
        )
        return [login_url]
    with open(NAMESPACES_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]


def login_to_app():
    """Logs into the application and verifies successful login."""
    logging.info("Starting login process...")
    try:
        driver.get(login_url)

        # Step 1: Enter email
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.ID, "email"))
        )
        email_input = driver.find_element(By.ID, "email")
        email_input.clear()
        email_input.send_keys(USERNAME + Keys.RETURN)
        logging.info("Email submitted.")

        # Step 2: Enter password (new page loads dynamically)
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.ID, "password"))
        )
        password_input = driver.find_element(By.ID, "password")
        password_input.clear()
        password_input.send_keys(PASSWORD + Keys.RETURN)
        logging.info("Password submitted.")

        # Step 3: Wait for dashboard/homepage
        WebDriverWait(driver, 20).until(EC.title_contains("Dashboard"))
        logging.info("Login successful.")

    except TimeoutException:
        logging.error("Login timed out. Page structure may have changed.")
    except NoSuchElementException as e:
        logging.error(f"Error locating elements during login: {e}")


def extract_links():
    """Extracts links from the current page."""
    links = set()
    try:
        # Wait for the page to load completely
        WebDriverWait(driver, 10).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )

        # Extract anchor tags
        anchor_tags = driver.find_elements(By.TAG_NAME, "a")
        for tag in anchor_tags:
            link = tag.get_attribute("href")
            if link and link.startswith("https://app.stg.thousandeyes.com"):
                links.add(link)
                logging.info(f"Found new link: {link}")

        # Handle iframes
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        for index, iframe in enumerate(iframes):
            try:
                driver.switch_to.frame(iframe)
                logging.info(f"Switched to iframe {index + 1}")
                iframe_links = driver.find_elements(By.TAG_NAME, "a")
                for tag in iframe_links:
                    link = tag.get_attribute("href")
                    if link and link.startswith("https://app.stg.thousandeyes.com"):
                        links.add(link)
                        logging.info(f"Found link in iframe: {link}")
            except (NoSuchElementException, WebDriverException) as e:
                logging.error(f"Error accessing iframe {index + 1}: {e}")
            finally:
                driver.switch_to.default_content()
    except Exception as e:
        logging.error(f"Error extracting links: {e}")

    return links


def crawl_links(urls, visited_links):
    """Crawls the provided URLs to find links recursively."""
    for url in urls:
        if url not in visited_links:  # Avoid revisiting links
            logging.info(f"Visiting {url}")
            driver.get(url)
            time.sleep(AJAX_RETRY_DELAY)  # Allow time for AJAX content to load
            new_links = extract_links()
            visited_links.update(new_links)  # Add new links to visited set

            # Recursively crawl new links
            crawl_links(new_links, visited_links)


if __name__ == "__main__":
    try:
        login_to_app()
        namespaces = load_namespaces()  # Load namespaces as starting points
        visited_links = set()  # Set to store all visited links
        crawl_links(namespaces, visited_links)  # Start crawling from each namespace

        # Save found links to file
        with open("crawled_links.txt", "w") as f:
            for link in visited_links:
                f.write(link + "\n")
        logging.info("Crawling complete. Links saved to crawled_links.txt.")
    finally:
        driver.quit()
        logging.info("Browser closed.")
