import logging
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import time
import os,sys,re

##
##
# Set up logging to both console and file
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
    logging.FileHandler("selenium_crawl.log"),
    logging.StreamHandler()
])

# Initialize Firefox WebDriver
firefox_options = Options()
firefox_options.add_argument("--headless")  # Run in headless mode for no GUI
firefox_options.add_argument("--no-sandbox")
firefox_options.add_argument("--disable-dev-shm-usage")

# Path to geckodriver (replace with the actual path to your geckodriver)
webdriver_service = Service('/usr/local/bin/geckodriver')
driver = webdriver.Firefox(service=webdriver_service, options=firefox_options)

# URL and credentials
login_url = 'https://app.stg.things.com/login?teRegion=1'
USERNAME = 'thing@thing.org.eu'
PASSWORD = 'sxxxxxxxxxxxxx'

def login_to_app():
    logging.info("Starting login process...")
    try:
        # Navigate to login page
        driver.get(login_url)
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, 'email')))
        logging.info("Login page loaded.")

        # Find the email and password fields
        username_field = driver.find_element(By.ID, 'email')
        password_field = driver.find_element(By.ID, 'password')

        # Input the credentials
        username_field.send_keys(USERNAME)
        password_field.send_keys(PASSWORD)
        logging.info("Credentials entered.")

        # Submit the login form
        password_field.send_keys(Keys.RETURN)

        # Wait for the post-login page to load
        WebDriverWait(driver, 10).until(EC.title_contains("Dashboard"))
        logging.info("Login successful, Dashboard page loaded.")

    except TimeoutException:
        logging.error("Login timed out. Please check if the page or elements have changed.")
    except NoSuchElementException as e:
        logging.error(f"Error locating elements during login: {e}")

def crawl_links():
    logging.info("Starting link crawling process...")
    links = set()  # To track unique links
    crawl_queue = [driver.current_url]  # Start with the current URL

    while crawl_queue:
        url = crawl_queue.pop(0)
        logging.info(f"Visiting {url}")
        try:
            driver.get(url)
            WebDriverWait(driver, 10).until(lambda d: d.execute_script('return document.readyState') == 'complete')
            logging.info(f"Page loaded: {url}")

            # Extract all anchor tags and process internal links
            anchor_tags = driver.find_elements(By.TAG_NAME, 'a')

            for tag in anchor_tags:
                link = tag.get_attribute('href')
                if link and link.startswith('https://app.stg.things.com'):
                    if link not in links:
                        links.add(link)
                        crawl_queue.append(link)
                        logging.info(f"Found new link: {link}")

        except TimeoutException:
            logging.error(f"Timed out while loading {url}")
        except Exception as e:
            logging.error(f"Error while crawling {url}: {e}")

    logging.info(f"Total unique links found: {len(links)}")
    
    # Write the results to a file
    with open("crawled_links.txt", "w") as f:
        for link in links:
            f.write(link + "\n")
    logging.info("Crawling complete. Links saved to crawled_links.txt.")

if __name__ == '__main__':
    try:
        login_to_app()  # Log in to the site
        crawl_links()  # Crawl all links after login
    finally:
        driver.quit()  # Close the browser when done
        logging.info("Browser closed.")

##
##
