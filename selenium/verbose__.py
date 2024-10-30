import logging
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
    logging.FileHandler("selenium_crawl.log"),
    logging.StreamHandler()
])

# Initialize Firefox WebDriver
firefox_options = Options()
firefox_options.add_argument("--headless")
webdriver_service = Service('/usr/local/bin/geckodriver')
driver = webdriver.Firefox(service=webdriver_service, options=firefox_options)

# URL and credentials
login_url = 'https://app.aux.thing.com/login?Region=1'
USERNAME = 'person+tester@aces.org.au'
PASSWORD = 'ahignsfiznzxxxxxxx'

##
##

# Configurable retry count for AJAX content loads
AJAX_RETRY_COUNT = 3
AJAX_RETRY_DELAY = 2  # seconds

def login_to_app():
    logging.info("Starting login process...")
    try:
        driver.get(login_url)
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, 'email')))
        
        username_field = driver.find_element(By.ID, 'email')
        password_field = driver.find_element(By.ID, 'password')
        
        username_field.send_keys(USERNAME)
        password_field.send_keys(PASSWORD)
        password_field.send_keys(Keys.RETURN)
        
        WebDriverWait(driver, 10).until(EC.title_contains("Dashboard"))
        logging.info("Login successful.")
    except TimeoutException:
        logging.error("Login timed out.")
    except NoSuchElementException as e:
        logging.error(f"Error locating elements during login: {e}")

def crawl_links():
    logging.info("Starting link crawling...")
    links = set()
    crawl_queue = [driver.current_url]

    while crawl_queue:
        url = crawl_queue.pop(0)
        logging.info(f"Visiting {url}")
        
        try:
            driver.get(url)
            WebDriverWait(driver, 10).until(lambda d: d.execute_script('return document.readyState') == 'complete')

            for _ in range(AJAX_RETRY_COUNT):
                anchor_tags = driver.find_elements(By.TAG_NAME, 'a')
                
                for tag in anchor_tags:
                    link = tag.get_attribute('href')
                    if link and link.startswith('https://app.stg.thousandeyes.com') and link not in links:
                        links.add(link)
                        crawl_queue.append(link)
                        logging.info(f"Found new link: {link}")
                
                time.sleep(AJAX_RETRY_DELAY)

            iframes = driver.find_elements(By.TAG_NAME, 'iframe')
            
            for index, iframe in enumerate(iframes):
                try:
                    driver.switch_to.frame(iframe)
                    logging.info(f"Switched to iframe {index + 1}")
                    
                    iframe_links = driver.find_elements(By.TAG_NAME, 'a')
                    
                    for tag in iframe_links:
                        link = tag.get_attribute('href')
                        if link and link.startswith('https://app.stg.thousandeyes.com') and link not in links:
                            links.add(link)
                            crawl_queue.append(link)
                            logging.info(f"Found link in iframe: {link}")
                except (NoSuchElementException, WebDriverException) as e:
                    logging.error(f"Error accessing iframe {index + 1}: {e}")
                finally:
                    driver.switch_to.default_content()

        except TimeoutException:
            logging.error(f"Timed out while loading {url}")
        except Exception as e:
            logging.error(f"Error while crawling {url}: {e}")

    logging.info(f"Total unique links found: {len(links)}")

    with open("crawled_links.txt", "w") as f:
        for link in links:
            f.write(link + "\n")
    logging.info("Crawling complete. Links saved to crawled_links.txt.")

if __name__ == '__main__':
    try:
        login_to_app()
        crawl_links()
    finally:
        driver.quit()
        logging.info("Browser closed.")

##
##
