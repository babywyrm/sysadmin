##
##

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import time
import os,sys,re

# Initialize Chrome WebDriver
chrome_options = Options()
chrome_options.add_argument("--headless")  # Run in headless mode for no GUI
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")

# Replace this path with the actual path to your chromedriver
webdriver_service = Service('/Users/THING/SELENIUM/chromedriver')

driver = webdriver.Chrome(service=webdriver_service, options=chrome_options)

# Login page URL
login_url = 'https://app.stg.things.com/login?teRegion=1'

# Credentials (replace with actual login credentials)
USERNAME = 'your_username'
PASSWORD = 'your_password'

def login_to_app():
    # Navigate to login page
    driver.get(login_url)
    
    # Allow page to load
    time.sleep(2)

    # Find username and password fields and log in
    username_field = driver.find_element(By.NAME, 'username')  # Adjust if 'name' is different
    password_field = driver.find_element(By.NAME, 'password')  # Adjust if 'name' is different
    
    username_field.send_keys(USERNAME)
    password_field.send_keys(PASSWORD)
    
    # Submit the login form (adjust selector based on actual form structure)
    password_field.send_keys(Keys.RETURN)
    
    # Allow time for login
    time.sleep(3)

    # Check for successful login by finding a post-login element
    # This could be adjusted based on what appears after login
    if "Dashboard" in driver.title:
        print("Login successful!")
    else:
        print("Login might have failed. Check the credentials or selectors.")

def crawl_links():
    # Find all anchor tags after login
    links = set()  # Use a set to avoid duplicates
    crawl_queue = [driver.current_url]  # Start with the current page

    while crawl_queue:
        url = crawl_queue.pop(0)
        driver.get(url)
        time.sleep(2)  # Wait for the page to load

        # Get all the <a> tags (hyperlinks) on the page
        anchor_tags = driver.find_elements(By.TAG_NAME, 'a')

        for tag in anchor_tags:
            link = tag.get_attribute('href')
            if link and link.startswith('https://app.stg.things.com'):
                # Ensure we only crawl internal links
                if link not in links:
                    links.add(link)
                    crawl_queue.append(link)  # Add new links to the queue
                    print(f"Found link: {link}")

    print(f"Total unique links found: {len(links)}")

if __name__ == '__main__':
    try:
        login_to_app()  # Log in to the site
        crawl_links()  # Crawl all links after login
    finally:
        driver.quit()  # Close the browser when done

##
##
