from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
import time
import os,sys,re

##
##

# Initialize Firefox WebDriver
firefox_options = Options()
firefox_options.add_argument("--headless")  # Run in headless mode for no GUI

# Path to Geckodriver (adjust to your setup)
webdriver_service = Service('/path/to/geckodriver')

# Create a Firefox WebDriver instance
driver = webdriver.Firefox(service=webdriver_service, options=firefox_options)

# Login page URL
login_url = 'https://app.stg.things.com/login?teRegion=1'

# Credentials (replace with actual login credentials)
USERNAME = 'your_username'
PASSWORD = 'your_password'

# Output file for storing crawled URLs
output_file = 'crawled_urls.txt'

def login_to_app():
    """
    Logs into the application using provided credentials.
    """
    print("Navigating to login page...")
    driver.get(login_url)
    time.sleep(2)

    # Find username and password fields and log in
    username_field = driver.find_element(By.NAME, 'username')  # Adjust selector if needed
    password_field = driver.find_element(By.NAME, 'password')  # Adjust selector if needed

    username_field.send_keys(USERNAME)
    password_field.send_keys(PASSWORD)

    # Submit the form
    password_field.send_keys(Keys.RETURN)
    time.sleep(3)

    # Check if login was successful
    if "Dashboard" in driver.title:
        print("Login successful!")
    else:
        print("Login might have failed. Check the credentials or selectors.")

def crawl_links():
    """
    Crawls all the internal links in the application after login and writes them to a file.
    """
    links = set()  # To store unique URLs
    crawl_queue = [driver.current_url]  # Start with the current page

    with open(output_file, 'w') as f:
        while crawl_queue:
            url = crawl_queue.pop(0)
            print(f"Visiting {url}")
            driver.get(url)
            time.sleep(2)  # Wait for the page to load

            # Get all the anchor (<a>) tags (links) on the page
            anchor_tags = driver.find_elements(By.TAG_NAME, 'a')

            for tag in anchor_tags:
                link = tag.get_attribute('href')
                if link and link.startswith('https://app.stg.things.com'):
                    # Only crawl internal links
                    if link not in links:
                        links.add(link)
                        crawl_queue.append(link)  # Add new link to the queue
                        f.write(f"{link}\n")  # Write the link to the file
                        print(f"Found link: {link}")

    print(f"Total unique links found: {len(links)}")
    print(f"Crawled URLs written to {output_file}")

if __name__ == '__main__':
    try:
        login_to_app()  # Log in to the application
        crawl_links()  # Crawl all the links and write them to a file
    finally:
        driver.quit()  # Close the browser when done

##
##
