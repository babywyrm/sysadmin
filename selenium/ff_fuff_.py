import subprocess
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
import time

# Selenium settings
firefox_options = Options()
firefox_options.add_argument("--headless")  # Headless mode
webdriver_service = Service('/path/to/geckodriver')

# Create Firefox WebDriver instance
driver = webdriver.Firefox(service=webdriver_service, options=firefox_options)

## Login page URL
login_url = 'https://app.stg.things.com/login?teRegion=1'
##
## Credentials (replace with actual credentials)
USERNAME = 'your_username'
PASSWORD = 'your_password'

# Wordlist path for ffuf
wordlist_path = '/path/to/wordlist.txt'

# Output files
ffuf_output_file = 'ffuf_discovered_urls.txt'
crawled_output_file = 'crawled_urls.txt'

# Base URL to target with ffuf
base_url = 'https://app.stg.thousandeyes.com'

def run_ffuf():
    """
    Runs ffuf to discover hidden endpoints and saves them to a file.
    """
    print("Running ffuf to gather hidden endpoints...")

    # ffuf command with options
    ffuf_command = [
        'ffuf', '-u', f'{base_url}/FUZZ',
        '-w', wordlist_path,
        '-o', ffuf_output_file,
        '-of', 'csv'
    ]

    # Run the ffuf command
    result = subprocess.run(ffuf_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print("Error running ffuf:", result.stderr.decode())
    else:
        print("ffuf completed. Discovered URLs are stored in:", ffuf_output_file)

def get_ffuf_urls():
    """
    Parses the ffuf output file and returns a list of discovered URLs.
    """
    discovered_urls = []

    with open(ffuf_output_file, 'r') as file:
        next(file)  # Skip header
        for line in file:
            # Assuming the CSV format with the URL as the first column
            url = line.split(',')[0]
            if url:
                discovered_urls.append(url.strip())

    return discovered_urls

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

def crawl_links(starting_urls):
    """
    Crawls all the internal links from starting URLs and writes them to a file.
    """
    links = set()  # To store unique URLs
    crawl_queue = starting_urls[:]  # Initialize the crawl queue with ffuf-discovered URLs

    with open(crawled_output_file, 'w') as f:
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
    print(f"Crawled URLs written to {crawled_output_file}")

if __name__ == '__main__':
    try:
        # Step 1: Run ffuf to gather hidden endpoints
        run_ffuf()

        # Step 2: Parse ffuf output to get the discovered URLs
        ffuf_urls = get_ffuf_urls()
        print(f"Discovered {len(ffuf_urls)} URLs from ffuf")

        # Step 3: Log in to the app via Selenium
        login_to_app()

        # Step 4: Crawl all discovered links
        crawl_links(ffuf_urls)
    finally:
        # Close the browser when done
        driver.quit()

##
##
