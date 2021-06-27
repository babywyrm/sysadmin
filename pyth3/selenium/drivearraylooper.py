# Import unittest module for creating unit tests
import unittest

# Import time module to implement 
import time

# Import the Selenium 2 module (aka "webdriver")
from selenium import webdriver

# For automating data input
from selenium.webdriver.common.keys import Keys

# For providing custom configurations for Chrome to run
from selenium.webdriver.chrome.options import Options

# Define array to hold all drivers
driver_array = []



# --------------------------------------
# Provide a class for the unit test case
class PythonOrgSearchChrome(unittest.TestCase):

	# Anything declared in setUp will be executed for all test cases
	def setUp(self):
		
		# Define a variable to hold all the chrome_options we want to configure in the driver
		chrome_options = webdriver.ChromeOptions()
		#chrome_options.add_argument("--start-maximised")

		# Define and append each driver to the driver_array array. You can create as many as you want, and you can create multiple Chrome instances with different options
		driver_array.append(webdriver.Chrome(executable_path='/Library/Python/2.7/site-packages/selenium/webdriver/chrome/chromedriver', chrome_options=chrome_options))
		driver_array.append(webdriver.Firefox())

	# An individual test case. Must start with 'test_' (as per unittest module)
	def test_search_in_python_chrome(self):
		
		# Loop through each driver in the array
		for driver_instance in driver_array:
			
			# Window management hacks because I'm using OS X. On Windows or Linux you could just specify these as a ChromeOption
			driver_instance.set_window_size(1920, 1080)
			driver_instance.maximize_window()
			
			# Go to google.com
			driver_instance.get('http://www.google.com')
			
			# A test to ensure the page has keyword Google in the page title
			self.assertIn("Google", driver_instance.title)

			# Pauses the screen for 1 seconds so we have time to confirm it arrived at the right page
			time.sleep(1) 

			# Find and select the search box element on the page
			search_box = driver_instance.find_element_by_name('q')

			# Enter text into the search box
			search_box.send_keys('Devin Mancuso')

			# Make sure the results page returned something
			assert "No results found." not in driver_instance.page_source

			# Submit the search box form
			search_box.submit() 

			# Another pause so we can see what's going on
			time.sleep(1)
			
			# Close the browser. 
			# Note close() will close the current tab, if its the last tab it will close the browser. To close the browser entirely use quit()
			driver_instance.close()

	# Anything declared in tearDown will be executed for all test cases
	#def tearDown(self):


# Boilerplate code to start the unit tests
if __name__ == "__main__":
	unittest.main()		
