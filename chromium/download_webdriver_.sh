Download chrome webdriver from

https://chromedriver.chromium.org/downloads
Make sure driver version match your chrome browser version

Open folder where chrome driver downloaded and open terminal & run one by one

#
###########
###########
#

sudo chmod +x chromedriver

sudo mv chromedriver /usr/local/share/chromedriver

sudo ln -s /usr/local/share/chromedriver /usr/bin/chromedriver

chromedriver --version

If output looks like something 👇🏻

    ChromeDriver 91.0.4472.19 (1bf021f248676a0b2ab3ee0561d83a59e424c23e-refs/branch-heads/4472@{#288})

Its ready to go

Open any py file where you write program

from selenium import webdriver

Please make sure you install selenium

pip3 install selenium

driver_location = '/usr/bin/chromedriver'
binary_location = '/usr/bin/google-chrome'

options = webdriver.ChromeOptions()
options.binary_location = binary_location

driver = webdriver.Chrome(executable_path=driver_location,options=options)
driver.get("https://www.youtube.com/watch?v=67h3IT2lm40")

Run this py file

#
###
###
#

🌟 Voila its work
