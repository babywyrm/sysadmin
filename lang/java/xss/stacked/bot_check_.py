#!/usr/bin/python3

## stacked_htb
## webdriver_thing
##
##

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException
import MySQLdb
import time
import os
ops = FirefoxOptions()
ops.add_argument('--headless')
profile = FirefoxProfile()
#profile.set_preference('browser.cache.disk.enable', False)
#profile.set_preference('browser.cache.memory.enable', False)
#profile.set_preference('browser.cache.offline.enable', False)
#profile.set_preference('network.cookie.cookieBehavior', 2)
#profile.set_preference("http.response.timeout", 5)
#profile.set_preference("dom.max_script_run_time", 5)
driver = webdriver.Firefox(executable_path=r'/home/adam/selenium/geckodriver',options=ops,firefox_profile=profile)
#driver.set_page_load_timeout(20)
db = MySQLdb.connect("localhost", "adam", "ReallyStrongSQLPassword@2021", "contact")

def main():
    c = db.cursor()
    c.execute("select * from messages where id > 1;")
    res = c.fetchall()
    print("STARTING")
    if res:
        for row in res:
            try:
                id = row[0]
                print(f"trying {id}")
                if id:
                    driver.get(f"http://mail.stacked.htb/read-mail.php?id={id}")
                    htmlSource = driver.page_source
                    time.sleep(5)
                else:
                    print(f"Cannot access mail for {id}")
            except:
                print(f"Cannot access for {id}")
                pass
            time.sleep(2)
        c.execute("truncate messages;")
        c.execute("insert into messages (fullname, email, subject, message, reg_date) values ('Jeremy Taint','jtaint@stacked.htb','S3 Instance Started','Hey Adam, I have set up S3 instance on s3-testing.stacked.htb so that you can configure the IAM users, roles and permissions. I have initialized a serverless instance for you to work from but keep in mind for the time being you can only run node instances. If you need anything let me know. Thanks.','2021-06-25 08:30:00');")
        db.commit()
        c.close()
        db.close()
    else:
        print("no mail")
    driver.close()
    os.system("sh -c /home/adam/selenium/delete_lambda.sh")
    exit()

if __name__ == "__main__":
    main()

##
##
##
