import org.openqa.selenium.By
import org.openqa.selenium.Keys
import org.openqa.selenium.TimeoutException
import org.openqa.selenium.NoSuchElementException
import org.openqa.selenium.WebDriver
import org.openqa.selenium.firefox.FirefoxDriver
import org.openqa.selenium.firefox.FirefoxOptions
import org.openqa.selenium.firefox.FirefoxService
import org.openqa.selenium.WebElement
import org.openqa.selenium.support.ui.ExpectedConditions
import org.openqa.selenium.support.ui.WebDriverWait

import java.util.logging.Logger
import java.time.Duration

// Setup logger for both console and file logging
Logger logger = Logger.getLogger("SeleniumCrawlLogger")

// Path to geckodriver (replace this with your geckodriver path)
def geckodriverPath = '/usr/local/bin/geckodriver'

// Firefox options to run in headless mode
FirefoxOptions options = new FirefoxOptions()
options.addArguments("--headless")
options.addArguments("--no-sandbox")
options.addArguments("--disable-dev-shm-usage")

// Initialize the Firefox WebDriver with the appropriate service
FirefoxService service = new FirefoxService(new File(geckodriverPath))
WebDriver driver = new FirefoxDriver(service, options)

// URL and credentials for login
def loginUrl = 'https://app.stg.things.com/login?teRegion=1'
def USERNAME = 'yoyo+tester@things.com'
def PASSWORD = 'ZZZZrasfasdfes=asfasdfasdf'

// Login to the application
void loginToApp(WebDriver driver) {
    logger.info("Starting login process...")
    try {
        // Navigate to the login page
        driver.get(loginUrl)
        
        // Wait for the login page to load and find the email input field
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10))
        WebElement emailField = wait.until(ExpectedConditions.presenceOfElementLocated(By.id("email")))
        logger.info("Login page loaded.")
        
        // Find the password field and input the credentials
        WebElement passwordField = driver.findElement(By.id("password"))
        emailField.sendKeys(USERNAME)
        passwordField.sendKeys(PASSWORD)
        logger.info("Credentials entered.")

        // Submit the login form
        passwordField.sendKeys(Keys.RETURN)

        // Wait for the post-login page to load (assuming "Dashboard" appears in the title)
        wait.until(ExpectedConditions.titleContains("Dashboard"))
        logger.info("Login successful, Dashboard page loaded.")
        
    } catch (TimeoutException e) {
        logger.severe("Login timed out. Please check if the page or elements have changed.")
    } catch (NoSuchElementException e) {
        logger.severe("Error locating elements during login: ${e.getMessage()}")
    }
}

// Crawl and collect links
void crawlLinks(WebDriver driver) {
    logger.info("Starting link crawling process...")
    
    Set<String> links = new HashSet<>()
    List<String> crawlQueue = new ArrayList<>()
    crawlQueue.add(driver.getCurrentUrl()) // Start with the current URL
    
    while (!crawlQueue.isEmpty()) {
        def url = crawlQueue.remove(0)
        logger.info("Visiting: ${url}")
        try {
            driver.get(url)
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10))
            wait.until { driver.executeScript("return document.readyState") == "complete" }
            logger.info("Page loaded: ${url}")
            
            // Get all anchor tags and process internal links
            List<WebElement> anchorTags = driver.findElements(By.tagName("a"))
            anchorTags.each { tag ->
                def link = tag.getAttribute("href")
                if (link != null && link.startsWith("https://app.stg.things.com") && !links.contains(link)) {
                    links.add(link)
                    crawlQueue.add(link)
                    logger.info("Found new link: ${link}")
                }
            }
        } catch (TimeoutException e) {
            logger.severe("Timed out while loading: ${url}")
        } catch (Exception e) {
            logger.severe("Error while crawling ${url}: ${e.getMessage()}")
        }
    }
    
    logger.info("Total unique links found: ${links.size()}")
    
    // Save the crawled links to a file
    File file = new File("crawled_links.txt")
    file.withWriter { writer ->
        links.each { writer.writeLine(it) }
    }
    logger.info("Crawling complete. Links saved to crawled_links.txt.")
}

// Main execution block
try {
    loginToApp(driver) // Log into the application
    crawlLinks(driver) // Start crawling links after successful login
} finally {
    driver.quit() // Close the browser when done
    logger.info("Browser closed.")
}

//
//
