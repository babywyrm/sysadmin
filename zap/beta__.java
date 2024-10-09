import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.firefox.FirefoxService;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.util.logging.Logger;
import java.time.Duration;
import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

// Main class
public class Yoyo {
    
    public static void main(String[] args) {
        // Setup logger for both console and file logging
        Logger logger = Logger.getLogger("SeleniumCrawlLogger");

        // Path to geckodriver (replace this with your geckodriver path)
        String geckodriverPath = "/usr/local/bin/geckodriver";

        // Firefox options to run in headless mode
        FirefoxOptions options = new FirefoxOptions();
        options.addArguments("--headless");
        options.addArguments("--no-sandbox");
        options.addArguments("--disable-dev-shm-usage");

        // Initialize the Firefox WebDriver with the appropriate service
        FirefoxService service = new FirefoxService(new File(geckodriverPath));
        WebDriver driver = new FirefoxDriver(service, options);

        // Argument handling: targetUrl, username, password, and additionalUrls
        String targetUrl = args.length > 0 ? args[0] : "https://app.stg.yoyoyo.com/login?teRegion=1"; // Default target URL
        String USERNAME = args.length > 1 ? args[1] : "default_user@example.com"; // Default username
        String PASSWORD = args.length > 2 ? args[2] : "default_password"; // Default password
        List<String> additionalUrls = new ArrayList<>(); // Custom list of target URLs (optional)

        for (int i = 3; i < args.length; i++) {
            additionalUrls.add(args[i]);
        }

        try {
            loginToApp(driver, targetUrl, USERNAME, PASSWORD, logger); // Log into the application
            crawlLinks(driver, additionalUrls, logger); // Start crawling links after successful login
        } finally {
            driver.quit(); // Close the browser when done
            logger.info("Browser closed.");
        }
    }

    // Login to the application
    public static void loginToApp(WebDriver driver, String targetUrl, String username, String password, Logger logger) {
        logger.info("Starting login process...");
        try {
            // Navigate to the login page
            driver.get(targetUrl);

            // Wait for the login page to load and find the email input field
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
            WebElement emailField = wait.until(ExpectedConditions.presenceOfElementLocated(By.id("email")));
            logger.info("Login page loaded.");

            // Find the password field and input the credentials
            WebElement passwordField = driver.findElement(By.id("password"));
            emailField.sendKeys(username);
            passwordField.sendKeys(password);
            logger.info("Credentials entered.");

            // Submit the login form
            passwordField.sendKeys(Keys.RETURN);

            // Wait for the post-login page to load (assuming "Dashboard" appears in the title)
            wait.until(ExpectedConditions.titleContains("Dashboard"));
            logger.info("Login successful, Dashboard page loaded.");

        } catch (TimeoutException e) {
            logger.severe("Login timed out. Please check if the page or elements have changed.");
        } catch (NoSuchElementException e) {
            logger.severe("Error locating elements during login: " + e.getMessage());
        }
    }

    // Crawl and collect links
    public static void crawlLinks(WebDriver driver, List<String> additionalUrls, Logger logger) {
        logger.info("Starting link crawling process...");

        Set<String> links = new HashSet<>();
        List<String> crawlQueue = new ArrayList<>();
        crawlQueue.add(driver.getCurrentUrl()); // Start with the current URL

        // Add additional URLs to the crawl queue
        if (additionalUrls != null && !additionalUrls.isEmpty()) {
            logger.info("Adding custom URLs to crawl queue...");
            crawlQueue.addAll(additionalUrls);
            additionalUrls.forEach(url -> logger.info("Added custom URL: " + url));
        }

        while (!crawlQueue.isEmpty()) {
            String url = crawlQueue.remove(0);
            logger.info("Visiting: " + url);
            try {
                driver.get(url);
                WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
                wait.until(webDriver -> ((String) ((org.openqa.selenium.JavascriptExecutor) driver).executeScript("return document.readyState")).equals("complete"));
                logger.info("Page loaded: " + url);

                // Get all anchor tags and process internal links
                List<WebElement> anchorTags = driver.findElements(By.tagName("a"));
                for (WebElement tag : anchorTags) {
                    String link = tag.getAttribute("href");
                    if (link != null && link.startsWith("https://app.stg.yoyoyo.com") && !links.contains(link)) {
                        links.add(link);
                        crawlQueue.add(link);
                        logger.info("Found new link: " + link);
                    }
                }
            } catch (TimeoutException e) {
                logger.severe("Timed out while loading: " + url);
            } catch (Exception e) {
                logger.severe("Error while crawling " + url + ": " + e.getMessage());
            }
        }

        logger.info("Total unique links found: " + links.size());

        // Save the crawled links to a file
        try {
            java.nio.file.Files.write(java.nio.file.Paths.get("crawled_links.txt"), links);
            logger.info("Crawling complete. Links saved to crawled_links.txt.");
        } catch (java.io.IOException e) {
            logger.severe("Error writing links to file: " + e.getMessage());
        }
    }
}
