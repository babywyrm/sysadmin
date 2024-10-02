// https://gist.github.com/pragmatictesters/1af7ae02187d4661942e99a7f985da9a
//

package com.pragmatic.selenium;


import io.github.bonigarcia.wdm.WebDriverManager;
import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.ie.InternetExplorerDriver;
import org.openqa.selenium.ie.InternetExplorerOptions;
import org.openqa.selenium.opera.OperaDriver;
import org.openqa.selenium.opera.OperaOptions;
import org.openqa.selenium.safari.SafariDriver;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;


/**
 * This class demonstrate running tests against web browsers
 * <p>
 * Notes :
 * Switching between the browsers could be transferred to a Base Class.
 * Please refer to https://git.io/fhqYE  for more concise version
 */
public class CrossBrowserTest {


    private static final String BASE_URL = "http://hrm.pragmatictestlabs.com";
    private static final String USERNAME = "Admin";
    private static final String PASSWORD = "Ptl@#321";
    private static final String WELCOME_MESSAGE = "Welcome Admin";
    private static final int TIMEOUT = 30;

    /**
     * This method demonstrate launching Firefox web browser
     */
    @Test
    public void openFirefox() {
        WebDriverManager.firefoxdriver().setup();
        WebDriver driver = new FirefoxDriver();

        //Set the implicit wait
        driver.manage().timeouts().implicitlyWait(TIMEOUT, TimeUnit.SECONDS);

        driver.manage().window().maximize();
        driver.navigate().to(BASE_URL);

        driver.findElement(By.name("txtUsername")).sendKeys(USERNAME);
        driver.findElement(By.name("txtPassword")).sendKeys(PASSWORD);
        driver.findElement(By.name("txtPassword")).sendKeys(Keys.RETURN);

        String welcomeMessage = driver.findElement(By.id("welcome")).getText();

        Assert.assertEquals(welcomeMessage, WELCOME_MESSAGE, "Welcome message is incorrect ");
        driver.quit();
    }


    /**
     * Demonstrate launching Google Chrome web browser
     */
    @Test
    public void openChrome() {
        WebDriverManager.chromedriver().setup();


        //Launching an instance of Google Chrome
        WebDriver driver = new ChromeDriver();

        //Set the implicit wait
        driver.manage().timeouts().implicitlyWait(TIMEOUT, TimeUnit.SECONDS);

        driver.manage().window().maximize();
        driver.navigate().to(BASE_URL);

        driver.findElement(By.name("txtUsername")).sendKeys(USERNAME);
        driver.findElement(By.name("txtPassword")).sendKeys(PASSWORD);
        driver.findElement(By.name("txtPassword")).sendKeys(Keys.RETURN);

        String welcomeMessage = driver.findElement(By.id("welcome")).getText();

        Assert.assertEquals(welcomeMessage, WELCOME_MESSAGE, "Welcome message is incorrect ");
        driver.quit();
    }


    /**
     * This method demonstrate launching Chrome headless mode
     * You can create an instance of ChromeOptions,
     * which has convenient methods for setting ChromeDriver-specific capabilities.
     * You can then pass the ChromeOptions object into the ChromeDriver constructor:
     * Please refer to http://chromedriver.chromium.org/capabilities
     */
    @Test
    public void openChromeHeadless() {
        WebDriverManager.chromedriver().setup();

        //Following Chrome option shuld be set for switching to headless mode
        ChromeOptions options = new ChromeOptions();
        options.setHeadless(true);
        //options.addArguments("headless");

        //Creating an instance of the Chrome Driver with Chrome Options passed to the constructor
        WebDriver driver = new ChromeDriver(options);

        //Set the implicit wait
        driver.manage().timeouts().implicitlyWait(TIMEOUT, TimeUnit.SECONDS);

        driver.manage().window().maximize();
        driver.navigate().to(BASE_URL);

        driver.findElement(By.name("txtUsername")).sendKeys(USERNAME);
        driver.findElement(By.name("txtPassword")).sendKeys(PASSWORD);
        driver.findElement(By.name("txtPassword")).sendKeys(Keys.RETURN);

        String welcomeMessage = driver.findElement(By.id("welcome")).getText();

        Assert.assertEquals(welcomeMessage, WELCOME_MESSAGE, "Welcome message is incorrect ");
        driver.quit();
    }


    /**
     * This method demonstrate launching Firefox headless mode
     */
    @Test
    public void openFirefoxHeadless() {
        WebDriverManager.firefoxdriver().setup();

        //Additional statements to configure headless
        FirefoxOptions options = new FirefoxOptions();
        options.setHeadless(true);

        //Ensure options is passed as a parameter to the constructor
        WebDriver driver = new FirefoxDriver(options);

        //Set the implicit wait
        driver.manage().timeouts().implicitlyWait(TIMEOUT, TimeUnit.SECONDS);

        driver.manage().window().maximize();
        driver.navigate().to(BASE_URL);

        driver.findElement(By.name("txtUsername")).sendKeys(USERNAME);
        driver.findElement(By.name("txtPassword")).sendKeys(PASSWORD);
        driver.findElement(By.name("txtPassword")).sendKeys(Keys.RETURN);

        String welcomeMessage = driver.findElement(By.id("welcome")).getText();

        Assert.assertEquals(welcomeMessage, WELCOME_MESSAGE, "Welcome message is incorrect ");
        driver.quit();
    }


    /**
     * Demonstrate launching Safari web browser
     * <p>
     * Note :
     * Browser driver configuration is not required as browser has the driver inbuilt
     */
    @Test
    public void openSafari() {

        //Browser driver is not required

        //Launch safari browser
        WebDriver driver = new SafariDriver();

        //Set the implicit wait
        driver.manage().timeouts().implicitlyWait(TIMEOUT, TimeUnit.SECONDS);

        driver.manage().window().maximize();
        driver.navigate().to(BASE_URL);

        driver.findElement(By.name("txtUsername")).sendKeys(USERNAME);
        driver.findElement(By.name("txtPassword")).sendKeys(PASSWORD);
        driver.findElement(By.name("txtPassword")).sendKeys(Keys.RETURN);

        String welcomeMessage = driver.findElement(By.id("welcome")).getText();

        Assert.assertEquals(welcomeMessage, WELCOME_MESSAGE, "Welcome message is incorrect ");
        driver.quit();

    }


    /**
     * Demonstrates launching Internet Explorer
     */

    @Test
    public void openIE() {

        WebDriverManager.iedriver().setup();

        InternetExplorerOptions options = new InternetExplorerOptions();
        options.ignoreZoomSettings(); //Ignoring the Zoom level setting 
        options.introduceFlakinessByIgnoringSecurityDomains(); //Ignoring the Security domains settings 
        options.disableNativeEvents(); //Disabling the NATIVE_EVENTS capability to ensure the typing speed with 64bit driver 
        //Launch IE browser
        WebDriver driver = new InternetExplorerDriver(options);

        //Set the implicit wait
        driver.manage().timeouts().implicitlyWait(TIMEOUT, TimeUnit.SECONDS);

        driver.manage().window().maximize();
        driver.navigate().to(BASE_URL);

        driver.findElement(By.name("txtUsername")).sendKeys(USERNAME);
        driver.findElement(By.name("txtPassword")).sendKeys(PASSWORD);
        driver.findElement(By.name("txtPassword")).sendKeys(Keys.RETURN);

        String welcomeMessage = driver.findElement(By.id("welcome")).getText();

        Assert.assertEquals(welcomeMessage, WELCOME_MESSAGE, "Welcome message is incorrect ");
        driver.quit();
    }


    /**
     * Demonstrate launching Edge web browser
     */
    @Test
    public void openEdge() {

        //WebDriverManager.iedriver().setup(); This will download the 64bit driver
        WebDriverManager.edgedriver().setup();

        //Launch Edge browser
        WebDriver driver = new EdgeDriver();

        //Set the implicit wait
        driver.manage().timeouts().implicitlyWait(TIMEOUT, TimeUnit.SECONDS);

        driver.manage().window().maximize();
        driver.navigate().to(BASE_URL);

        driver.findElement(By.name("txtUsername")).sendKeys(USERNAME);
        driver.findElement(By.name("txtPassword")).sendKeys(PASSWORD);
        driver.findElement(By.name("txtPassword")).sendKeys(Keys.RETURN);

        String welcomeMessage = driver.findElement(By.id("welcome")).getText();

        Assert.assertEquals(welcomeMessage, WELCOME_MESSAGE, "Welcome message is incorrect ");
        driver.quit();

    }


    /**
     * Demonstrate launching Opera web browser
     */
    @Test
    public void openOpera() {

        WebDriverManager.operadriver().setup();

        //Opera specific settings 
        OperaOptions operaOptions = new OperaOptions();
        operaOptions.setBinary("/Applications/Opera.app/Contents/MacOS/Opera");

        //Launch Opera browser
        WebDriver driver = new OperaDriver();

        //Set the implicit wait
        driver.manage().timeouts().implicitlyWait(TIMEOUT, TimeUnit.SECONDS);

        driver.manage().window().maximize();
        driver.navigate().to(BASE_URL);

        driver.findElement(By.name("txtUsername")).sendKeys(USERNAME);
        driver.findElement(By.name("txtPassword")).sendKeys(PASSWORD);
        driver.findElement(By.name("txtPassword")).sendKeys(Keys.RETURN);

        String welcomeMessage = driver.findElement(By.id("welcome")).getText();

        Assert.assertEquals(welcomeMessage, WELCOME_MESSAGE, "Welcome message is incorrect ");
        driver.quit();

    }


    @Test
    public void mobileEmulation() {

        WebDriverManager.chromedriver().setup();

        Map<String, String> mobileEmulation = new HashMap<>();
        mobileEmulation.put("deviceName", "iPhone 4");

        ChromeOptions chromeOptions = new ChromeOptions();
        chromeOptions.setExperimentalOption("mobileEmulation", mobileEmulation);
        WebDriver driver = new ChromeDriver(chromeOptions);


        //Set the implicit wait
        driver.manage().timeouts().implicitlyWait(TIMEOUT, TimeUnit.SECONDS);

        driver.manage().window().maximize();
        driver.navigate().to(BASE_URL);

        driver.findElement(By.name("txtUsername")).sendKeys(USERNAME);
        driver.findElement(By.name("txtPassword")).sendKeys(PASSWORD);
        driver.findElement(By.name("txtPassword")).sendKeys(Keys.RETURN);

        String welcomeMessage = driver.findElement(By.id("welcome")).getText();

        Assert.assertEquals(welcomeMessage, WELCOME_MESSAGE, "Welcome message is incorrect ");
        driver.quit();
    }


}
