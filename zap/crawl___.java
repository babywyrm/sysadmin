/*
 * Yoyo.java — Secure Selenium + HttpClient Hybrid Crawler ..beta..
 * --------------------------------------------------------
 * Modern 2025 version with:
 *  • Selenium login (headless)
 *  • Cookie transfer to HttpClient for authenticated crawling
 *  • Concurrency with bounded depth
 *  • JSON and CSV reporting
 *  • Strong typing, safe collections, and clear logging
 */

import org.openqa.selenium.*;
import org.openqa.selenium.firefox.*;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

public final class Yoyo {

    private static final Logger logger = Logger.getLogger(Yoyo.class.getName());
    private static final Duration DEFAULT_WAIT = Duration.ofSeconds(10);
    private static final String BASE_DOMAIN = "https://app.stg.yoyoyo.com";
    private static final int MAX_THREADS = 6;
    private static final int DEFAULT_DEPTH = 2;

    private Yoyo() {} // utility class

    public static void main(String[] args) {
        setupLogging();

        String geckodriverPath = System.getenv().getOrDefault("GECKODRIVER_PATH", "/usr/local/bin/geckodriver");
        String targetUrl = args.length > 0 ? args[0] : BASE_DOMAIN + "/login?teRegion=1";
        String username = args.length > 1 ? args[1] : "default_user@example.com";
        String password = args.length > 2 ? args[2] : "default_password";
        int maxDepth = args.length > 3 ? Integer.parseInt(args[3]) : DEFAULT_DEPTH;

        FirefoxOptions options = new FirefoxOptions()
                .addArguments("--headless", "--no-sandbox", "--disable-dev-shm-usage");

        FirefoxService service = new FirefoxService(new File(geckodriverPath));

        try (WebDriver driver = new FirefoxDriver(service, options)) {
            login(driver, targetUrl, username, password);

            List<String> startLinks = extractLinks(driver);
            logger.info("Initial links collected: " + startLinks.size());

            HttpClient client = buildAuthenticatedHttpClient(driver);
            List<CrawlResult> results = crawl(startLinks, client, maxDepth);

            writeReports(results);
            summarize(results);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Fatal error", e);
        }

        logger.info("Crawler finished.");
    }

    /** Perform login using Selenium. */
    private static void login(WebDriver driver, String targetUrl, String username, String password) {
        logger.info("Navigating to login page: " + targetUrl);
        driver.get(targetUrl);

        WebDriverWait wait = new WebDriverWait(driver, DEFAULT_WAIT);
        try {
            WebElement email = wait.until(ExpectedConditions.presenceOfElementLocated(By.id("email")));
            WebElement pass = driver.findElement(By.id("password"));
            email.sendKeys(username);
            pass.sendKeys(password, Keys.RETURN);
            wait.until(ExpectedConditions.titleContains("Dashboard"));
            logger.info("Login successful.");
        } catch (Exception e) {
            throw new IllegalStateException("Login failed", e);
        }
    }

    /** Extract anchor hrefs from the current Selenium DOM. */
    private static List<String> extractLinks(WebDriver driver) {
        return driver.findElements(By.tagName("a")).stream()
                .map(e -> e.getAttribute("href"))
                .filter(Objects::nonNull)
                .filter(h -> h.startsWith(BASE_DOMAIN))
                .distinct()
                .collect(Collectors.toList());
    }

    /** Build an HttpClient carrying cookies from the Selenium session. */
    private static HttpClient buildAuthenticatedHttpClient(WebDriver driver) {
        CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        Set<org.openqa.selenium.Cookie> seleniumCookies = driver.manage().getCookies();

        for (org.openqa.selenium.Cookie c : seleniumCookies) {
            HttpCookie httpCookie = new HttpCookie(c.getName(), c.getValue());
            httpCookie.setDomain(c.getDomain() != null ? c.getDomain() : URI.create(BASE_DOMAIN).getHost());
            httpCookie.setPath(Optional.ofNullable(c.getPath()).orElse("/"));
            httpCookie.setSecure(c.isSecure());
            cookieManager.getCookieStore().add(URI.create(BASE_DOMAIN), httpCookie);
        }

        logger.info("Transferred " + seleniumCookies.size() + " cookies to HttpClient.");
        return HttpClient.newBuilder()
                .cookieHandler(cookieManager)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    /** Crawl links concurrently using HttpClient with cookie auth. */
    private static List<CrawlResult> crawl(List<String> initial, HttpClient client, int maxDepth)
            throws InterruptedException {

        ExecutorService pool = Executors.newFixedThreadPool(MAX_THREADS);
        Set<String> visited = ConcurrentHashMap.newKeySet();
        List<CrawlResult> results = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger active = new AtomicInteger();

        Deque<CrawlTask> queue = new ArrayDeque<>();
        initial.forEach(u -> queue.add(new CrawlTask(u, 0)));

        while (!queue.isEmpty()) {
            CrawlTask task = queue.poll();
            if (task.depth > maxDepth || !visited.add(task.url)) continue;

            active.incrementAndGet();
            pool.submit(() -> {
                Instant start = Instant.now();
                try {
                    HttpRequest req = HttpRequest.newBuilder(URI.create(task.url))
                            .timeout(Duration.ofSeconds(20))
                            .GET()
                            .build();
                    HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
                    Duration elapsed = Duration.between(start, Instant.now());
                    results.add(new CrawlResult(task.url, resp.statusCode(), elapsed.toMillis(), task.depth, null));

                    if (resp.statusCode() == 200 && task.depth < maxDepth) {
                        extractLinksFromHtml(resp.body()).stream()
                                .filter(l -> l.startsWith(BASE_DOMAIN))
                                .filter(l -> !visited.contains(l))
                                .forEach(l -> queue.add(new CrawlTask(l, task.depth + 1)));
                    }
                } catch (Exception e) {
                    results.add(new CrawlResult(task.url, 0, 0, task.depth, e.getMessage()));
                } finally {
                    active.decrementAndGet();
                }
            });
        }

        pool.shutdown();
        pool.awaitTermination(15, TimeUnit.MINUTES);
        return results;
    }

    /** Extract hrefs from raw HTML using regex. */
    private static Set<String> extractLinksFromHtml(String html) {
        Set<String> out = new HashSet<>();
        var matcher = Pattern.compile("href=[\"'](https?://[^\"'>\\s]+)[\"']", Pattern.CASE_INSENSITIVE)
                .matcher(html);
        while (matcher.find()) out.add(matcher.group(1));
        return out;
    }

    /** Write JSON and CSV reports. */
    private static void writeReports(List<CrawlResult> results) {
        Path jsonPath = Paths.get("crawled_links.json");
        Path csvPath = Paths.get("crawled_links.csv");

        try {
            ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            mapper.writeValue(jsonPath.toFile(), results);

            try (BufferedWriter w = Files.newBufferedWriter(csvPath, StandardCharsets.UTF_8)) {
                w.write("URL,Status,ResponseTimeMs,Depth,Error\n");
                for (CrawlResult r : results) {
                    w.write(String.format("%s,%d,%d,%d,%s%n",
                            r.url, r.status, r.responseTimeMs, r.depth,
                            r.error == null ? "" : r.error.replace(',', ' ')));
                }
            }
            logger.info("Reports saved: " + jsonPath + " and " + csvPath);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Report generation failed", e);
        }
    }

    /** Print concise summary metrics. */
    private static void summarize(List<CrawlResult> results) {
        long total = results.size();
        long ok = results.stream().filter(r -> r.status == 200).count();
        long fail = results.stream().filter(r -> r.status != 200).count();
        double avg = results.stream().mapToLong(r -> r.responseTimeMs).average().orElse(0.0);

        System.out.println("==================================");
        System.out.println("Crawl Summary");
        System.out.println("==================================");
        System.out.println("Total pages: " + total);
        System.out.println("Successful: " + ok);
        System.out.println("Failed: " + fail);
        System.out.printf("Average response time: %.2f ms%n", avg);
        System.out.println("==================================");
    }

    /** Simple rotating file + console logging. */
    private static void setupLogging() {
        Logger root = Logger.getLogger("");
        root.setLevel(Level.INFO);
        for (Handler h : root.getHandlers()) h.setLevel(Level.INFO);
        try {
            FileHandler fh = new FileHandler("yoyo_crawler.log", true);
            fh.setFormatter(new SimpleFormatter());
            root.addHandler(fh);
        } catch (IOException e) {
            logger.warning("File logger initialization failed: " + e.getMessage());
        }
    }

    /** Task wrapper for queued crawl jobs. */
    private record CrawlTask(String url, int depth) {}

    /** Immutable result model. */
    private static final class CrawlResult {
        public final String url;
        public final int status;
        public final long responseTimeMs;
        public final int depth;
        public final String error;
        public final String timestamp;

        CrawlResult(String url, int status, long responseTimeMs, int depth, String error) {
            this.url = url;
            this.status = status;
            this.responseTimeMs = responseTimeMs;
            this.depth = depth;
            this.error = error;
            this.timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        }
    }
}
