/*
 * yoyo.java — Secure Selenium + HTTP Hybrid Crawler
 * --------------------------------------------------
 * 2025 Edition — with concurrency, structured reports, and summary metrics.
 *
 * Features:
 *  • Authenticates via Selenium, then crawls pages concurrently.
 *  • Restricts crawling to specified BASE_DOMAIN.
 *  • Gathers metadata, status codes, and timestamps.
 *  • Outputs JSON and CSV reports + human-readable summary.
 */

import org.openqa.selenium.*;
import org.openqa.selenium.firefox.*;
import org.openqa.selenium.support.ui.*;

import java.io.*;
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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

public class Yoyo {

    // --------------------------------------
    // Configuration
    // --------------------------------------
    private static final Logger logger = Logger.getLogger("YoyoCrawler");
    private static final Duration DEFAULT_WAIT = Duration.ofSeconds(10);
    private static final String BASE_DOMAIN = "https://app.stg.yoyoyo.com";
    private static final int MAX_THREADS = 6;

    private static final List<CrawlResult> results = Collections.synchronizedList(new ArrayList<>());
    private static final AtomicInteger activeTasks = new AtomicInteger(0);

    public static void main(String[] args) {
        setupLogging();

        // --- Parse CLI args ---
        String geckodriverPath = System.getenv().getOrDefault("GECKODRIVER_PATH", "/usr/local/bin/geckodriver");
        String targetUrl = args.length > 0 ? args[0] : BASE_DOMAIN + "/login?teRegion=1";
        String username = args.length > 1 ? args[1] : "default_user@example.com";
        String password = args.length > 2 ? args[2] : "default_password";
        int maxDepth = args.length > 3 ? Integer.parseInt(args[3]) : 2;

        FirefoxOptions options = new FirefoxOptions()
                .addArguments("--headless", "--no-sandbox", "--disable-dev-shm-usage");
        FirefoxService service = new FirefoxService(new File(geckodriverPath));

        try (WebDriver driver = new FirefoxDriver(service, options)) {
            loginToApp(driver, targetUrl, username, password);

            List<String> initialLinks = extractLinks(driver);
            logger.info("Initial links found: " + initialLinks.size());

            crawlConcurrently(initialLinks, maxDepth);
            generateReports(results);
            printSummary(results);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Fatal error: " + e.getMessage(), e);
        }

        logger.info("✅ Crawl complete.");
    }

    // --------------------------------------------------
    // Login to the application
    // --------------------------------------------------
    private static void loginToApp(WebDriver driver, String targetUrl, String username, String password) {
        logger.info("Navigating to login: " + targetUrl);
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
            logger.log(Level.SEVERE, "Login failed: " + e.getMessage());
            throw new RuntimeException("Unable to login to app.");
        }
    }

    // --------------------------------------------------
    // Extract initial set of links after login
    // --------------------------------------------------
    private static List<String> extractLinks(WebDriver driver) {
        List<String> links = new ArrayList<>();
        for (WebElement a : driver.findElements(By.tagName("a"))) {
            String href = a.getAttribute("href");
            if (href != null && href.startsWith(BASE_DOMAIN)) {
                links.add(href);
            }
        }
        return links;
    }

    // --------------------------------------------------
    // Crawl concurrently with HTTPClient (not Selenium)
    // --------------------------------------------------
    private static void crawlConcurrently(List<String> initialLinks, int maxDepth) throws InterruptedException {
        ExecutorService executor = Executors.newFixedThreadPool(MAX_THREADS);
        Set<String> visited = ConcurrentHashMap.newKeySet();
        HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();

        Deque<CrawlTask> queue = new ArrayDeque<>();
        for (String link : initialLinks) {
            queue.add(new CrawlTask(link, 0));
        }

        while (!queue.isEmpty()) {
            CrawlTask task = queue.poll();
            if (task.depth > maxDepth || visited.contains(task.url)) continue;
            visited.add(task.url);
            activeTasks.incrementAndGet();

            executor.submit(() -> {
                Instant start = Instant.now();
                try {
                    HttpRequest request = HttpRequest.newBuilder(URI.create(task.url))
                            .timeout(Duration.ofSeconds(15))
                            .GET()
                            .build();
                    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                    Duration duration = Duration.between(start, Instant.now());

                    results.add(new CrawlResult(task.url, response.statusCode(), duration.toMillis(), task.depth));

                    // Extract new links
                    if (response.body() != null && response.statusCode() == 200 && task.depth < maxDepth) {
                        for (String link : extractLinksFromHtml(response.body())) {
                            if (link.startsWith(BASE_DOMAIN) && !visited.contains(link)) {
                                queue.add(new CrawlTask(link, task.depth + 1));
                            }
                        }
                    }
                } catch (Exception e) {
                    results.add(new CrawlResult(task.url, 0, 0, task.depth, e.getMessage()));
                } finally {
                    activeTasks.decrementAndGet();
                }
            });
        }

        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.MINUTES);
    }

    // --------------------------------------------------
    // Extract hrefs from HTML via regex (safe fallback)
    // --------------------------------------------------
    private static Set<String> extractLinksFromHtml(String html) {
        Set<String> links = new HashSet<>();
        var matcher = java.util.regex.Pattern.compile("href=[\"'](https?://[^\"'>\\s]+)[\"']")
                .matcher(html);
        while (matcher.find()) {
            links.add(matcher.group(1));
        }
        return links;
    }

    // --------------------------------------------------
    // Generate JSON + CSV reports
    // --------------------------------------------------
    private static void generateReports(List<CrawlResult> results) {
        Path jsonOut = Paths.get("crawled_links.json");
        Path csvOut = Paths.get("crawled_links.csv");

        try {
            // JSON
            ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            mapper.writeValue(jsonOut.toFile(), results);

            // CSV
            try (BufferedWriter writer = Files.newBufferedWriter(csvOut, StandardCharsets.UTF_8)) {
                writer.write("URL,Status,ResponseTime(ms),Depth,Error\n");
                for (CrawlResult r : results) {
                    writer.write(String.format("%s,%d,%d,%d,%s%n",
                            r.url, r.status, r.responseTimeMs, r.depth,
                            r.error == null ? "" : r.error.replace(",", " ")));
                }
            }
            logger.info("Reports generated: crawled_links.json + crawled_links.csv");
        } catch (IOException e) {
            logger.severe("Error writing reports: " + e.getMessage());
        }
    }

    // --------------------------------------------------
    // Print crawl summary
    // --------------------------------------------------
    private static void printSummary(List<CrawlResult> results) {
        long success = results.stream().filter(r -> r.status == 200).count();
        long failures = results.stream().filter(r -> r.status != 200).count();
        double avgResponse = results.stream()
                .mapToLong(r -> r.responseTimeMs)
                .average()
                .orElse(0.0);

        System.out.println("\n==============================");
        System.out.println("🧠 Crawl Summary");
        System.out.println("==============================");
        System.out.println("Total pages: " + results.size());
        System.out.println("Successful (200): " + success);
        System.out.println("Failed: " + failures);
        System.out.printf("Avg response time: %.2f ms%n", avgResponse);
        System.out.println("Results saved to: crawled_links.json / crawled_links.csv");
        System.out.println("==============================\n");
    }

    // --------------------------------------------------
    // Logging setup
    // --------------------------------------------------
    private static void setupLogging() {
        Logger rootLogger = Logger.getLogger("");
        rootLogger.setLevel(Level.INFO);
        for (var h : rootLogger.getHandlers()) h.setLevel(Level.INFO);

        try {
            FileHandler fileHandler = new FileHandler("yoyo_crawler.log", true);
            fileHandler.setFormatter(new SimpleFormatter());
            rootLogger.addHandler(fileHandler);
        } catch (IOException e) {
            logger.warning("Failed to init file logger: " + e.getMessage());
        }
    }

    // --------------------------------------------------
    // Internal record classes
    // --------------------------------------------------
    private record CrawlTask(String url, int depth) {}

    private static class CrawlResult {
        public String url;
        public int status;
        public long responseTimeMs;
        public int depth;
        public String error;
        public String timestamp;

        public CrawlResult(String url, int status, long responseTimeMs, int depth) {
            this(url, status, responseTimeMs, depth, null);
        }

        public CrawlResult(String url, int status, long responseTimeMs, int depth, String error) {
            this.url = url;
            this.status = status;
            this.responseTimeMs = responseTimeMs;
            this.depth = depth;
            this.error = error;
            this.timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        }
    }
}
