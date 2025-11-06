package com.example.vulnerablesite;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.owasp.encoder.Encode;

@SpringBootApplication
public class VulnerableSiteApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableSiteApplication.class, args);
    }
}

/**
 * Includes intentionally vulnerable endpoints for educational purposes
 * and secure variants demonstrating mitigations.
 */
@RestController
@RequestMapping("/demo")
public class VulnerableController {

    // === 1. CORS DEMONSTRATION ===

    /**
     * Vulnerable: allows all origins, any script on any site can call it.
     */
    @CrossOrigin(origins = "*")
    @GetMapping("/cors-vulnerable")
    public ResponseEntity<String> corsVulnerable() {
        return ResponseEntity.ok("CORS policy is wide open!");
    }

    /**
     * Fixed: restrict origins explicitly based on trusted configuration.
     */
    @CrossOrigin(origins = {"https://trusted.example.com"})
    @GetMapping("/cors-safe")
    public ResponseEntity<String> corsSafe() {
        return ResponseEntity.ok("CORS restricted to trusted origins only.");
    }

    // === 2. REFLECTED XSS DEMONSTRATION ===

    /**
     * Vulnerable: directly reflects user input into HTML content without encoding.
     * Payload example: <script>alert(1)</script>
     */
    @GetMapping("/xss")
    public ResponseEntity<String> xssVulnerable(@RequestParam("input") String input) {
        return ResponseEntity.ok("<html><body>Reflected input: " + input + "</body></html>");
    }

    /**
     * Fixed: Encode user input before inserting into HTML.
     */
    @GetMapping("/xss-safe")
    public ResponseEntity<String> xssSafe(@RequestParam("input") String input) {
        String safeInput = Encode.forHtml(input);
        return ResponseEntity.ok("<html><body>Reflected input: " + safeInput + "</body></html>");
    }

    // === 3. CSRF DEMONSTRATION ===

    /**
     * Vulnerable: Allows any external site to cause state changes by POST.
     */
    @PostMapping("/change-password")
    public ResponseEntity<String> changePasswordVulnerable(
            @RequestParam("newPassword") String newPassword,
            HttpSession session) {

        session.setAttribute("password", newPassword);
        return ResponseEntity.ok("Password changed to: " + newPassword);
    }

    /**
     * Fixed: CSRF protection using token header simulation.
     * Would typically use Spring Security’s built-in CSRF protection.
     */
    @PostMapping("/change-password-safe")
    public ResponseEntity<String> changePasswordSafe(
            @RequestHeader(value = "X-CSRF-Token", required = false) String token,
            @RequestParam("newPassword") String newPassword,
            HttpSession session) {

        String validToken = "known-static-demo-token"; // Example demonstration
        if (token == null || !token.equals(validToken)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                 .body("CSRF token missing or invalid.");
        }

        session.setAttribute("password", newPassword);
        return ResponseEntity.ok("Password changed securely with CSRF validation.");
    }

    // === 4. COOKIE HANDLING DEMONSTRATION ===

    /**
     * Vulnerable: Sets cookie without HttpOnly, Secure, or SameSite flags.
     */
    @GetMapping("/set-cookie")
    public ResponseEntity<String> setCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("sessionID", "123456");
        response.addCookie(cookie);
        return ResponseEntity.ok("Cookie set without security flags.");
    }

    /**
     * Fixed: Sets HttpOnly and Secure cookies to reduce risk.
     */
    @GetMapping("/set-cookie-safe")
    public ResponseEntity<String> setCookieSafe(HttpServletResponse response) {
        Cookie cookie = new Cookie("sessionID", "abcdef-secure");
        cookie.setHttpOnly(true);        // Not accessible via JavaScript
        cookie.setSecure(true);          // Only transmitted over HTTPS
        cookie.setPath("/");
        cookie.setMaxAge(3600);
        cookie.setAttribute("SameSite", "Strict");
        response.addCookie(cookie);
        return ResponseEntity.ok("Secure cookie has been set with proper flags.");
    }

    // === 5. IFRAME EMBEDDING DEMONSTRATION ===

    /**
     * Vulnerable: Missing X-Frame-Options or CSP headers allows clickjacking.
     */
    @GetMapping("/embed")
    public ResponseEntity<String> iframeVulnerable() {
        return ResponseEntity.ok("<html><body>This page can be embedded in an iframe!</body></html>");
    }

    /**
     * Fixed: Add X-Frame-Options DENY or CSP header to disallow framing.
     */
    @GetMapping("/embed-safe")
    public ResponseEntity<String> iframeSafe() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Frame-Options", "DENY");
        headers.add("Content-Security-Policy", "frame-ancestors 'none'");
        String body = "<html><body>This page cannot be embedded in an iframe.</body></html>";
        return new ResponseEntity<>(body, headers, HttpStatus.OK);
    }
}
