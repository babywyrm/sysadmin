package com.example.vulnerablesite;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

@SpringBootApplication
public class VulnerableSiteApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableSiteApplication.class, args);
    }
}

@RestController
public class VulnerableController {

    // CORS Vulnerability - Allow all origins
    @CrossOrigin(origins = "*")
    @GetMapping("/cors-vulnerable")
    public ResponseEntity<String> corsVulnerable() {
        return ResponseEntity.ok("CORS policy is wide open!");
    }

    // XSS Vulnerability - Reflects user input without sanitization
    @GetMapping("/xss")
    public ResponseEntity<String> xssVulnerable(@RequestParam("input") String input) {
        return ResponseEntity.ok("<html><body>Reflected input: " + input + "</body></html>");
    }

    // CSRF Vulnerability - No CSRF protection on state-changing request
    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(@RequestParam("newPassword") String newPassword, HttpSession session) {
        session.setAttribute("password", newPassword);
        return ResponseEntity.ok("Password changed to: " + newPassword);
    }

    // Insecure Cookie Handling - Cookie without security flags
    @GetMapping("/set-cookie")
    public ResponseEntity<String> setCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("sessionID", "123456");
        response.addCookie(cookie);
        return ResponseEntity.ok("Cookie set without security flags.");
    }

    // Iframe Embedding Vulnerability - No X-Frame-Options header
    @GetMapping("/embed")
    public ResponseEntity<String> iframeVulnerable() {
        return ResponseEntity.ok("<html><body>This page can be embedded in an iframe!</body></html>");
    }
}
