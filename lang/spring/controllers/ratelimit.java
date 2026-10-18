package com.example.ratelimiting.config;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

@Configuration
public class RateLimitControllerConfig {

    // In-memory storage for rate limiting by IP
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    // Creates or retrieves the token bucket for a specific IP address
    private Bucket resolveBucket(String ip) {
        return buckets.computeIfAbsent(ip, createNewBucket());
    }

    // Defines the rate-limiting strategy: 240 requests per minute per IP
    private Function<String, Bucket> createNewBucket() {
        return ip -> Bucket4j.builder()
                .addLimit(Bandwidth.classic(240, Refill.greedy(240, Duration.ofMinutes(1))))
                .build();
    }

    // IP-based rate-limiting resolver
    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> Mono.just(exchange.getRequest().getRemoteAddress().getAddress().getHostAddress());
    }

    @RestController
    @RequestMapping("/api")
    public class RateLimitedController {

        // GET endpoint for rate-limited requests by IP
        @PostMapping("/sensitive-endpoint")
        public ResponseEntity<String> sensitiveAction(ServerWebExchange exchange) {
            // Extract client IP address
            String clientIP = exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();

            // Resolve or create a bucket for this client IP
            Bucket bucket = resolveBucket(clientIP);

            // Try to consume a token from the bucket
            if (bucket.tryConsume(1)) {
                // Allow the request if within the rate limit
                return ResponseEntity.ok("Request processed successfully for IP: " + clientIP);
            } else {
                // Reject the request if rate limit exceeded
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body("Rate limit exceeded. Too many requests from IP: " + clientIP);
            }
        }

        // Simple endpoint to show the rate limit status
        @GetMapping("/rate-limit-status")
        public ResponseEntity<String> getRateLimitStatus(ServerWebExchange exchange) {
            String clientIP = exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
            Bucket bucket = resolveBucket(clientIP);
            long availableTokens = bucket.getAvailableTokens();

            return ResponseEntity.ok("Remaining requests for IP " + clientIP + ": " + availableTokens);
        }
    }
}


//
//

Key Components Explained:
buckets Map<String, Bucket>:
This map stores token buckets per unique IP address. 
    For each IP, a token bucket is created or retrieved with a limit of 240 requests per minute. 
    This setup ensures that rate limiting is done per client IP.

resolveBucket(String ip):
The method checks if there is an existing bucket for the given IP. If not, it creates a new one using the createNewBucket() method, which defines the rate limit.

Bucket4j.builder():
Defines the rate-limiting strategy: Bandwidth.classic(240, Refill.greedy(240, Duration.ofMinutes(1))) limits each IP to 240 requests per minute, refilling the bucket every minute.

sensitiveAction(ServerWebExchange exchange):
This endpoint enforces rate limiting. It extracts the client's IP from the request and checks whether there is capacity in the bucket for the request. If the bucket has available tokens, the request is processed. Otherwise, it returns a 429 Too Many Requests response.

Rate-Limit Status Endpoint:
The getRateLimitStatus() endpoint can be used to check how many requests are left for the current IP address. It provides useful feedback for debugging or monitoring.

Rate Limiting Flow:
When a request is made to /api/sensitive-endpoint, the system checks how many tokens are available in the bucket for the requesting IP.
If tokens are available, the request is processed.
If not, the request is rejected with a 429 Too Many Requests HTTP response.
This controller enforces the rate limit per IP address, ensuring that no single IP can exceed 240 requests per minute.

How to Run:
The RateLimitControllerConfig class is a Spring configuration class, and the RateLimitedController is a REST controller. Simply include this class in your Spring project, and ensure that you have the appropriate dependencies in your pom.xml.
If you need centralized rate limiting for multiple microservices, this structure can be implemented using Spring Cloud Gateway for all AJAX requests or API calls. The core logic will remain similar, except that you may want to customize how KeyResolver handles requestor identification (for example, based on session, IP, or JWT).

Spring Boot Application Configuration (application.yml):
For the application to manage rate limiting efficiently, here's an example of some basic configurations you might use in your application.yml.

//
server:
  port: 8080

spring:
  application:
    name: RateLimiterApp

# Redis or other centralized stores can be integrated for multi-instance setups

