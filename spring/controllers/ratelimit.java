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
