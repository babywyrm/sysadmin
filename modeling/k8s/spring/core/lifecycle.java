@Component
@Slf4j
public class SessionLifecycleManager {

    @EventListener
    public void handleAuthenticationSuccess(AuthenticationSuccessEvent event) {
        Authentication auth = event.getAuthentication();
        String spiffeId = auth.getName();
        
        log.info("Session started - SPIFFE: {}, Authorities: {}, Timestamp: {}", 
                spiffeId, 
                auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(",")),
                Instant.now());
        
        // Optional: Record session metrics
        Metrics.counter("session.started", 
                "spiffe_tenant", extractTenant(spiffeId),
                "spiffe_service", extractService(spiffeId))
               .increment();
    }

    @EventListener
    public void handleAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        Exception exception = event.getException();
        
        log.warn("Authentication failed - Reason: {}, Timestamp: {}", 
                exception.getMessage(), Instant.now());
        
        Metrics.counter("session.failed", 
                "failure_reason", exception.getClass().getSimpleName())
               .increment();
    }

    @EventListener
    public void handleAuthorizationFailure(AuthorizationDeniedEvent event) {
        Authentication auth = event.getAuthentication();
        
        log.warn("Authorization denied - SPIFFE: {}, Resource: {}, Timestamp: {}", 
                auth.getName(), 
                event.getAuthorizationDecision(), 
                Instant.now());
        
        Metrics.counter("authorization.denied",
                "spiffe_id", auth.getName())
               .increment();
    }

    private String extractTenant(String spiffeId) {
        String[] parts = spiffeId.replace("spiffe://", "").split("/");
        return parts.length > 1 ? parts[1] : "unknown";
    }

    private String extractService(String spiffeId) {
        String[] parts = spiffeId.replace("spiffe://", "").split("/");
        return parts.length > 2 ? parts[2] : "unknown";
    }
}
