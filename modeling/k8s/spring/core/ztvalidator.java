@Service
@Slf4j
public class ZeroTrustValidator {

    @Value("${app.tenant}")
    private String currentTenant;

    // Validate user can access specific user data
    public boolean canAccessUser(Authentication auth, String targetUserId) {
        String spiffeId = auth.getName();
        String userTenant = extractTenantFromSpiffeId(spiffeId);
        String targetTenant = extractTenantFromUserId(targetUserId);
        
        // Same tenant check
        if (!Objects.equals(userTenant, targetTenant)) {
            log.warn("Cross-tenant access denied - SPIFFE: {}, Target: {}", 
                    spiffeId, targetUserId);
            return false;
        }
        
        // Admin can access any user in same tenant
        if (auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            return true;
        }
        
        // User can only access their own data
        String currentUserId = extractUserIdFromSpiffeId(spiffeId);
        boolean canAccess = Objects.equals(currentUserId, targetUserId);
        
        if (!canAccess) {
            log.warn("Self-access violation - SPIFFE: {}, Target: {}", 
                    spiffeId, targetUserId);
        }
        
        return canAccess;
    }

    // Validate user can modify specific user
    public boolean canModifyUser(Authentication auth, String targetUserId) {
        // Same access rules as read, but log modification attempts
        boolean canModify = canAccessUser(auth, targetUserId);
        
        if (canModify) {
            log.info("User modification authorized - SPIFFE: {}, Target: {}", 
                    auth.getName(), targetUserId);
        }
        
        return canModify;
    }

    // Validate transfer operations with additional business rules
    public boolean canInitiateTransfer(Authentication auth, String userId) {
        if (!canAccessUser(auth, userId)) {
            return false;
        }
        
        // Additional check: only services with transfer scope
        boolean hasTransferScope = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("SCOPE_transfer"));
        
        if (!hasTransferScope) {
            log.warn("Transfer scope missing - SPIFFE: {}", auth.getName());
            return false;
        }
        
        return true;
    }

    // Runtime transfer limits validation
    public boolean validateTransferLimits(Authentication auth, TransferRequest request) {
        String spiffeId = auth.getName();
        
        // Business rule: Different limits based on service identity
        BigDecimal maxAmount = getMaxTransferAmount(spiffeId);
        
        if (request.getAmount().compareTo(maxAmount) > 0) {
            log.warn("Transfer limit exceeded - SPIFFE: {}, Amount: {}, Limit: {}", 
                    spiffeId, request.getAmount(), maxAmount);
            return false;
        }
        
        return true;
    }

    // Filter sensitive data based on caller identity
    public UserDto filterUserData(UserDto user, Authentication auth) {
        String spiffeId = auth.getName();
        
        // Admin gets full data
        if (auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            return user;
        }
        
        // Regular users get filtered view
        return UserDto.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                // Remove sensitive fields
                .build();
    }

    private String extractTenantFromSpiffeId(String spiffeId) {
        // spiffe://mycompany.internal/bank-a/user-service -> bank-a
        String[] parts = spiffeId.replace("spiffe://", "").split("/");
        return parts.length > 1 ? parts[1] : null;
    }

    private String extractUserIdFromSpiffeId(String spiffeId) {
        // For user-specific SPIFFEs: spiffe://mycompany.internal/bank-a/user/12345
        String[] parts = spiffeId.replace("spiffe://", "").split("/");
        return parts.length > 3 && "user".equals(parts[2]) ? parts[3] : null;
    }

    private String extractTenantFromUserId(String userId) {
        // Business logic to determine tenant from user ID
        // Could be prefix, database lookup, etc.
        return userId.startsWith("bank-a") ? "bank-a" : "bank-b";
    }

    private BigDecimal getMaxTransferAmount(String spiffeId) {
        // Business rules based on service identity
        if (spiffeId.contains("/admin-service")) {
            return new BigDecimal("1000000"); // $1M limit for admin
        } else if (spiffeId.contains("/api-gateway")) {
            return new BigDecimal("10000"); // $10K limit for regular API
        }
        return new BigDecimal("1000"); // $1K default limit
    }
}
