@Service
@Slf4j
public class AwsCredentialsService {

    @Value("${aws.region:us-west-2}")
    private String awsRegion;

    @Value("${spring.datasource.url}")
    private String databaseUrl;

    // Use AWS Pod Identity to get RDS auth token
    @Bean
    @RefreshScope
    public DataSource dataSource() {
        HikariConfig config = new HikariConfig();
        
        // Extract RDS endpoint from JDBC URL
        String rdsEndpoint = extractRdsEndpoint(databaseUrl);
        String username = getCurrentPodServiceAccount() + "_db_user";
        
        // Generate IAM auth token (15-minute TTL)
        String authToken = generateRdsAuthToken(rdsEndpoint, username);
        
        config.setJdbcUrl(databaseUrl);
        config.setUsername(username);
        config.setPassword(authToken);
        config.setDriverClassName("org.postgresql.Driver");
        
        // Connection pool settings for short-lived tokens
        config.setMaximumPoolSize(10);
        config.setMinimumIdle(2);
        config.setMaxLifetime(TimeUnit.MINUTES.toMillis(10)); // Shorter than token TTL
        config.setLeakDetectionThreshold(TimeUnit.MINUTES.toMillis(2));
        
        // Validate connections before use (important for IAM auth)
        config.setConnectionTestQuery("SELECT 1");
        config.setValidationTimeout(5000);
        
        log.info("Configured RDS connection with IAM authentication for user: {}", username);
        
        return new HikariDataSource(config);
    }

    private String generateRdsAuthToken(String rdsEndpoint, String username) {
        try {
            // Use default credential provider chain (includes pod identity)
            DefaultCredentialsProvider credentialsProvider = DefaultCredentialsProvider.create();
            
            Region region = Region.of(awsRegion);
            RdsUtilities rdsUtilities = RdsUtilities.builder()
                .credentialsProvider(credentialsProvider)
                .region(region)
                .build();

            GenerateDbAuthTokenRequest tokenRequest = GenerateDbAuthTokenRequest.builder()
                .credentialsProvider(credentialsProvider)
                .hostname(rdsEndpoint)
                .port(5432)
                .username(username)
                .region(region)
                .build();

            String authToken = rdsUtilities.generateDbAuthToken(tokenRequest);
            
            log.debug("Generated RDS auth token for user: {} (expires in 15 minutes)", username);
            return authToken;
            
        } catch (Exception e) {
            log.error("Failed to generate RDS auth token", e);
            throw new RuntimeException("Database authentication failed", e);
        }
    }

    private String getCurrentPodServiceAccount() {
        // In real implementation, this would come from pod metadata
        // For now, derive from SPIFFE ID or environment
        String spiffeId = getCurrentSpiffeId();
        if (spiffeId != null && spiffeId.contains("/")) {
            String[] parts = spiffeId.split("/");
            return parts[parts.length - 1]; // Get service name
        }
        return "default-service";
    }

    private String getCurrentSpiffeId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : null;
    }

    private String extractRdsEndpoint(String jdbcUrl) {
        // Extract hostname from JDBC URL
        // jdbc:postgresql://mydb.cluster-xyz.us-west-2.rds.amazonaws.com:5432/mydb
        return jdbcUrl.replaceFirst(".*://", "")
                     .replaceFirst(":.*", "");
    }
}
