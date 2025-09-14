@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@Slf4j
public class ZeroTrustSecurityConfig {

    @Value("${spiffe.trust-domain:mycompany.internal}")
    private String trustDomain;

    @Value("${spiffe.socket-path:/tmp/spire-agent/public/api.sock}")
    private String spiffeSocketPath;

    // SPIFFE X.509 Source for mTLS
    @Bean
    @Primary
    public SpiffeX509Source spiffeX509Source() {
        try {
            return DefaultSpiffeX509Source.builder()
                .spiffeSocketPath(spiffeSocketPath)
                .build();
        } catch (Exception e) {
            log.error("Failed to initialize SPIFFE X509 Source", e);
            throw new RuntimeException("SPIFFE initialization failed", e);
        }
    }

    // Custom JWT decoder that validates internal JWTs from Ambassador
    @Bean
    public JwtDecoder jwtDecoder() {
        return new SpiffeJwtDecoder(trustDomain);
    }

    // Main security filter chain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(spiffeJwtAuthenticationConverter())
                )
            )
            .authorizeHttpRequests(authz -> authz
                // Health checks - no auth required
                .requestMatchers("/actuator/health", "/actuator/ready").permitAll()
                
                // API endpoints - require valid SPIFFE identity
                .requestMatchers("/api/v1/users/**").hasAuthority("SPIFFE_ID")
                .requestMatchers("/api/v1/accounts/**").hasAuthority("SPIFFE_ID")
                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                
                // Everything else requires authentication
                .anyRequest().authenticated()
            )
            .csrf(csrf -> csrf.disable()) // Stateless API
            .httpBasic(basic -> basic.disable())
            .formLogin(form -> form.disable());

        return http.build();
    }

    // Convert JWT claims to Spring Security Authentication
    @Bean
    public Converter<Jwt, JwtAuthenticationToken> spiffeJwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            
            // Extract SPIFFE ID and add as authority
            String spiffeId = jwt.getClaimAsString("sub");
            if (spiffeId != null && spiffeId.startsWith("spiffe://")) {
                authorities.add(new SimpleGrantedAuthority("SPIFFE_ID"));
                
                // Extract tenant from SPIFFE ID
                String tenant = extractTenantFromSpiffeId(spiffeId);
                if (tenant != null) {
                    authorities.add(new SimpleGrantedAuthority("TENANT_" + tenant.toUpperCase()));
                }
                
                // Extract service role
                String serviceRole = extractServiceRoleFromSpiffeId(spiffeId);
                if (serviceRole != null) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + serviceRole.toUpperCase()));
                }
            }
            
            // Extract scopes from JWT
            List<String> scopes = jwt.getClaimAsStringList("scope");
            if (scopes != null) {
                scopes.forEach(scope -> 
                    authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope))
                );
            }
            
            return authorities;
        });
        
        return converter::convert;
    }

    private String extractTenantFromSpiffeId(String spiffeId) {
        // spiffe://mycompany.internal/bank-a/user-service -> bank-a
        String[] parts = spiffeId.replace("spiffe://", "").split("/");
        return parts.length > 1 ? parts[1] : null;
    }

    private String extractServiceRoleFromSpiffeId(String spiffeId) {
        // spiffe://mycompany.internal/bank-a/user-service -> user-service
        String[] parts = spiffeId.replace("spiffe://", "").split("/");
        return parts.length > 2 ? parts[2] : null;
    }
}
