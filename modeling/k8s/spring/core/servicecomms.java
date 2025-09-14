@Configuration
public class ServiceClientConfig {

    @Autowired
    private SpiffeX509Source spiffeX509Source;

    @Bean
    @Qualifier("accountService")
    public WebClient accountServiceClient() {
        return createMtlsWebClient("https://account-service.bank-a.svc.cluster.local");
    }

    @Bean
    @Qualifier("paymentService")  
    public WebClient paymentServiceClient() {
        return createMtlsWebClient("https://payment-service.bank-b.svc.cluster.local");
    }

    private WebClient createMtlsWebClient(String baseUrl) {
        try {
            // Create SSL context with SPIFFE certificates
            SslContext sslContext = SslContextBuilder.forClient()
                .keyManager(
                    spiffeX509Source.getX509Context().getPrivateKey(),
                    spiffeX509Source.getX509Context().getCertificateChain()
                )
                .trustManager(spiffeX509Source.getX509Context().getTrustedCerts())
                .build();

            HttpClient httpClient = HttpClient.create()
                .secure(ssl -> ssl.sslContext(sslContext))
                .responseTimeout(Duration.ofSeconds(30));

            return WebClient.builder()
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .defaultHeader("X-Service-Identity", getCurrentSpiffeId())
                .build();
                
        } catch (Exception e) {
            throw new RuntimeException("Failed to create mTLS WebClient", e);
        }
    }

    private String getCurrentSpiffeId() {
        try {
            return spiffeX509Source.getX509Context()
                    .getSpiffeId()
                    .toString();
        } catch (Exception e) {
            log.warn("Could not get current SPIFFE ID", e);
            return "unknown";
        }
    }
}
