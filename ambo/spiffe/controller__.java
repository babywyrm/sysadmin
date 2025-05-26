package com.example;

import io.spiffe.workloadapi.DefaultWorkloadApiClient;
import io.spiffe.workloadapi.WorkloadApiClient;
import io.spiffe.workloadapi.X509Source;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

@SpringBootApplication
public class Application {

  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }

  // Expose a WebClient.Builder for injection
  @Bean
  public WebClient.Builder webClientBuilder() {
    return WebClient.builder();
  }

  /**
   * Component that talks to the SPIRE Agent via the Workload API
   * to fetch X.509 SVIDs (SPIFFE identities) for mTLS.
   */
  @Component
  public static class SpiffeIdentityProvider {
    private static final Logger logger =
        LoggerFactory.getLogger(SpiffeIdentityProvider.class);

    // Path to the SPIFFE Workload API socket (in-cluster)
    private static final String SPIFFE_SOCKET =
        System.getenv()
            .getOrDefault("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/agent.sock");

    public X509Source getX509Source() throws Exception {
      WorkloadApiClient client =
          DefaultWorkloadApiClient.newClient(SPIFFE_SOCKET);
      X509Source x509Source = client.getX509Source();
      logger.info("Obtained SPIFFE ID: {}", x509Source.getSpiffeId());
      return x509Source;
    }
  }

  /**
   * REST controller that receives user requests (with JWTs minted by Ambassador),
   * and calls downstream services with SPIFFE-based mTLS + JWT propagation.
   */
  @RestController
  public static class SecureController {
    private static final Logger logger =
        LoggerFactory.getLogger(SecureController.class);

    private final WebClient webClient;

    @Autowired
    public SecureController(
        WebClient.Builder webClientBuilder,
        SpiffeIdentityProvider spiffeProvider
    ) throws Exception {
      // Retrieve SPIFFE X.509 context
      X509Source x509Source = spiffeProvider.getX509Source();
      TrustManager[] trustManagers = x509Source.getTrustManager();
      KeyManager[] keyManagers = x509Source.getKeyManager();

      // Build Netty SslContext for mTLS
      SslContext sslContext = SslContextBuilder.forClient()
          .trustManager(trustManagers)
          .keyManager(keyManagers)
          .build();

      // Create an HttpClient secured with SPIFFE mTLS
      HttpClient httpClient = HttpClient.create()
          .secure(spec -> spec.sslContext(sslContext));

      // Build a WebClient that uses the secure HttpClient
      this.webClient = webClientBuilder
          .clientConnector(new ReactorClientHttpConnector(httpClient))
          .build();

      logger.info("Configured WebClient with SPIFFE mTLS");
    }

    /**
     * Example endpoint: forwards the call to a backend service,
     * propagating the user JWT and using SPIFFE mTLS under the hood.
     */
    @GetMapping("/secure-data")
    public Mono<ResponseEntity<String>> getSecureData(
        @RequestHeader("Authorization") String authHeader
    ) {
      logger.info("Incoming /secure-data request; forwarding with SPIFFE mTLS");
      return webClient.get()
          .uri("https://backend-service.backend-namespace:8080/secure")
          .header("Authorization", authHeader)
          .retrieve()
          .toEntity(String.class)
          .doOnNext(resp ->
              logger.info("Backend responded: {}", resp.getStatusCode()))
          .doOnError(err ->
              logger.error("Error calling backend", err));
    }
  }
}

   /**
     * SpiffeIdentityProvider uses the SPIFFE Workload API to fetch the pod’s SVID, trust and key managers.
     * SecureController builds a Reactor WebClient with an SSL context based on those SPIFFE credentials, ensuring all downstream calls use mTLS with verified SPIFFE identities.
     * Incoming JWTs (minted by Ambassador at the edge) are propagated via the Authorization header so you retain user context throughout.
     * You can drop this single file into your Spring Boot application (com.example.Application), and Spring will wire up both components automatically.
     */
