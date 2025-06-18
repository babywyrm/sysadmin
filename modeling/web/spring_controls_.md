

## A. Spring MVC–Specific Controls

### 1. Authentication & Authorization

#### Java Config (Spring Security 5+)

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
      // authorize by role
      .authorizeHttpRequests(auth -> auth
        .requestMatchers("/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated())
      // form-login or JWT/OAuth2 config here
      .formLogin(withDefaults())
      // CSRF enabled by default
      .csrf(csrf -> csrf.disable());   // if using token-based auth
    return http.build();
  }
}
```

```java
// Method-level check
@RestController
public class AdminController {
  @PreAuthorize("hasRole('ADMIN')")
  @GetMapping("/admin/dashboard")
  public String dashboard() { … }
}
```

### 2. Input Validation & Output Encoding

#### DTO with JSR-303 & Global Handler

```java
@Data
public class UserDTO {
  @NotBlank @Size(min=3,max=50)
  private String username;

  @Email @NotBlank
  private String email;
}

@RestController
public class UserController {
  @PostMapping("/users")
  public ResponseEntity<?> create(@Valid @RequestBody UserDTO dto) {
    // …
  }
}

@ControllerAdvice
public class ValidationErrorHandler {
  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<Map<String,String>> handle(MANException ex) {
    Map<String,String> errs = ex.getBindingResult().getFieldErrors().stream()
      .collect(toMap(FieldError::getField, FieldError::getDefaultMessage));
    return badRequest().body(errs);
  }
}
```

#### Thymeleaf Auto-Escaping

```html
<!-- templates/profile.html -->
<p>Welcome, <span th:text="${user.name}"></span>!</p>
```

---

## B. Cryptography & Secrets

### 1. TLS Everywhere

#### `application.yml`

```yaml
server:
  port: 8443
  ssl:
    key-store: classpath:keystore.p12
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
    key-store-type: PKCS12
```

### 2. Encrypt at Rest

#### JPA Attribute Converter

```java
@Converter
public class CryptoConverter implements AttributeConverter<String,String> {
  private static final String KEY = System.getenv("DB_ENCRYPTION_KEY");
  @Override
  public String convertToDatabaseColumn(String attr) {
    return AES.encrypt(attr, KEY);
  }
  @Override
  public String convertToEntityAttribute(String dbData) {
    return AES.decrypt(dbData, KEY);
  }
}

@Entity
public class SecretEntity {
  @Convert(converter = CryptoConverter.class)
  private String secretField;
}
```

### 3. Secrets Management

#### Kubernetes Secret + Deployment Snippet

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
type: Opaque
stringData:
  username: dbuser
  password: P@ssw0rd

---

apiVersion: apps/v1
kind: Deployment
metadata: { name: user-service }
spec:
  template:
    spec:
      containers:
      - name: app
        image: myregistry/user-service:latest
        env:
        - name: DB_USER
          valueFrom:
            secretKeyRef:
              name: db-creds
              key: username
        - name: DB_PASS
          valueFrom:
            secretKeyRef:
              name: db-creds
              key: password
```

---

## C. Logging & Monitoring

### 1. Correlation ID Filter

```java
@Component
public class CorrelationIdFilter extends OncePerRequestFilter {
  public static final String HEADER = "X-Correlation-Id";
  @Override
  protected void doFilterInternal(
      HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {
    String id = req.getHeader(HEADER);
    if (id == null) id = UUID.randomUUID().toString();
    MDC.put("correlationId", id);
    res.setHeader(HEADER, id);
    try {
      chain.doFilter(req, res);
    } finally {
      MDC.remove("correlationId");
    }
  }
}
```

#### Logback Pattern (in `logback-spring.xml`)

```xml
<pattern>
  {"timestamp":"%d{ISO8601}","level":"%level","thread":"%thread",
   "logger":"%logger","message":"%msg","correlationId":"%X{correlationId}" }
</pattern>
```

### 2. Structured JSON Logging

```xml
<configuration>
  <appender name="stash" class="ch.qos.logback.core.ConsoleAppender">
    <encoder class="net.logstash.logback.encoder.LogstashEncoder">
      <customFields>{"app":"user-service"}</customFields>
    </encoder>
  </appender>
  <root level="INFO">
    <appender-ref ref="stash"/>
  </root>
</configuration>
```

---

## D. Container & Deployment Hardening

### 1. Dockerfile Best Practices

```dockerfile
# 1) Build stage
FROM maven:3.8-jdk-17 AS build
WORKDIR /workspace
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src src
RUN mvn package -DskipTests

# 2) Runtime stage
FROM eclipse-temurin:17-jre-alpine
RUN addgroup -S appgrp && adduser -S spring -G appgrp
USER spring
WORKDIR /app
COPY --from=build /workspace/target/*.jar app.jar
ENTRYPOINT ["java","-jar","/app/app.jar"]
```

> **Runtime flags:**
>
> ```shell
> docker run --read-only \
>   --cap-drop ALL \
>   -p 8443:8443 \
>   myregistry/user-service:latest
> ```

### 2. Kubernetes Pod Security Context

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: user-service }
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        readOnlyRootFilesystem: true
      containers:
      - name: app
        image: myregistry/user-service:latest
        ports: [{ containerPort: 8443 }]
      restartPolicy: Always
```

---

## E. Supply-Chain & CI/CD

### 1. Image Signing (GitHub Actions)

```yaml
jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Build image
      run: docker build -t user-service:latest .
    - name: Sign & push
      env:
        DOCKER_CONTENT_TRUST: 1
        DOCKER_CONTENT_TRUST_ROOT_PASSPHRASE: ${{ secrets.NOTARY_ROOT_PASSPHRASE }}
        DOCKER_CONTENT_TRUST_REPOSITORY_PASSPHRASE: ${{ secrets.NOTARY_REPO_PASSPHRASE }}
      run: docker push user-service:latest
```

### 2. SBOM Generation (Syft)

```yaml
- name: Generate SBOM
  run: syft user-service:latest -o cyclonedx-json=sbom.json
- name: Upload SBOM
  uses: actions/upload-artifact@v3
  with:
    name: sbom
    path: sbom.json
```

### 3. Dependency Scanning (OWASP Dependency-Check)

```yaml
- name: Dependency-Check Scan
  uses: jeremylong/DependencyCheck_Github_Action@v2
  with:
    format: 'ALL'
    scan-path: '.'
```

### 4. Automated Upgrades (Renovate)

```json
// renovate.json
{
  "extends": ["config:base"],
  "packageRules": [
    {
      "updateTypes": ["major","minor","patch"],
      "automerge": true
    }
  ]
}
```

