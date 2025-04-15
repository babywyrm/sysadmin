
---

# **OWASP Top 10 Vulnerabilities for Java/Spring Microservices: Detailed Examples and Solutions** (2025, Beta) 

## **1. Injection (SQL, NoSQL, Command Injection)**

### **Penetration Testing Steps**
   - **Step 1: Identify User Inputs**: Look for any places where user data is passed directly to a database or system command (e.g., search forms, login forms, query parameters).
   - **Step 2: Test with Common Payloads**: 
     - For **SQL Injection**: Test with payloads like `' OR 1=1 --` or `'; DROP TABLE users; --`.
     - For **NoSQL Injection**: Test with `{ "$ne": null }` in MongoDB queries.
     - For **Command Injection**: Test for system command injections by adding shell commands to inputs like `; ls -la`.

### **Example of a Flaw**:
   - **Example 1**: SQL Injection vulnerability in a Spring Data JPA query:

```java
@Repository
public class UserRepository {
    @PersistenceContext
    private EntityManager entityManager;

    public User findByUsername(String username) {
        String query = "SELECT u FROM User u WHERE u.username = '" + username + "'";
        return entityManager.createQuery(query, User.class).getSingleResult();
    }
}
```

   - **Example 2**: Command Injection in a Spring service that runs shell commands with user input.

```java
public class CommandService {
    public String executeCommand(String command) throws IOException {
        Runtime.getRuntime().exec(command);  // Unsafe command execution
    }
}
```

#### **Remediation**:
   - **Use Prepared Statements**: Use parameterized queries or Spring’s `@Query` annotation with safe parameters to prevent SQL injection.
   - **Command Execution**: Avoid executing shell commands directly with user input. Use safe APIs or libraries for system interaction.

```java
@Repository
public class UserRepository {
    @PersistenceContext
    private EntityManager entityManager;

    public User findByUsername(String username) {
        String query = "SELECT u FROM User u WHERE u.username = :username";
        return entityManager.createQuery(query, User.class)
                            .setParameter("username", username)
                            .getSingleResult();
    }
}

public class CommandService {
    public String executeCommand(String command) throws IOException {
        if (command.equals("allowed_command")) {
            Runtime.getRuntime().exec(command);
        } else {
            throw new IllegalArgumentException("Invalid command");
        }
    }
}
```

   - **Libraries to Fix**:
     - **Spring Data JPA** (for secure database access)
     - **Apache Commons Exec** (to securely run system commands)

---

## **2. Broken Authentication**

### **Penetration Testing Steps**
   - **Step 1: Brute Force Testing**: Use tools like **Hydra** or **Burp Suite Intruder** to test for weak or missing rate limiting on login forms.
   - **Step 2: Session Management**: Ensure that sessions are properly terminated and regenerate session IDs after login to prevent **session fixation**.

### **Example of a Flaw**:
   - **Example**: Password comparison using plain-text passwords in a Spring authentication controller.

```java
@RestController
public class AuthenticationController {

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        User user = userRepository.findByUsername(username);
        if (user != null && password.equals(user.getPassword())) {
            return "Logged in successfully";
        } else {
            return "Invalid credentials";
        }
    }
}
```

#### **Remediation**:
   - **Use Password Hashing**: Use **bcrypt** or **Argon2** for hashing passwords and **Spring Security** for authentication.
   - **Regenerate Session ID**: After login, regenerate the session ID to prevent session fixation.

```java
@Service
public class AuthenticationService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        User user = userRepository.findByUsername(username);
        if (user != null && passwordEncoder.matches(password, user.getPassword())) {
            return "Logged in successfully";
        } else {
            return "Invalid credentials";
        }
    }
}
```

   - **Libraries to Fix**:
     - **Spring Security** (for user authentication and password encoding)
     - **BCryptPasswordEncoder** (for securely hashing passwords)

---

## **3. Sensitive Data Exposure**

### **Penetration Testing Steps**
   - **Step 1: Check for Insecure Transmission**: Test that all sensitive data is transmitted over **HTTPS** and not HTTP.
   - **Step 2: Test for Insecure Storage**: Check if sensitive data like passwords, API tokens, or session cookies are stored in **plaintext**.

### **Example of a Flaw**:
   - **Example 1**: Sensitive data logged or exposed in plaintext.

```java
// Exposing sensitive data in logs
logger.info("User's password: " + user.getPassword());
```

   - **Example 2**: Storing sensitive data in **plaintext** in the database.

```java
@Entity
public class User {
    @Id
    private Long id;
    private String username;
    private String password;  // Plaintext password storage
}
```

#### **Remediation**:
   - **Encrypt Sensitive Data**: Always encrypt sensitive data both in transit (using **TLS**) and at rest (using **AES-256**).
   - **Never Log Sensitive Data**: Avoid logging sensitive information like passwords or tokens.

```java
// Use AES-256 encryption for passwords and sensitive data
@Service
public class EncryptionService {

    public String encryptPassword(String password) {
        // Implement AES encryption for password
        return encryptedPassword;
    }
}
```

   - **Libraries to Fix**:
     - **Spring Security** (for encryption and hashing)
     - **BCryptPasswordEncoder** (for hashing passwords)
     - **JCE (Java Cryptography Extension)** (for encrypting sensitive data)

---

## **4. XML External Entities (XXE)**

### **Penetration Testing Steps**
   - **Step 1: Identify XML Parsers**: Look for places where **XML** input is processed.
   - **Step 2: Test for XXE**: Craft an XML payload with an external entity like `<!ENTITY xxe SYSTEM "file:///etc/passwd">`.

### **Example of a Flaw**:
   - **Example**: Unsafe XML parsing in Spring application.

```java
public void parseXml(String xml) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document document = builder.parse(new InputSource(new StringReader(xml)));
}
```

#### **Remediation**:
   - **Disable DTDs**: Disable Document Type Definitions (DTDs) and external entities in XML parsers to prevent XXE attacks.

```java
public void parseXml(String xml) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document document = builder.parse(new InputSource(new StringReader(xml)));
}
```

   - **Libraries to Fix**:
     - **Java XML Libraries** (e.g., **JAXP**)
     - **OWASP Java XML Security Library** (for securing XML parsing)

---

## **5. Broken Access Control**

### **Penetration Testing Steps**
   - **Step 1: Test Role-Based Access**: Try accessing restricted areas by modifying URLs or request parameters.
   - **Step 2: Test for Horizontal Access Control**: Access other users' data by manipulating user IDs in the URL.

### **Example of a Flaw**:
   - **Example**: No access control for `/admin` endpoint.

```java
@RestController
public class AdminController {

    @GetMapping("/admin/dashboard")
    public String getAdminDashboard() {
        return "Admin Dashboard";
    }
}
```

#### **Remediation**:
   - **Use Spring Security** to enforce **RBAC** and ensure proper authorization checks are performed.

```java
@RestController
public class AdminController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/dashboard")
    public String getAdminDashboard() {
        return "Admin Dashboard";
    }
}
```

   - **Libraries to Fix**:
     - **Spring Security** (for role-based access control)
     - **Spring Security Annotations** (`@PreAuthorize`)

---

## **6. Security Misconfiguration**

### **Penetration Testing Steps**
   - **Step 1: Test for Exposed Services**: Check if default or development services are exposed in production.
   - **Step 2: Test for Missing Security Headers**: Check for missing security-related HTTP headers like `X-Content-Type-Options`.

### **Example of a Flaw**:
   - **Example**: Exposing development configurations and services in production.

```properties
# application.properties (development)
server.port=8080
spring.devtools.restart.enabled=true
```

#### **Remediation**:
   - **Use Profiles for Configuration**: Disable development features in production.

```properties
# application-prod.properties
spring.devtools.restart.enabled=false
server.port=8080
```

   - **Libraries to Fix**:
     - **Spring Profiles** (for environment-specific configurations)
     - **Spring Security** (for securing endpoints)

---

## **7. Cross-Site Scripting (XSS)**

### **Penetration Testing Steps**
   - **Step 1: Inject Payloads**: Test input fields and URL parameters with malicious payloads like `<script>alert('XSS')</script>`.
   - **Step 2: Check Stored vs. Reflected XSS**: Check if the payload is stored on the server (stored XSS) or executed directly (reflected XSS).

### **Example of a Flaw**:
   - **Example**: Directly rendering user input without sanitizing it.

```java
@GetMapping("/user-profile")
public String getUserProfile(@RequestParam String username) {
    return "<h1>Welcome, " + username + "!</h1>";  // Vulnerable to XSS
}
```

#### **Remediation**:
   - **Sanitize User Input**: Use **Spring's HTML escaping** to sanitize input.

```java
@GetMapping("/user-profile")
public String getUserProfile(@RequestParam String username) {
    String sanitizedUsername = StringEscapeUtils.escapeHtml4(username);  // Sanitize input
    return "<h1>Welcome, " + sanitizedUsername + "!</h1>";
}
```

   - **Use Thymeleaf for Automatic HTML Escaping**:

```html
<p>Welcome, <span th:text="${username}"></span>!</p>
```

   - **Libraries to Fix**:
     - **Spring Security** (for escaping HTML)
     - **OWASP Java HTML Sanitizer** (to sanitize HTML input)
     - **Thymeleaf** (for automatic escaping)

---

## **8. Insecure Deserialization**

### **Penetration Testing Steps**
   - **Step 1: Inspect Serialized Data**: Look for deserialization vulnerabilities in HTTP requests or stored data.
   - **Step 2: Modify Serialized Objects**: Use tools like **ysoserial** to inject malicious payloads.

### **Example of a Flaw**:
   - **Example**: Deserialization of untrusted data.

```java
public class MyController {

    @PostMapping("/deserialize-object")
    public String deserializeObject(@RequestBody String objectData) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(objectData.getBytes()));
        MyObject obj = (MyObject) ois.readObject();  // Insecure deserialization
        return "Deserialized object: " + obj.toString();
    }
}
```

#### **Remediation**:
   - **Use JSON or XML**: Replace native Java serialization with safer formats like **JSON** or **XML**.

```java
public class MyController {

    @PostMapping("/deserialize-object")
    public String deserializeObject(@RequestBody String objectData) throws IOException {
        MyObject obj = objectMapper.readValue(objectData, MyObject.class);  // Use Jackson for JSON deserialization
        return "Deserialized object: " + obj.toString();
    }
}
```

   - **Libraries to Fix**:
     - **Jackson** (for safe JSON deserialization)
     - **Apache Commons Lang** (for better handling of serialization and reflection)

---

## **9. Using Components with Known Vulnerabilities**

### **Penetration Testing Steps**
   - **Step 1: Identify Outdated Dependencies**: Use tools like **Snyk** or **OWASP Dependency-Check** to identify known vulnerabilities in third-party libraries.
   - **Step 2: Test for Exploits**: Test older versions of frameworks like **Spring** or **Apache Struts** that might have known **CVE vulnerabilities**.

### **Example of a Flaw**:
   - **Example**: Using an outdated version of **Spring** with known vulnerabilities.

```xml
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-core</artifactId>
    <version>3.0.0</version> <!-- Vulnerable version -->
</dependency>
```

#### **Remediation**:
   - **Regularly Update Dependencies**: Keep dependencies up to date with the latest stable versions.

```xml
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-core</artifactId>
    <version>5.2.0</version> <!-- Updated version -->
</dependency>
```

   - **Libraries to Fix**:
     - **OWASP Dependency-Check** (for checking CVEs in dependencies)
     - **Snyk** (for continuous monitoring and patching of dependencies)

---

## **10. Insufficient Logging & Monitoring**

### **Penetration Testing Steps**
   - **Step 1: Check for Logging of Sensitive Actions**: Ensure that important events like login attempts, access to sensitive data, and role changes are logged.
   - **Step 2: Test for Alerts**: Simulate suspicious activity and check if the system raises alerts or logs these events.

### **Example of a Flaw**:
   - **Example**: Not logging failed login attempts or suspicious activities.

```java
public void logIn(String username, String password) {
    if (username.equals("admin") && password.equals("admin123")) {
        // User logged in successfully
    }
    // No logging for failed attempts
}
```

#### **Remediation**:
   - **Enable Logging**: Ensure that **failed login attempts** and other suspicious activities are logged.

```java
public void logIn(String username, String password) {
    if (username.equals("admin") && password.equals("admin123")) {
        logger.info("User " + username + " logged in successfully.");
    } else {
        logger.warn("Failed login attempt for user " + username);
    }
}
```

   - **Libraries to Fix**:
     - **SLF4J** (for logging)
     - **Logback** (for logging configuration)
     - **Splunk** or **ELK Stack** (for centralized log monitoring)

---

