# **Web Application Security Testing Framework: Detailed OWASP Top 10 Focus** 
## (early 2025)

## **1. Injection (SQL, NoSQL, Command Injection)**

### **Penetration Testing Steps**
   - **Step 1: Identify User Inputs**: Start by identifying all user input fields such as login forms, search bars, and URL parameters.
   - **Step 2: Test with Common Payloads**:
     - For **SQL Injection**: Test with payloads like `' OR 1=1 --` or `' UNION SELECT null, username, password FROM users--`.
     - For **NoSQL Injection**: Test with `{ "$ne": null }` in MongoDB queries.
     - For **Command Injection**: Test with payloads like `; ls -la` or `&& whoami`.
   - **Step 3: Verify Error Messages**: If the application reveals database errors, this could indicate that the input is directly passed into a query.

### **Example of a Flaw**:
   - **Flaw**: The application allows SQL queries directly in the input field without sanitization.
   - **Example Payload**: `admin' OR 1=1 --`

   **Impact**: Unauthorized access to sensitive data or users' accounts.

### **Remediation**:
   - **Use Prepared Statements**: Implement parameterized queries or use ORM frameworks (e.g., **Hibernate**, **Django ORM**) to prevent direct injection.
   - **Input Validation**: Validate inputs to ensure that no special characters or query-related keywords are included.
   - **Error Handling**: Ensure that database errors are not exposed to the user. Use **generic error messages**.

### **Tools**:
   - [Burp Suite](https://portswigger.net/burp) – For manual testing and identifying SQL injection.
   - [SQLMap](http://sqlmap.org/) – Automated tool for SQL injection testing.
   - [OWASP ZAP](https://www.zaproxy.org/) – For scanning SQL injection and other vulnerabilities.

---

## **2. Broken Authentication**

### **Penetration Testing Steps**
   - **Step 1: Test for Brute Force**: Use **Hydra** or **Burp Suite Intruder** to attempt brute-forcing the login page.
   - **Step 2: Session Management Testing**: Test for **session fixation**, **session hijacking**, and **predictable session IDs**.
     - Try manipulating the session cookie values and see if you can impersonate another user.
   - **Step 3: Test for Weak Password Policies**: Check if weak passwords like `123456` or `password` are allowed.

### **Example of a Flaw**:
   - **Flaw**: The login page is vulnerable to brute-force attacks due to weak rate-limiting or a lack of CAPTCHA.
   - **Example Attack**: An attacker uses a tool like **Hydra** to repeatedly try common password combinations.

   **Impact**: An attacker could gain unauthorized access to user accounts.

### **Remediation**:
   - **Rate Limiting**: Implement **rate-limiting** on the login page to prevent brute force.
   - **Multi-Factor Authentication (MFA)**: Use MFA (e.g., **TOTP**, **SMS-based authentication**) to secure login.
   - **Session Fixation Protection**: Regenerate the session ID after login to prevent session fixation.
   - **Strong Password Policies**: Enforce strong passwords and limit the number of failed login attempts.

### **Tools**:
   - [Hydra](https://github.com/vanhauser-thc/thc-hydra) – For brute-forcing login attempts.
   - [Burp Suite](https://portswigger.net/burp) – For brute force and session manipulation testing.
   - [OWASP ZAP](https://www.zaproxy.org/) – To scan for broken authentication issues.

---

## **3. Sensitive Data Exposure**

### **Penetration Testing Steps**
   - **Step 1: Check for HTTPS**: Ensure that sensitive data is transmitted over **HTTPS** and not HTTP.
   - **Step 2: Test Data Encryption**: Ensure that sensitive data is encrypted both in transit and at rest.
   - **Step 3: Test for Insecure Data Storage**: Check if sensitive data like passwords, API keys, or tokens are stored insecurely in **plaintext**.

### **Example of a Flaw**:
   - **Flaw**: Sensitive data like **passwords** is being transmitted over **HTTP**.
   - **Example Payload**: A user submits their password on an unencrypted HTTP login form.

   **Impact**: Sensitive data is vulnerable to **Man-in-the-Middle (MITM)** attacks, exposing user credentials.

### **Remediation**:
   - **Force HTTPS**: Ensure **HTTPS** is enabled across all endpoints.
   - **Use Strong Encryption**: Encrypt sensitive data at rest using **AES-256** and use **TLS** (Transport Layer Security) for data in transit.
   - **Tokenization**: Use tokenization or **Hashing (e.g., bcrypt, Argon2)** for sensitive data like passwords.

### **Tools**:
   - [SSL Labs](https://www.ssllabs.com/ssltest/) – To test SSL/TLS configurations.
   - [OWASP ZAP](https://www.zaproxy.org/) – For automated security testing, including checking for sensitive data exposure.

---

## **4. XML External Entities (XXE)**

### **Penetration Testing Steps**
   - **Step 1: Identify XML Parsers**: Look for endpoints that accept **XML** input.
   - **Step 2: Test for XXE**: Send an XXE payload like `<!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "file:///etc/passwd">] >`.
   - **Step 3: Check for Information Disclosure**: Attempt to access internal files or services through the XXE payload.

### **Example of a Flaw**:
   - **Flaw**: The application accepts XML input and processes it insecurely, allowing external entity references.
   - **Example Payload**: `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd">] >`

   **Impact**: The attacker can access sensitive files like `/etc/passwd` or initiate **Denial of Service (DoS)** attacks.

### **Remediation**:
   - **Disable DTDs**: Disable **Document Type Definitions (DTD)** in XML parsers.
   - **Use Secure XML Parsers**: Ensure that XML libraries and parsers are configured securely (e.g., **JAXP**, **libxml2**).
   - **Input Validation**: Validate all XML input to ensure it cannot contain harmful entities.

### **Tools**:
   - [OWASP ZAP](https://www.zaproxy.org/) – For automated XXE vulnerability scanning.
   - [Burp Suite](https://portswigger.net/burp) – To manually test XXE and other injection flaws.

---

## **5. Broken Access Control**

### **Penetration Testing Steps**
   - **Step 1: Test URL Access Controls**: Try accessing URLs that belong to other users, such as `/admin`, `/profile/1234`, to see if the application enforces proper access control.
   - **Step 2: Test for Authorization Bypass**: Try manipulating the request parameters to access resources without proper permissions.
   - **Step 3: Test for API Access Control Issues**: Intercept API calls and check if unauthorized users can access endpoints they shouldn’t.

### **Example of a Flaw**:
   - **Flaw**: An attacker can access another user's profile by changing the user ID in the URL.
   - **Example Attack**: Accessing `/profile/5678` as `/profile/1234`.

   **Impact**: Users can access other users' data or administrative functionality.

### **Remediation**:
   - **Implement RBAC**: Ensure that **Role-Based Access Control (RBAC)** is enforced for both the UI and API endpoints.
   - **Use Server-Side Authorization**: Always perform authorization checks on the server, not just on the client-side.
   - **Least Privilege**: Apply the **least privilege principle** to all users and services.

### **Tools**:
   - [Burp Suite](https://portswigger.net/burp) – For testing broken access control via request interception and manipulation.
   - [OWASP ZAP](https://www.zaproxy.org/) – For automated scanning of access control issues.

---

## **6. Security Misconfiguration**

### **Penetration Testing Steps**
   - **Step 1: Identify Default Configurations**: Look for default configurations that should be modified, such as **default admin credentials**, **debugging enabled**, and **default ports**.
   - **Step 2: Test HTTP Headers**: Check for missing or weak HTTP headers like **Strict-Transport-Security**, **X-Content-Type-Options**, and **X-Frame-Options**.
   - **Step 3: Test for Open Ports**: Use tools like **Nmap** or **Masscan** to detect unnecessary open ports.

### **Example of a Flaw**:
   - **Flaw**: The application is running with default admin credentials or unnecessary services exposed.
   - **Example Attack**: An attacker exploits an exposed **admin** panel because of the default credentials.

   **Impact**: Unsecured admin panels or exposed services can lead to full system compromise.

### **Remediation**:
   - **Change Default Credentials**: Always change default credentials and disable unused services.
   - **Enable Security Headers**: Configure strong HTTP headers to prevent attacks like **clickjacking** or **XSS**.
   - **Remove Unnecessary Services**: Disable all non-essential services and ports.

### **Tools**:
   - [Nikto](https://github.com/sullo/nikto) – A web scanner that identifies misconfigurations.
   - [OWASP ZAP](https://www.zaproxy.org/) – To identify misconfigurations in HTTP headers.

---

## **7. Cross-Site Scripting (XSS)**

### **Penetration Testing Steps**
   - **Step 1: Test User Input**: Inject payloads like `<script>alert('XSS')</script>` into form fields, URL parameters, or cookies.
   - **Step 2: Test Stored vs. Reflected XSS**: Check if payloads are stored and then reflected in responses (stored XSS) or immediately executed in the response (reflected XSS).
   - **Step 3: Check for DOM-Based XSS**: Use tools like **Burp Suite** to intercept and modify client-side scripts that may lead to DOM-based XSS.

### **Example of a Flaw**:
   - **Flaw**: The application allows users to submit input that is not properly sanitized, leading to script execution.
   - **Example Payload**: `<script>alert('XSS')</script>`

   **Impact**: Malicious scripts can execute in a victim's browser, stealing cookies or performing actions on behalf of the user.

### **Remediation**:
   - **Input Sanitization**: Always sanitize and escape user input to prevent script injection.
   - **Content Security Policy (CSP)**: Use a strict **CSP** to block inline JavaScript and reduce the impact of XSS.
   - **Use HttpOnly Cookies**: Set the `HttpOnly` flag on session cookies to prevent JavaScript from accessing them.

### **Tools**:
   - [Burp Suite](https://portswigger.net/burp) – For testing XSS in web applications.
   - [OWASP ZAP](https://www.zaproxy.org/) – For automated XSS vulnerability scanning.
   - [XSStrike](https://github.com/s0md3v/XSStrike) – Advanced XSS detection and exploitation.

---

## **8. Insecure Deserialization**

### **Penetration Testing Steps**
   - **Step 1: Identify Deserialized Data**: Look for functions or endpoints that accept serialized objects. Common sources of serialized data are **HTTP cookies**, **REST APIs**, and **files**.
   - **Step 2: Manipulate Serialized Data**: Modify serialized objects and observe the application’s behavior. Use tools like **ysoserial** to generate payloads.
   - **Step 3: Test for Code Execution**: Check if modifying the serialized object leads to the execution of unintended code (e.g., **remote code execution**).

### **Example of a Flaw**:
   - **Flaw**: The application accepts and deserializes user-controlled data without any validation or checking, allowing attackers to inject malicious objects.
   - **Example Attack**: An attacker sends a modified object through the **HTTP cookie** to execute arbitrary code on the server.
   
   **Example Payload**: `ysoserial` payload that exploits the deserialization vulnerability to execute a command on the server.

   **Impact**: Remote Code Execution (RCE), unauthorized access to sensitive information, or privilege escalation.

### **Remediation**:
   - **Use Safe Serialization Libraries**: Use **JSON** or **XML** (with validation) instead of **Java serialization**.
   - **Signature Validation**: Ensure that serialized objects are **signed** to detect any tampering.
   - **Whitelist Valid Classes**: Implement a **whitelist** for acceptable classes to be deserialized.

### **Tools**:
   - [ysoserial](https://github.com/frohoff/ysoserial) – A tool to generate payloads for deserialization attacks.
   - [Burp Suite](https://portswigger.net/burp) – For manual testing of serialized objects in cookies or requests.
   - [OWASP ZAP](https://www.zaproxy.org/) – To test for insecure deserialization.

---

## **9. Using Components with Known Vulnerabilities**

### **Penetration Testing Steps**
   - **Step 1: Identify All Components**: Start by identifying all the **third-party libraries** and **frameworks** used by your application (e.g., Spring Boot, Apache Struts).
   - **Step 2: Check for Vulnerabilities**: Use tools like **OWASP Dependency-Check**, **Snyk**, or **Retire.js** to check for known vulnerabilities in components.
   - **Step 3: Check for Outdated Versions**: Ensure that all libraries and dependencies are up-to-date and patched for known vulnerabilities.

### **Example of a Flaw**:
   - **Flaw**: The application uses an outdated version of **Apache Struts** that contains a **remote code execution vulnerability** (CVE-2017-5638).
   - **Example Attack**: The attacker exploits the known vulnerability in the outdated **Struts** component to execute arbitrary code on the server.

   **Impact**: Remote Code Execution (RCE) in your application due to the use of outdated components.

### **Remediation**:
   - **Dependency Management**: Use **dependency management** tools to track and automatically update third-party libraries.
   - **Use SCA Tools**: Regularly scan for vulnerabilities in dependencies using tools like **Snyk**, **OWASP Dependency-Check**, or **Retire.js**.
   - **Patch Management**: Immediately apply **security patches** and upgrade to the latest stable versions of dependencies.

### **Tools**:
   - [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) – To identify known vulnerabilities in third-party libraries.
   - [Snyk](https://snyk.io/) – Continuously monitor and patch dependencies.
   - [Retire.js](https://github.com/rioscus/retire.js) – To find outdated JavaScript libraries with known vulnerabilities.

---

## **10. Insufficient Logging & Monitoring**

### **Penetration Testing Steps**
   - **Step 1: Check for Log Availability**: Ensure that security-related events, such as failed login attempts, privilege escalation, and unusual API calls, are logged.
   - **Step 2: Test for Alerting**: Simulate security events (e.g., brute-force login attempts) and check if appropriate **alerts** are triggered.
   - **Step 3: Check Log Integrity**: Ensure that logs are **immutable** and stored securely (e.g., use **WORM** or **SIEM** systems).

### **Example of a Flaw**:
   - **Flaw**: The application does not log failed login attempts or does not log any significant security events.
   - **Example Attack**: An attacker performs multiple brute-force login attempts, but the application doesn't log or alert on this behavior.
   
   **Impact**: Attackers can remain undetected while performing malicious activities like credential stuffing or privilege escalation.

### **Remediation**:
   - **Enable Comprehensive Logging**: Log all security-related events, including **failed logins**, **account changes**, and **access to sensitive data**.
   - **Integrate SIEM Solutions**: Use **Security Information and Event Management (SIEM)** systems to monitor logs and set up alerts for suspicious activities.
   - **Log Integrity**: Ensure logs are stored securely and are **tamper-proof** using methods like **WORM (Write Once, Read Many)**.

### **Tools**:
   - [Splunk](https://www.splunk.com/) – For centralized logging and monitoring.
   - [ELK Stack (Elasticsearch, Logstash, Kibana)](https://www.elastic.co/elk-stack) – For log aggregation, searching, and alerting.
   - [OSSEC](https://www.ossec.net/) – Host-based intrusion detection for log monitoring.

---

# **Summary: Remediation Strategy for All OWASP Top 10**

Here’s a brief overview of **how to remediate** each vulnerability:

| **Vulnerability**                 | **Remediation**                                                                                                                                                                  |
|-----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Injection**                      | Use **parameterized queries** or **ORMs**. Validate all inputs and sanitize data before passing it to the backend.                                                              |
| **Broken Authentication**         | Implement **rate-limiting**, use **multi-factor authentication (MFA)**, regenerate **session IDs** after login, and enforce strong password policies.                           |
| **Sensitive Data Exposure**       | Enforce **HTTPS**, encrypt sensitive data **at rest** and **in transit**, and use **strong encryption algorithms** (e.g., AES-256, TLS 1.2+).                                   |
| **XML External Entities (XXE)**   | Disable **DTDs** in XML parsers, use secure libraries, and validate all XML inputs to avoid external entity injections.                                                         |
| **Broken Access Control**         | Use **Role-Based Access Control (RBAC)**, implement **server-side authorization** checks, and enforce the **principle of least privilege**.                                    |
| **Security Misconfiguration**     | Change default credentials, disable unused ports/services, enable security headers like **Strict-Transport-Security** and **X-Content-Type-Options**.                         |
| **Cross-Site Scripting (XSS)**    | Use **Content Security Policy (CSP)**, **input sanitization**, and **output encoding** (e.g., **HTML escape**). Implement **HttpOnly** cookies.                               |
| **Insecure Deserialization**      | Avoid **Java serialization** and use safe alternatives like **JSON**. Implement **signature validation** for serialized objects.                                               |
| **Using Components with Known Vulnerabilities** | Regularly update libraries and dependencies, use **Software Composition Analysis (SCA)** tools, and apply **security patches** as soon as they are released.             |
| **Insufficient Logging & Monitoring** | Log all security events, use a **SIEM system** for real-time alerting, and ensure that logs are **immutable** and stored securely.                                              |

---

