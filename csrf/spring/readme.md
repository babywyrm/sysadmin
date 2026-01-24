# CSRF Lab Controller ..beta..

A comprehensive educational platform for demonstrating Cross-Site Request 
Forgery (CSRF) attacks in controlled lab environments.

⚠️ **WARNING: Educational Use Only** - This tool is designed ONLY for 
authorized security testing and education in controlled environments.

---

## Table of Contents

- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Detailed Setup](#detailed-setup)
- [Features](#features)
- [Usage Guide](#usage-guide)
- [Educational Scenarios](#educational-scenarios)
- [API Documentation](#api-documentation)

---

## Project Structure

```
csrf-lab-controller/
│
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── lab/
│   │   │           └── csrf/
│   │   │               ├── CsrfLabController.java
│   │   │               │   # Main Spring Boot application class
│   │   │               │   # Configures CORS and starts the server
│   │   │               │
│   │   │               ├── controller/
│   │   │               │   └── PayloadController.java
│   │   │               │       # REST endpoints for campaigns,
│   │   │               │       # payloads, and captures
│   │   │               │
│   │   │               ├── service/
│   │   │               │   └── CampaignService.java
│   │   │               │       # Business logic for campaign
│   │   │               │       # management and statistics
│   │   │               │
│   │   │               └── model/
│   │   │                   ├── Campaign.java
│   │   │                   │   # Campaign entity and config
│   │   │                   ├── CaptureData.java
│   │   │                   │   # Captured data from victims
│   │   │                   └── [Other model classes from above]
│   │   │
│   │   └── resources/
│   │       ├── application.properties
│   │       │   # Spring Boot configuration
│   │       │
│   │       ├── templates/
│   │       │   ├── dashboard.html
│   │       │   │   # Main control panel interface
│   │       │   │
│   │       │   ├── payload-post.html
│   │       │   │   # POST-based CSRF payload template
│   │       │   │
│   │       │   ├── payload-get.html
│   │       │   │   # GET-based CSRF payload template
│   │       │   │
│   │       │   ├── payload-json.html
│   │       │   │   # JSON/XHR-based CSRF payload template
│   │       │   │
│   │       │   ├── payload-xhr.html
│   │       │   │   # PUT/DELETE CSRF payload template
│   │       │   │
│   │       │   ├── captures.html
│   │       │   │   # View captured data for a campaign
│   │       │   │
│   │       │   ├── test-target.html
│   │       │   │   # Demo vulnerable/protected forms
│   │       │   │
│   │       │   └── index.html
│   │       │       # Landing page (optional)
│   │       │
│   │       └── static/
│   │           └── (CSS/JS files if separated)
│   │
│   └── test/
│       └── java/
│           └── com/
│               └── lab/
│                   └── csrf/
│                       └── [Test files]
│
├── pom.xml
│   # Maven dependencies and build configuration
│
├── README.md
│   # This file
│
└── .gitignore
    # Git ignore patterns
```

---

## Prerequisites

- **Java Development Kit (JDK) 17 or higher**
  - Download from: https://adoptium.net/
  - Verify: `java -version`

- **Maven 3.6+** (or use Maven Wrapper included)
  - Download from: https://maven.apache.org/download.cgi
  - Verify: `mvn -version`

- **IDE (Optional but recommended)**
  - IntelliJ IDEA Community Edition
  - Eclipse
  - VS Code with Java extensions

---

## Quick Start

### Option 1: Using Maven Wrapper (Recommended)

```bash
# Clone or create the project directory
mkdir csrf-lab-controller
cd csrf-lab-controller

# Create all necessary files (follow structure above)

# Run the application
./mvnw spring-boot:run

# On Windows:
mvnw.cmd spring-boot:run
```

### Option 2: Using Maven

```bash
# Build the project
mvn clean install

# Run the application
mvn spring-boot:run
```

### Option 3: Run as JAR

```bash
# Build the JAR
mvn clean package

# Run the JAR
java -jar target/csrf-lab-controller-1.0.0.jar
```

The application will start on http://localhost:8080

---

## Detailed Setup

### Step 1: Create Project Structure

**Using Maven Archetype:**

```bash
mvn archetype:generate \
  -DgroupId=com.lab.csrf \
  -DartifactId=csrf-lab-controller \
  -DarchetypeArtifactId=maven-archetype-quickstart \
  -DinteractiveMode=false

cd csrf-lab-controller
```

**Or manually create the directory structure shown above.**

### Step 2: Configure pom.xml

Create/edit `pom.xml` in the project root:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.lab.csrf</groupId>
    <artifactId>csrf-lab-controller</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>

    <name>CSRF Lab Controller</name>
    <description>Educational platform for CSRF demonstrations</description>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.0</version>
        <relativePath/>
    </parent>

    <properties>
        <java.version>17</java.version>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <!-- Spring Boot Web (includes Tomcat) -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <!-- Thymeleaf Template Engine -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>

        <!-- Spring Boot DevTools (auto-reload during development) -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-devtools</artifactId>
            <scope>runtime</scope>
            <optional>true</optional>
        </dependency>

        <!-- Spring Boot Test -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

### Step 3: Configure Application Properties

Create `src/main/resources/application.properties`:

```properties
# Application name
spring.application.name=CSRF Lab Controller

# Server configuration
server.port=8080
server.compression.enabled=true

# Thymeleaf configuration
spring.thymeleaf.cache=false
spring.thymeleaf.prefix=classpath:/templates/
spring.thymeleaf.suffix=.html

# Logging
logging.level.root=INFO
logging.level.com.lab.csrf=DEBUG

# Jackson JSON configuration
spring.jackson.serialization.indent-output=true
spring.jackson.serialization.write-dates-as-timestamps=false

# File upload (if needed for future features)
spring.servlet.multipart.max-file-size=10MB
spring.servlet.multipart.max-request-size=10MB
```

### Step 4: Create Java Source Files

Create each Java file in the appropriate package directory:

1. **Main Application** - `src/main/java/com/lab/csrf/CsrfLabController.java`
   - Copy the main application class from the previous response

2. **Controller** - `src/main/java/com/lab/csrf/controller/PayloadController.java`
   - Copy the PayloadController class

3. **Service** - `src/main/java/com/lab/csrf/service/CampaignService.java`
   - Copy the CampaignService class

4. **Models** - `src/main/java/com/lab/csrf/model/`
   - Create `Campaign.java` with all nested classes
   - Create `CaptureData.java` with nested classes
   - Create `CampaignRequest.java`
   - Create `CampaignExport.java`

### Step 5: Create HTML Templates

Create each HTML file in `src/main/resources/templates/`:

1. `dashboard.html` - Main control panel
2. `payload-post.html` - POST CSRF payload
3. `payload-get.html` - GET CSRF payload
4. `payload-json.html` - JSON CSRF payload
5. `payload-xhr.html` - XHR-based payload (create similar to payload-json)
6. `captures.html` - Capture viewer (create below)
7. `test-target.html` - Demo target (create below)

### Step 6: Create Additional Templates

**captures.html:**

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Captures - CSRF Lab</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            padding: 20px;
            background: #f5f5f5;
        }
        .header {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .capture-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .timestamp {
            color: #666;
            font-size: 14px;
        }
        pre {
            background: #f5f5f5;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }
        .back-btn {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Captured Data</h1>
        <p>Campaign: <strong th:text="${campaign.name}">Campaign Name</strong></p>
        <a href="/" class="back-btn">← Back to Dashboard</a>
    </div>

    <div class="statistics">
        <h2>Statistics</h2>
        <p>Total Captures: <strong th:text="${statistics.captureCount}">0</strong></p>
        <p>Success Rate: <strong th:text="${statistics.successRate}">0%</strong></p>
    </div>

    <h2>Capture Log</h2>
    
    <div th:if="${#lists.isEmpty(captures)}">
        <p>No captures yet.</p>
    </div>
    
    <div th:each="capture : ${captures}" class="capture-card">
        <div class="timestamp" 
             th:text="${#dates.format(new java.util.Date(capture.serverTimestamp), 
             'yyyy-MM-dd HH:mm:ss')}">
            Timestamp
        </div>
        
        <h3>Browser Information</h3>
        <p><strong>User Agent:</strong> <span th:text="${capture.userAgent}">UA</span></p>
        <p><strong>Referer:</strong> <span th:text="${capture.referer}">None</span></p>
        
        <h3>Metadata</h3>
        <pre th:text="${capture.browserMetadata}">Metadata</pre>
        
        <h3>Custom Data</h3>
        <pre th:text="${capture.customData}">Custom Data</pre>
        
        <h3>Cookies</h3>
        <pre th:text="${capture.cookies ?: 'None'}">Cookies</pre>
    </div>
</body>
</html>
```

**test-target.html:**

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Test Target - Vulnerable Form</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .warning {
            background: #fff3cd;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
        }
        .protected {
            background: #d4edda;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            padding: 12px 24px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background: #5568d3;
        }
        .token-display {
            background: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Bank Transfer Form</h1>
        
        <div th:if="${protected}" class="protected">
            <strong>✅ CSRF Protection Enabled</strong><br>
            This form includes a CSRF token and is protected against attacks.
        </div>
        
        <div th:unless="${protected}" class="warning">
            <strong>⚠️ WARNING: No CSRF Protection</strong><br>
            This form is vulnerable to CSRF attacks for demonstration purposes.
        </div>
        
        <form method="POST" action="/test-target/submit">
            <div class="form-group">
                <label>Recipient Account:</label>
                <input type="text" name="to" placeholder="account@example.com" required>
            </div>
            
            <div class="form-group">
                <label>Amount:</label>
                <input type="number" name="amount" placeholder="0.00" step="0.01" required>
            </div>
            
            <div th:if="${protected}" class="form-group">
                <label>CSRF Token:</label>
                <input type="hidden" name="csrfToken" th:value="${csrfToken}">
                <div class="token-display" th:text="${csrfToken}">token</div>
                <small>This token must match the server's expectation</small>
            </div>
            
            <button type="submit">Transfer Funds</button>
        </form>
        
        <hr style="margin: 30px 0;">
        
        <h2>Testing Instructions</h2>
        <ol>
            <li>Create a CSRF campaign targeting this form</li>
            <li>Set target URL to: <code>http://localhost:8080/test-target/submit</code></li>
            <li>Add parameters: <code>to=attacker@example.com</code> and <code>amount=1000</code></li>
            <li>Visit the payload URL while "logged in" to this page</li>
            <li>Observe the attack succeed (vulnerable) or fail (protected)</li>
        </ol>
        
        <a href="/">← Back to Dashboard</a>
    </div>
</body>
</html>
```

Add this endpoint to `PayloadController.java`:

```java
@PostMapping("/test-target/submit")
@ResponseBody
public ResponseEntity<Map<String, Object>> handleTestSubmit(
        @RequestParam String to,
        @RequestParam Double amount,
        @RequestParam(required = false) String csrfToken) {
    
    // Simulate CSRF token validation
    boolean hasValidToken = csrfToken != null && 
        !csrfToken.isEmpty();
    
    Map<String, Object> response = new HashMap<>();
    
    if (hasValidToken) {
        response.put("status", "success");
        response.put("message", 
            "Transfer of $" + amount + " to " + to + " completed");
        response.put("csrfProtection", "enabled");
    } else {
        response.put("status", "success");
        response.put("message", 
            "VULNERABLE: Transfer of $" + amount + " to " + to + 
            " completed WITHOUT CSRF protection!");
        response.put("csrfProtection", "disabled");
        response.put("warning", 
            "This request was processed without CSRF validation");
    }
    
    return ResponseEntity.ok(response);
}
```

### Step 7: Create .gitignore

Create `.gitignore` in project root:

```
# Maven
target/
pom.xml.tag
pom.xml.releaseBackup
pom.xml.versionsBackup
pom.xml.next
release.properties
dependency-reduced-pom.xml

# IDE
.idea/
*.iml
.vscode/
.settings/
.classpath
.project

# OS
.DS_Store
Thumbs.db

# Logs
*.log

# Application
application-local.properties
```

---

## Build and Run Checklist

- [ ] All Java files created in correct package structure
- [ ] All HTML templates created in `src/main/resources/templates/`
- [ ] `pom.xml` configured with all dependencies
- [ ] `application.properties` created
- [ ] Run `mvn clean install` successfully
- [ ] Start application with `mvn spring-boot:run`
- [ ] Access http://localhost:8080 in browser
- [ ] Create a test campaign
- [ ] Verify payload generation works
- [ ] Test capture functionality

---

## Features

### Campaign Management
- Create multiple CSRF campaigns with different configurations
- Track payloads served and successful captures
- View statistics and analytics
- Export campaign data

### Flexible Payload Generation
- **GET Requests**: Simple URL-based attacks
- **POST Requests**: Form-based attacks with hidden fields
- **JSON/XHR**: Modern API attacks
- **Custom Methods**: PUT, DELETE, etc.

### Capture & Analysis
- Browser fingerprinting
- Timing analysis
- Cookie exfiltration (where possible)
- Success/failure tracking

### Educational Features
- Side-by-side vulnerable and protected examples
- Inline documentation explaining attack vectors
- Statistics dashboard for analysis
- Test target forms

---

## Usage Guide

### Creating Your First Campaign

1. **Start the application** and navigate to http://localhost:8080

2. **Click the + button** to create a new campaign

3. **Fill in the form:**
   - **Name**: "Account Transfer Attack"
   - **Description**: "Demonstrates CSRF on a bank transfer form"
   - **Target URL**: `http://localhost:8080/test-target/submit`
   - **Method**: `POST`
   - **Parameters**:
     ```
     to=attacker@example.com
     amount=1000
     ```

4. **Click "Create Campaign"**

5. **Copy the payload URL** and open it in a new tab

6. **Observe the attack execute** and data captured

### Testing CSRF Protection

1. Navigate to http://localhost:8080/test-target?protected=true

2. Create a campaign targeting this protected form

3. Try to execute the attack - it should fail due to missing token

4. Compare with the unprotected version (?protected=false)

---
##
##
