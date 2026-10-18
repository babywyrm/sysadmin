Cross-Site Request Forgery (CSRF) is a type of attack that occurs when a malicious website, 
email, or program causes a user's web browser to perform an unwanted action on a trusted site for which the user is currently authenticated. 
Spring Security provides various ways to protect against CSRF attacks. 
Here are a few examples of how to implement CSRF protection with the latest Spring and Tomcat:

Example 1: Default CSRF Protection with Spring Security
By default, Spring Security includes CSRF protection. 
To enable it, simply ensure that Spring Security is on the classpath and is configured. Here's a basic configuration:

```
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().and()
            .authorizeRequests()
            .antMatchers("/public/**").permitAll()
            .anyRequest().authenticated();
    }
}
```


In this configuration, CSRF protection is enabled by default.
The .csrf() method call is not strictly necessary because CSRF protection is enabled automatically.

Example 2: Customizing CSRF Configuration
You can customize the CSRF protection behavior by configuring the CSRF token repository or the paths that are protected. For example:

```
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
            .authorizeRequests()
            .antMatchers("/public/**").permitAll()
            .anyRequest().authenticated();
    }
}
```



In this example, the CSRF token is stored in a cookie. 
The withHttpOnlyFalse() method makes the cookie accessible to client-side scripts, which may be necessary for some applications.

Example 3: Disabling CSRF Protection for Specific Paths
Sometimes, you might want to disable CSRF protection for specific paths, such as API endpoints that are used with stateless authentication 
(e.g., JWT). 
Here's how you can do it:

```
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
                .ignoringAntMatchers("/api/**")
                .and()
            .authorizeRequests()
            .antMatchers("/public/**").permitAll()
            .antMatchers("/api/**").permitAll()
            .anyRequest().authenticated();
    }
}
```


In this configuration, CSRF protection is disabled for all paths starting with /api/.

Example 4: Adding CSRF Protection to Forms
If you're using Thymeleaf or another template engine, you can easily include the CSRF token in your forms. Here's an example with Thymeleaf:

```
<form th:action="@{/process}" method="post">
    <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}" />
    <!-- other form fields -->
    <button type="submit">Submit</button>
</form>
```


Spring Security will automatically generate the _csrf attribute and make it available in the model for Thymeleaf templates.

Example 5: CSRF Protection with JavaScript
If you're working with AJAX requests, you need to include the CSRF token in the request headers. 
Here's an example using jQuery:



```
$(document).ready(function() {
    var token = $("meta[name='_csrf']").attr("content");
    var header = $("meta[name='_csrf_header']").attr("content");

    $(document).ajaxSend(function(e, xhr, options) {
        xhr.setRequestHeader(header, token);
    });
});
```


And in your HTML:

```
<meta name="_csrf" content="${_csrf.token}"/>
<meta name="_csrf_header" content="${_csrf.headerName}"/>
```


This setup ensures that every AJAX request includes the CSRF token in the headers.

By implementing one or more of these strategies, you can ensure that your Spring application is protected against CSRF attacks while running on Tomcat.



To implement CSRF protection using only headers for POST requests in a Spring Boot application, you can follow these steps:

Step 1: Enable CSRF Protection in Spring Security
Ensure that CSRF protection is enabled in your Spring Security configuration. 
You'll configure it to expect a CSRF token in the headers of POST requests.


```
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
            .authorizeRequests()
            .antMatchers("/public/**").permitAll()
            .anyRequest().authenticated();
    }
}
```


Step 2: Add CSRF Token to the Response Headers
When the user accesses the application, you need to provide the CSRF token in the response headers so that the client can include it in subsequent POST requests. You can achieve this by creating a filter that adds the CSRF token to the response.

```
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CsrfHeaderFilter extends OncePerRequestFilter {

    private final CsrfTokenRepository csrfTokenRepository;

    public CsrfHeaderFilter(CsrfTokenRepository csrfTokenRepository) {
        this.csrfTokenRepository = csrfTokenRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        CsrfToken csrfToken = csrfTokenRepository.loadToken(request);
        if (csrfToken == null) {
            csrfToken = csrfTokenRepository.generateToken(request);
            csrfTokenRepository.saveToken(csrfToken, request, response);
        }
        response.setHeader("X-CSRF-TOKEN", csrfToken.getToken());

        filterChain.doFilter(request, response);
    }
}
```

Register the filter in your Spring Security configuration:

```
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
                .csrfTokenRepository(cookieCsrfTokenRepository())
                .and()
            .addFilterAfter(new CsrfHeaderFilter(cookieCsrfTokenRepository()), CsrfHeaderFilter.class)
            .authorizeRequests()
            .antMatchers("/public/**").permitAll()
            .anyRequest().authenticated();
    }

    @Bean
    public CsrfTokenRepository cookieCsrfTokenRepository() {
        return CookieCsrfTokenRepository.withHttpOnlyFalse();
    }
}
```

Step 3: Include the CSRF Token in POST Requests
On the client side, you need to include the CSRF token in the headers of your POST requests. Here is an example using JavaScript (Fetch API):

```
document.addEventListener('DOMContentLoaded', function () {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    document.getElementById('postButton').addEventListener('click', function () {
        fetch('/your-endpoint', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': csrfToken
            },
            body: JSON.stringify({
                // Your POST data here
            })
        }).then(response => response.json())
          .then(data => console.log(data))
          .catch(error => console.error('Error:', error));
    });
});
```
Make sure to include the CSRF token in your HTML as a meta tag:

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="csrf-token" content="${_csrf.token}">
    <title>CSRF Protection Example</title>
</head>
<body>
    <button id="postButton">Send POST Request</button>
    <script src="your-script.js"></script>
</body>
</html>
```

Enable CSRF protection in Spring Security and configure it to use a CookieCsrfTokenRepository.
Create a filter to add the CSRF token to the response headers.
Include the CSRF token in the headers of your POST requests from the client side.

By following these steps, you can ensure that your Spring application is protected against CSRF attacks using only headers for POST requests.
