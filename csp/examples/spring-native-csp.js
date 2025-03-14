/////////////////////////////////////////////////////////////////////////////////////

https://csplite.com/csp221/

/////////////////////////////////////////////////////////////////////////////////////

«How to publish Content Security Policy in Spring Boot with Spring Security, CSP headers in JHipster»
The  Spring framework is an open source universal framework for the Java platform, includes a web server "out of the box".

Spring Boot - a set of utilities that automate the configuration process and speed up the process of creating and deploying Spring applications in Java.

Spring Security is a Java/JavaEE framework that provides mechanisms for building authentication and authorization systems and other security capabilities for enterprise applications built with the Spring Framework.

Spring Security does not add Content Security Policy by default, because a reasonable default is impossible to know without context of the application. The web application developers must declare the security policy(s) to enforce and/or monitor for the protected resources.


Content Security Policy in Spring Boot

Native way to publish any HTTP headers, including CSP
Spring has a native way to publish any custom headers:

@EnableWebSecurity
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

   @Override
   protected void configure(HttpSecurity http) throws Exception {
     http
     // ...
     .headers()
       .contentSecurityPolicy().disable()      # because it's built into WebSecurity
       .addHeaderWriter( new StaticHeadersWriter ("Content-Security-Policy", "default-src 'self';"))
       .and()
       .addHeaderWriter( new StaticHeadersWriter ("Feature-Policy", "vibrate 'none'; geolocation 'self'"));
   }
}
Publishing Content Security Policy header using Spring Security
Spring Security has Servlet of Content Security Policy (CSP) with which the Content Security Policy header can be easily configured:

@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) {
        http
            // ...
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("script-src 'self' https://site.com; object-src https://site.com; report-uri /csp-report-endpoint/")
                )
            );
    }
}
A simplified CSP publish notation is also possible:

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers()
            .contentSecurityPolicy("script-src 'self' https://site.com; object-src https://site.com; report-uri /csp-report-endpoint/")
            .reportOnly();  // Set the Report-Only mode
    }
}
It should be noted that this way the CSP is published via the header. Publishing a policy via meta tag is usually straightforward, pls see details in Configuring Content Security Policy via <meta> tag and HTTP header.

After the CSP is published in one way or another, it is necessary to set up and debug the Content Security Policy.


Usage of 'nonce-value' with Spring Security
You can use 'nonce-<base64-value>' with Spring Security using built-in filters. For example, you can define a filter nonce CSP():

public class CSPNonceFilter extends GenericFilterBean {
  private static final int NONCE_SIZE = 32; //recommended is at least 128 bits/16 bytes
  private static final String CSP_NONCE_ATTRIBUTE = "cspNonce";

  private SecureRandom secureRandom = new SecureRandom();

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;

    byte[] nonceArray = new byte[NONCE_SIZE];

    secureRandom.nextBytes(nonceArray);

    String nonce = Base64.getEncoder().encodeToString(nonceArray);
    request.setAttribute(CSP_NONCE_ATTRIBUTE, nonce);

    chain.doFilter(request, new CSPNonceResponseWrapper(response, nonce));
    }
 
  /**
   * Wrapper to fill the nonce value
   */
  public static class CSPNonceResponseWrapper extends HttpServletResponseWrapper {
    private String nonce;

    public CSPNonceResponseWrapper(HttpServletResponse response, String nonce) {
      super(response);
      this.nonce = nonce;
      }
 
      @Override
      public void setHeader(String name, String value) {
        if (name.equals("Content-Security-Policy") && StringUtils.isNotBlank(value)) {
          super.setHeader(name, value.replace("{nonce}", nonce));
          }
        else {
          super.setHeader(name, value);
          }
        }
 
      @Override
      public void addHeader(String name, String value) {
        if (name.equals("Content-Security-Policy") && StringUtils.isNotBlank(value)) {
          super.addHeader(name, value.replace("{nonce}", nonce));
          }
        else {
          super.addHeader(name, value);
          }
        }
      }
  }
This filter is configuired in Spring Securiuty using: .addFilterBefore(new CSPNonceFilter(), HeaderWriterFilter.class).

Content Security Policy rules for script-src and style-src directives must contain the 'nonce-{nonce}' string, which will be replaced with a random 'nonce-value' on every request.

The nonce CSP() filter is installed before HeaderWriterFilter() so that it can wrap the response and intercept all calls to set headers, because after HeaderWriterFiilter(), usage of response.setHeader() will not work - response headers are already committed and overriding them will do nothing.

 

On pages where you need inline scripts or styles for some reason, you can use:

<script nonce="{{cspNonce}}"> ... </script>
see Content-Security-Policy Nonce with Spring Security for details.


CSP reports in Spring Boot
It is easier to use third-party services to handle violation reports of Content Security Policy in Spring Boot.

It is also possible to make your own report visualization using Java libraries: BIRT (The Business intelligence and Reporting Tools) or Jasper Report, see:

BIRT Reporting with Spring Boot

Spring Boot + Jasper Report + MySQL Database Example


CSP headers in JHipster (Spring Boot)
 JHipster is a free and open-source application generator used to quickly develop modern web applications and Microservices using Angular or React (JavaScript library) and the Spring Framework.

Starting like around Jhipster 5.0.x, the CSP headers property was added to security configuration. You can find it in the Project folder -> src -> main -> java -> package -> config -> SecurityConfiguration.java:

/************
Content Security policy Jhipster
**********/

   // Single line CSP  
.headers()
  .contentSecurityPolicy("default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline' www.google-analytics.com;")
            
   // Multi Line CSP joined by and
.headers()
  .contentSecurityPolicy("default-src 'self';")
  .and()
  .contentSecurityPolicy("script-src 'self' 'unsafe-eval' 'unsafe-inline' www.google-analytics.com;")


//////////////
/////////////
