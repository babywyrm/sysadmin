##
#
https://github.com/spring-projects/spring-security/issues/13738
#
##

Spring Security 6 CSRF Token Accepting Random Tokens #13738
Closed
kkcodes opened this issue on Aug 24, 2023 · 1 comment
Comments
@kkcodes
kkcodes commented on Aug 24, 2023 • 
Using Spring Boot 3.1.2
Using Spring Boot Starter Security

Describe the bug
When I am passing any random csrf token as shown below in the image in postman, this is accepting the csrf token but my understanding is that it should fail. In the image, I am passing this as XSRF-TOKEN in Cookie and X-Xsrf-Token in header.

image
To Reproduce
I am currently working with Spring Boot 3.1.2 and working on Microservice Architecuture. I am currently working with JWT with Stateless session and CSRF Token. I have an API Gateway using Spring Cloud Gateway and it calls the Identity Service and inside the Identity Service Spring Security package is used. Below is the code for SecurityFilterChain present in Identity Service

Using ReactJS on the Frontend. So, will be storing the JWT in Cookie with HttpOny; Secure; and hence need to enable CSRF Protection.

@configuration
@EnableWebSecurity
public class AuthConfig {

@Autowired
private MobileOtpAuthenticationProvider mobileOtpAuthenticationProvider;

@Autowired
private JwtAuthenticationFilter jwtAuthenticationFilter;

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {


    XorCsrfTokenRequestAttributeHandler delegate = new XorCsrfTokenRequestAttributeHandler();

    delegate.setCsrfRequestAttributeName("_csrf");
    CsrfTokenRequestHandler
            requestHandler = delegate::handle;


    return http
            .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())

                            .csrfTokenRequestHandler(requestHandler)

            )
            .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
                authorizationManagerRequestMatcherRegistry.requestMatchers(
                        "/api/auth/v1/verify-otp", "/api/auth/v1/csrf-token")
                        .permitAll();
                authorizationManagerRequestMatcherRegistry.anyRequest().authenticated();
            })
            .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(exceptions -> {
                exceptions.authenticationEntryPoint(new ServerAuthenticationEntryPoint());
            })
            .cors(Customizer.withDefaults())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .build();

}

@Bean
AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
    AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);

    authenticationManagerBuilder.authenticationProvider(mobileOtpAuthenticationProvider);

    return authenticationManagerBuilder.build();
}

@Bean
CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();

    configuration.addAllowedOrigin("http://localhost:3000");
    configuration.setAllowedHeaders(List.of("*"));
    configuration.setAllowedMethods(Arrays.asList(
            HttpMethod.GET,
            HttpMethod.POST,
            HttpMethod.HEAD,
            HttpMethod.OPTIONS,
            HttpMethod.PUT,
            HttpMethod.PATCH,
            HttpMethod.DELETE
    ));
    configuration.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);

    return source;
}
}

Expected behavior
Expected Behaviour that it should fail and give invalid csrf

@kkcodes kkcodes added status: waiting-for-triage type: bug labels on Aug 24, 2023
@sjohnr
Member
sjohnr commented on Aug 28, 2023
@kkcodes thanks for reaching out!

As per the docs:

The CookieCsrfTokenRepository writes to a cookie named XSRF-TOKEN and reads it from an HTTP request header named X-XSRF-TOKEN or the request parameter _csrf by default.

Your screenshot makes it clear that you have set both the Cookie and the header to the value "s", indicating that the token value is valid. Spring Security would normally set the cookie to a randomly generated value. Using a CookieCsrfTokenRepository involves tradeoffs discussed in the CSRF and Session Timeouts section of the reference documentation.

I'm going to close this issue given the above explanation. If you have any further questions, please be sure to open a question on stackoverflow and provide a link here (so that others can find it), and I'll be happy to take a look.


  
