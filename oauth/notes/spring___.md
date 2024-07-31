##
#
https://github.com/spring-projects/spring-security/issues/8668
#
https://stackoverflow.com/questions/77202711/spring-security-csrf-protection-and-jwt-based-authorization
#
https://www.geeksforgeeks.org/csrf-protection-in-spring-security/
#
##

A way to re-enable CSRF for OAuth2 bearer token requests #8668
Open
lightoze opened this issue on Jun 9, 2020 · 8 comments
Comments
@lightoze
lightoze commented on Jun 9, 2020
We have user-facing services which are accessed via OAuth2 proxy, so they are configured as resource server and bearer token is added to request headers by the proxy (from client session).

Currently OAuth2ResourceServerConfigurer.registerDefaultCsrfOverride is called unconditionally and it makes it impossible to use conventional CSRF configuration.

On reactive side there seems to be a solution (not tested though): when custom requireCsrfProtectionMatcher is specified, the override is not applied. Similar behaviour could be implemented for servlet security by introducing specifiedRequireCsrfProtectionMatcher flag on CsrfConfigurer.

@lightoze lightoze added status: waiting-for-triage type: enhancement labels on Jun 9, 2020
@jzheaux jzheaux self-assigned this on Jun 9, 2020
@jzheaux jzheaux added in: oauth2 and removed status: waiting-for-triage labels on Jun 9, 2020
@jzheaux
Contributor
jzheaux commented on Jun 9, 2020
Thanks for the report, @lightoze. Can you tell me more about your use case?

I'm asking because, since your proxy is the thing that has the client's session, I'd expect that to be where the CSRF token is generated/stored and where CSRF denials would be performed.

@lightoze
Author
lightoze commented on Jun 9, 2020
In this setup both the proxy and each individual service have their own session. When CSRF is to be used, each service will use it's own session. If we ever want to have cross-service requests possible (not likely at the moment) we'll implement custom shared token repository, but decision when to use CSRF and when not to will be still on individual service side.

@jzheaux
Contributor
jzheaux commented on Jun 10, 2020
Okay, thanks @lightoze for the extra background.

Similar behaviour could be implemented for servlet security by introducing specifiedRequireCsrfProtectionMatcher flag on CsrfConfigurer.

Perhaps, though I wonder if applications already setting requreCsrfProtectionMatcher would be surprised to see the ignore setting no longer getting applied.

I'll keep this ticket open while I continue to research ways to accommodate your use case. In the meantime, I believe it will work to set the matcher directly on the filter using an ObjectPostProcessor:

.csrf(csrf -> csrf
		.withObjectPostProcessor(new ObjectPostProcessor<CsrfFilter>() {
			@Override 
			public <O extends CsrfFilter> O postProcess(O object) {
				object.setRequireCsrfProtectionMatcher(CsrfFilter.DEFAULT_CSRF_MATCHER);
				return object;
			}
		})
	)
@lightoze
Author
lightoze commented on Jun 11, 2020
@jzheaux Thanks for the workaround!

@zokkr
zokkr commented on Nov 23, 2020
Hi @jzheaux
With my current project, I have a similar requirement:
I am not using the JWT in an authorization header, but instead (to have it in a secure place) I set it as HttpOnly and SameSite=Strict cookie and afterwards resolve it like this:

  public String cookieTokenExtractor(HttpServletRequest request) {
    String header = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (header != null) {
      return header.replace("Bearer ", "");
    }
    Cookie cookie = WebUtils.getCookie(request, "access_token");
    return cookie != null ? cookie.getValue() : null;
  }
This leads to the need of having csrf validation in place. I modified your workaround (thanks for that one!) a bit, so it doesn't unnecessarily check GET requests to this one:

        .csrf(csrf -> csrf
            .withObjectPostProcessor(new ObjectPostProcessor<CsrfFilter>() {
              @Override
              public <O extends CsrfFilter> O postProcess(O object) {
                object.setRequireCsrfProtectionMatcher(request -> {
                  try {
                    return cookieTokenExtractor(request) != null;
                  }
                  catch (OAuth2AuthenticationException ex) {
                    return false;
                  }
                });
                return object;
              }
            })
        )
but basically reimplementing the BearerTokenRequestMatcher really only feels like a workaround. It would be great to have a configuration option to enable csrf also for requests that contain a JWT. If it defaults to being disabled, existing users would not feel a disruption, too.

@jzheaux jzheaux mentioned this issue on Dec 2, 2020
Add Cookie-based Bearer Token support #9230
Open
@OtenMoten
OtenMoten commented on Aug 14, 2023 • 
Hi @jzheaux With my current project, I have a similar requirement: I am not using the JWT in an authorization header, but instead (to have it in a secure place) I set it as HttpOnly and SameSite=Strict cookie and afterwards resolve it like this:

  public String cookieTokenExtractor(HttpServletRequest request) {
    String header = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (header != null) {
      return header.replace("Bearer ", "");
    }
    Cookie cookie = WebUtils.getCookie(request, "access_token");
    return cookie != null ? cookie.getValue() : null;
  }
This leads to the need of having csrf validation in place. I modified your workaround (thanks for that one!) a bit, so it doesn't unnecessarily check GET requests to this one:

        .csrf(csrf -> csrf
            .withObjectPostProcessor(new ObjectPostProcessor<CsrfFilter>() {
              @Override
              public <O extends CsrfFilter> O postProcess(O object) {
                object.setRequireCsrfProtectionMatcher(request -> {
                  try {
                    return cookieTokenExtractor(request) != null;
                  }
                  catch (OAuth2AuthenticationException ex) {
                    return false;
                  }
                });
                return object;
              }
            })
        )
but basically reimplementing the BearerTokenRequestMatcher really only feels like a workaround. It would be great to have a configuration option to enable csrf also for requests that contain a JWT. If it defaults to being disabled, existing users would not feel a disruption, too.

TL;DR

In a stateful JWT environment, the need for CSRF protection is often reduced due to inherent features such as token storage in HttpOnly cookies, adherence to the same origin policy, use of the Bearer token scheme, and stateful JWT verification. Additional mechanisms such as the default CSRF countermeasures in modern browsers and proper implementation of CORS further mitigate the risk. While these factors together provide a robust defence against CSRF attacks, it is important to recognise that security is a multifaceted discipline.

Personal statement: There's no need for CSRF in a stateful environment.

Detailed explanation

Cross-Site Request Forgery (CSRF) is an attack that tricks the victim into submitting a malicious request. This attack is specifically designed to change the state of requests, not steal data, as the attacker has no way of seeing the response to the fraudulent request. In the context of web applications that use JWT (JSON Web Tokens) for session management, the need for CSRF protection may be questioned. Here's why CSRF may not be necessary in a stateful JWT environment:

Token storage: In a stateful JWT environment, tokens are typically stored in HttpOnly cookies, which are inaccessible to JavaScript. This means that, unlike regular cookies, a malicious script on another site can't automatically include the credentials in a request because it doesn't have access to the JWT.

Same origin policy: Web browsers enforce the Same Origin Policy (SOP), which prevents a malicious site from making requests to another site using the credentials of the user logged on to that site. Because the JWT is stored in an HttpOnly cookie, it is only sent to requests to the same origin, and a CSRF attack from a different origin won't include the token.

Use of the Bearer Token Scheme: JWTs are often sent as bearer tokens in the Authorisation header. In a CSRF attack, the malicious site cannot set custom headers on the request to another site, so it cannot include the Authorisation header needed to authenticate the request. This ensures that even if a user is tricked into performing an action on the authenticated site, the JWT won't be included in the request by the malicious site.

Stateful JWT validation: In a stateful JWT environment, the server keeps track of the tokens issued, often in a database, and validates the token against the stored data. An attacker does not have easy access to this stateful information, making it much more difficult to create a valid JWT for malicious purposes.

Potential CSRF countermeasures in modern browsers: Many modern browsers have started to implement default CSRF protection, such as the SameSite cookie attribute. Cookies set to SameSite=Strict or SameSite=Lax won't be sent with cross-site requests, further reducing the risk of CSRF attacks.

Lack of state-changing information in JWT: CSRF primarily targets state-changing actions. Since JWT is a means of transmitting user authentication information and doesn't inherently contain any state-changing commands or capabilities, it is not directly susceptible to CSRF attacks.

Potential use of CORS: Proper implementation of Cross-Origin Resource Sharing (CORS) policies ensures that only those domains explicitly allowed by the server can make requests. This in turn limits the ability of a malicious site to make a successful request.

As you can see, there are many mechanics which protecting against man-in-the-middle attacks when using a stateless environment. Thus, the need for CSRF is not present.

@ujhazib
ujhazib commented on Oct 2, 2023
The proposed workaround above has one minor flaw. In case of a CSRF token is invalid, the http status should be 403, but spring returns 401 in this case.

@jzheaux
Contributor
jzheaux commented on Dec 14, 2023 • 
I'd like to take a moment to refresh my understanding of the situation here. When the token is stored in a cookie or in the session, then Spring Security's default CSRF defense is needed and should not be shut off by resource server configuration.

There are a few ways that we could do this:

Stop overriding CSRF configuration, requiring the application to disable (not passive)
Add a flag to resource server configuration, something like OAuthResourceServerConfiguration#requireCsrf (passive, but mixes two concerns)
Add a flag to CSRF configuration that allows replacing any existing overrides with an overarching one, something like ignoringRequestMatchers(Consumer<List<RequestMatcher>> ignoringRequestMatchers) where the final list could be mutated or ignoreOnlyRequestMatcher(RequestMatcher) (passive)
Override only for known-good BearerTokenResolver instances, e.g. those that don't use the session, a cookie, or HTTP Basic to pass the token. (not passive)
Option 4 could be made passive possibly by introducing a sub-interface to BearerTokenResolver called UsesBrowserCredentialsBearerTokenResolver or by introducing a default method in BearerTokenResolver like usesBrowserCredentials that returns false by default (forgive the names).

The first three options leave it up to the application to decide, so I don't want to only do that. I currently like a combination of options 3 and 4 the best since option 3 still gives the application full control should it feel that Spring Security is making the wrong decision and option 4 passively makes ResourceServerConfigurer's decision-making a bit smarter while remaining passive.

