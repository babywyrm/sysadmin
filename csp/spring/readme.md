
SPRING HEADERS

https://docs.spring.io/spring-security/site/docs/4.2.x/reference/html/headers.html#headers-csp

###############################
################################

20.1.5 X-Frame-Options
Allowing your website to be added to a frame can be a security issue. For example, using clever CSS styling users could be tricked into clicking on something that they were not intending (video demo). For example, a user that is logged into their bank might click a button that grants access to other users. This sort of attack is known as Clickjacking.

[Note]
Another modern approach to dealing with clickjacking is to use Section 20.1.7, “Content Security Policy (CSP)”.

There are a number ways to mitigate clickjacking attacks. For example, to protect legacy browsers from clickjacking attacks you can use frame breaking code. While not perfect, the frame breaking code is the best you can do for the legacy browsers.

A more modern approach to address clickjacking is to use X-Frame-Options header:

X-Frame-Options: DENY
The X-Frame-Options response header instructs the browser to prevent any site with this header in the response from being rendered within a frame. By default, Spring Security disables rendering within an iframe.

You can customize X-Frame-Options with the frame-options element. For example, the following will instruct Spring Security to use "X-Frame-Options: SAMEORIGIN" which allows iframes within the same domain:

<http>
	<!-- ... -->

	<headers>
		<frame-options
		policy="SAMEORIGIN" />
	</headers>
</http>
Similarly, you can customize frame options to use the same origin within Java Configuration using the following:

@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
	http
	// ...
	.headers()
		.frameOptions()
			.sameOrigin();
}
}
20.1.6 X-XSS-Protection
Some browsers have built in support for filtering out reflected XSS attacks. This is by no means foolproof, but does assist in XSS protection.

The filtering is typically enabled by default, so adding the header typically just ensures it is enabled and instructs the browser what to do when a XSS attack is detected. For example, the filter might try to change the content in the least invasive way to still render everything. At times, this type of replacement can become a XSS vulnerability in itself. Instead, it is best to block the content rather than attempt to fix it. To do this we can add the following header:

X-XSS-Protection: 1; mode=block
This header is included by default. However, we can customize it if we wanted. For example:

<http>
	<!-- ... -->

	<headers>
		<xss-protection block="false"/>
	</headers>
</http>
Similarly, you can customize XSS protection within Java Configuration with the following:

@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
	http
	// ...
	.headers()
		.xssProtection()
			.block(false);
}
}
20.1.7 Content Security Policy (CSP)
Content Security Policy (CSP) is a mechanism that web applications can leverage to mitigate content injection vulnerabilities, such as cross-site scripting (XSS). CSP is a declarative policy that provides a facility for web application authors to declare and ultimately inform the client (user-agent) about the sources from which the web application expects to load resources.

[Note]
Content Security Policy is not intended to solve all content injection vulnerabilities. Instead, CSP can be leveraged to help reduce the harm caused by content injection attacks. As a first line of defense, web application authors should validate their input and encode their output.

A web application may employ the use of CSP by including one of the following HTTP headers in the response:

Content-Security-Policy
Content-Security-Policy-Report-Only
Each of these headers are used as a mechanism to deliver a security policy to the client. A security policy contains a set of security policy directives (for example, script-src and object-src), each responsible for declaring the restrictions for a particular resource representation.

For example, a web application can declare that it expects to load scripts from specific, trusted sources, by including the following header in the response:

Content-Security-Policy: script-src https://trustedscripts.example.com
An attempt to load a script from another source other than what is declared in the script-src directive will be blocked by the user-agent. Additionally, if the report-uri directive is declared in the security policy, then the violation will be reported by the user-agent to the declared URL.

For example, if a web application violates the declared security policy, the following response header will instruct the user-agent to send violation reports to the URL specified in the policy’s report-uri directive.

Content-Security-Policy: script-src https://trustedscripts.example.com; report-uri /csp-report-endpoint/
Violation reports are standard JSON structures that can be captured either by the web application’s own API or by a publicly hosted CSP violation reporting service, such as, REPORT-URI.

The Content-Security-Policy-Report-Only header provides the capability for web application authors and administrators to monitor security policies, rather than enforce them. This header is typically used when experimenting and/or developing security policies for a site. When a policy is deemed effective, it can be enforced by using the Content-Security-Policy header field instead.

Given the following response header, the policy declares that scripts may be loaded from one of two possible sources.

Content-Security-Policy-Report-Only: script-src 'self' https://trustedscripts.example.com; report-uri /csp-report-endpoint/
If the site violates this policy, by attempting to load a script from evil.com, the user-agent will send a violation report to the declared URL specified by the report-uri directive, but still allow the violating resource to load nevertheless.

Configuring Content Security Policy
It’s important to note that Spring Security does not add Content Security Policy by default. The web application author must declare the security policy(s) to enforce and/or monitor for the protected resources.

For example, given the following security policy:

script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/
You can enable the CSP header using XML configuration with the <content-security-policy> element as shown below:

<http>
	<!-- ... -->

	<headers>
		<content-security-policy
			policy-directives="script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/" />
	</headers>
</http>
To enable the CSP 'report-only' header, configure the element as follows:

<http>
	<!-- ... -->

	<headers>
		<content-security-policy
			policy-directives="script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/"
			report-only="true" />
	</headers>
</http>
Similarly, you can enable the CSP header using Java configuration as shown below:

@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
	http
	// ...
	.headers()
		.contentSecurityPolicy("script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/");
}
}
To enable the CSP 'report-only' header, provide the following Java configuration:

@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
	http
	// ...
	.headers()
		.contentSecurityPolicy("script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/")
		.reportOnly();
}
}
Additional Resources
Applying Content Security Policy to a web application is often a non-trivial undertaking. The following resources may provide further assistance in developing effective security policies for your site.

An Introduction to Content Security Policy

CSP Guide - Mozilla Developer Network

W3C Candidate Recommendation

20.1.8 Referrer Policy
Referrer Policy is a mechanism that web applications can leverage to manage the referrer field, which contains the last page the user was on.

Spring Security’s approach is to use Referrer Policy header, which provides different policies:

Referrer-Policy: same-origin
The Referrer-Policy response header instructs the browser to let the destination knows the source where the user was previously.

Configuring Referrer Policy
Spring Security doesn’t add Referrer Policy header by default.

You can enable the Referrer-Policy header using XML configuration with the <referrer-policy> element as shown below:

<http>
	<!-- ... -->

	<headers>
		<referrer-policy policy="same-origin" />
	</headers>
</http>
Similarly, you can enable the Referrer Policy header using Java configuration as shown below:

@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
	http
	// ...
	.headers()
		.referrerPolicy(ReferrerPolicy.SAME_ORIGIN);
}
}
20.2 Custom Headers
Spring Security has mechanisms to make it convenient to add the more common security headers to your application. However, it also provides hooks to enable adding custom headers.

20.2.1 Static Headers
There may be times you wish to inject custom security headers into your application that are not supported out of the box. For example, given the following custom security header:

X-Custom-Security-Header: header-value
When using the XML namespace, these headers can be added to the response using the <header> element as shown below:

<http>
	<!-- ... -->

	<headers>
		<header name="X-Custom-Security-Header" value="header-value"/>
	</headers>
</http>
Similarly, the headers could be added to the response using Java Configuration as shown in the following:

@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
	http
	// ...
	.headers()
		.addHeaderWriter(new StaticHeadersWriter("X-Custom-Security-Header","header-value"));
}
}
