# Java And Spring Secure Review

This directory is for Java and Spring secure code review notes. The broad
multi-language static-analysis catalog now lives at `appsec/static-analysis/`.

## Review Goals

Use this checklist to review Java/Spring services for common implementation
risks before relying on tool output alone.

Focus on:

- injection and unsafe query construction
- unsafe templating or output encoding gaps
- authentication and session management errors
- authorization and object-level access control mistakes
- unsafe deserialization and parser exposure
- cryptography and secret-handling mistakes
- dependency and build configuration risk
- logging, error handling, and data exposure

## Manual Review Checklist

### Input And Injection

- Prefer parameterized queries, JPA criteria APIs, or trusted query builders over
  string concatenation.
- Check native SQL, JPQL, LDAP, XPath, OS command, SpEL, template, and NoSQL
  callsites.
- Treat file paths, archive names, headers, and JSON fields as attacker input
  unless proven otherwise.

### XSS And Output Encoding

- Confirm server-rendered templates use context-aware encoding.
- Review any `th:utext`, raw HTML helpers, Markdown rendering, or custom JSON to
  HTML conversion.
- Check reflected values in errors, redirects, search pages, admin panels, and
  debug views.

### Authentication And Sessions

- Confirm password storage uses a modern adaptive hash such as bcrypt, scrypt, or
  Argon2.
- Review session fixation protection, cookie flags, remember-me tokens, and login
  throttling.
- Check OAuth/OIDC client validation, redirect URI handling, nonce/state usage,
  and token audience/issuer checks.

### Authorization

- Review controller, service, and repository boundaries for missing object-level
  checks.
- Confirm admin-only methods are not protected only by UI visibility.
- Look for mass assignment, hidden field trust, tenant ID trust, and user ID trust
  in request bodies.

### Deserialization And Parsers

- Avoid Java native deserialization for untrusted input.
- Review Jackson default typing, XML external entity settings, YAML object
  construction, and polymorphic binders.
- Check upload, import, webhook, and message-consumer paths.

### Crypto, Secrets, And Configuration

- Do not hardcode credentials, API keys, private keys, salts, or production URLs.
- Prefer managed secret stores and short-lived credentials.
- Check TLS validation, random number generation, key lengths, and deprecated
  algorithms.

### Logging And Error Handling

- Avoid logging secrets, tokens, session IDs, authorization headers, and raw PII.
- Check exception handlers for stack traces or internal data returned to users.
- Ensure security decisions are logged without leaking sensitive values.

## Tooling

Use tools as coverage, not as the entire review.

| Tool | Best for |
|---|---|
| SonarQube or SonarLint | Broad quality/security rules and trend tracking. |
| SpotBugs with Find Security Bugs | Bug patterns, injection, crypto, and web risks. |
| PMD | Code smells and common implementation mistakes. |
| Checkstyle | Style and convention enforcement. |
| Spotless | Formatting consistency. |
| OWASP Dependency-Check or equivalent SCA | Dependency CVE visibility. |
| Semgrep | Custom rules and framework-specific checks. |

## Maven Examples

Checkstyle:

```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-checkstyle-plugin</artifactId>
  <version>3.1.2</version>
  <configuration>
    <consoleOutput>true</consoleOutput>
    <failOnError>true</failOnError>
  </configuration>
</plugin>
```

SpotBugs:

```xml
<plugin>
  <groupId>com.github.spotbugs</groupId>
  <artifactId>spotbugs-maven-plugin</artifactId>
  <version>4.5.3.0</version>
</plugin>
```

PMD:

```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-pmd-plugin</artifactId>
  <version>3.16.0</version>
</plugin>
```

## Review Output Format

Record findings with:

- affected component
- vulnerability class
- exploitability notes
- evidence path or code reference
- recommended fix
- test or verification step

Do not paste production secrets, tokens, customer data, or raw private endpoints
into review notes.
