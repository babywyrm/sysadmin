
##
#
https://github.com/oktadev/okta-oauth2-proxy-example
#
##


```
# Build image
FROM maven:3.8.5-amazoncorretto-17 as builder

COPY src /usr/src/app/src
COPY pom.xml /usr/src/app
WORKDIR /usr/src/app
RUN export ARTIFACT_ID=$(mvn org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate -Dexpression=project.artifactId -q -DforceStdout) \
    && mvn package \
    && mv target/${ARTIFACT_ID}-*.jar target/app.jar

# Run image
FROM amazoncorretto:17

COPY --from=builder /usr/src/app/target/app.jar /usr/app/app.jar
WORKDIR /usr/app
ENTRYPOINT ["java", "-jar", "app.jar"]
EXPOSE 8080


version: "3.7"

services:

  web-app:
    build: .

  oauth2-proxy:
    image: bitnami/oauth2-proxy:7.3.0
    depends_on:
      - redis
    command:
      - --http-address
      - 0.0.0.0:4180
    environment:
      OAUTH2_PROXY_EMAIL_DOMAINS: '*'
      OAUTH2_PROXY_PROVIDER: oidc
      OAUTH2_PROXY_PROVIDER_DISPLAY_NAME: Okta
      OAUTH2_PROXY_SKIP_PROVIDER_BUTTON: true
      OAUTH2_PROXY_REDIRECT_URL: http://localhost/oauth2/callback

      OAUTH2_PROXY_OIDC_ISSUER_URL: ${ISSUER}
      OAUTH2_PROXY_CLIENT_ID: ${CLIENT_ID}
      OAUTH2_PROXY_CLIENT_SECRET: ${CLIENT_SECRET}

      OAUTH2_PROXY_SKIP_JWT_BEARER_TOKENS: true
      OAUTH2_PROXY_OIDC_EXTRA_AUDIENCES: api://default
      OAUTH2_PROXY_OIDC_EMAIL_CLAIM: sub

      OAUTH2_PROXY_SET_XAUTHREQUEST: true
      OAUTH2_PROXY_PASS_ACCESS_TOKEN: true

      OAUTH2_PROXY_SESSION_STORE_TYPE: redis
      OAUTH2_PROXY_REDIS_CONNECTION_URL: redis://redis

      OAUTH2_PROXY_COOKIE_REFRESH: 30m
      OAUTH2_PROXY_COOKIE_NAME: SESSION
      OAUTH2_PROXY_COOKIE_SECRET: ${OAUTH2_PROXY_COOKIE_SECRET}

  nginx:
    image: nginx:1.21.6-alpine
    depends_on:
      - oauth2-proxy
      - web-app
    volumes:
      - ./nginx-default.conf.template:/etc/nginx/templates/default.conf.template
      - ./static-html:/usr/share/nginx/html # Not covered in blog post, adds a simple HTML page to test sign-out
    ports:
      - 80:80

  redis:
    image: redis:7.0.2-alpine3.16
    volumes:
      - cache:/data

volumes:
  cache:
    driver: local
