# First, build the JAR
FROM maven:3.9.11-eclipse-temurin-17 AS build
WORKDIR /app
COPY . /app
RUN mvn clean package -DskipTests

## create final image
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/vulnerable-site-0.0.1-SNAPSHOT.jar /app/vulnerable-site.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/vulnerable-site.jar"]

##
##
