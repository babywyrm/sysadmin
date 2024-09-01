# First, build the JAR
FROM maven:3.8.5-openjdk-17-slim AS build
WORKDIR /app
COPY . /app
RUN mvn clean package -DskipTests

## create final image
FROM openjdk:17-jdk-alpine
WORKDIR /app
COPY --from=build /app/target/vulnerable-site-0.0.1-SNAPSHOT.jar /app/vulnerable-site.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/vulnerable-site.jar"]

##
##
