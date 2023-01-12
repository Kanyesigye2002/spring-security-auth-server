#
# Build stage
#
FROM maven:3.8.6-openjdk-18 AS build
COPY . .
RUN mvn clean package -DskipTests

#
# Package stage
#
FROM openjdk:18.0.2-jdk-slim
COPY --from=build /target/Oauth-authorization-server-0.0.1.jar webdroid.jar
# ENV PORT=8080
EXPOSE 9000
ENTRYPOINT ["java","-jar","webdroid.jar"]