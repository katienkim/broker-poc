# Multi-stage build: gradle 8.14 + JDK 21 → JRE 21 runtime.
# Mirrors the lightweight Alpine pattern used by the Node services in this POC.

FROM gradle:8.14.0-jdk21-alpine AS build
WORKDIR /app
COPY settings.gradle build.gradle ./
COPY src/ src/
RUN gradle bootJar --no-daemon -x test

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
RUN apk add --no-cache wget
COPY --from=build /app/build/libs/*.jar app.jar
EXPOSE 3003
HEALTHCHECK --interval=10s --timeout=3s --start-period=90s --retries=10 \
    CMD wget -qO- http://localhost:3003/health || exit 1
CMD ["java", "-jar", "app.jar"]
