FROM maven:3.9.9-eclipse-temurin-21 AS build

WORKDIR /workspace
COPY pom.xml .
COPY backend backend
ARG SERVICE_PATH
RUN --mount=type=cache,target=/root/.m2/repository mvn -pl "${SERVICE_PATH}" -am -DskipTests package

FROM eclipse-temurin:21-jre

WORKDIR /app
ARG SERVICE_PATH
ARG JAR_NAME
COPY --from=build /workspace/${SERVICE_PATH}/target/${JAR_NAME}-*.jar /app/app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

