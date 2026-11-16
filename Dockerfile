FROM eclipse-temurin:21-jre-alpine AS runtime

WORKDIR /app

RUN addgroup -S secretdrop && adduser -S secretdrop -G secretdrop

COPY target/secretdrop-api-1.0.0-SNAPSHOT.jar app.jar

USER secretdrop

ENV SPRING_PROFILES_ACTIVE=prod

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/app.jar"]