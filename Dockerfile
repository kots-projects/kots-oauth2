FROM eclipse-temurin:21-jre
WORKDIR /opt/oauth2
COPY modules/host/target/scala-2.13/kots-oauth2-host.jar kots-oauth2-host.jar
EXPOSE 8080
USER nobody
ENTRYPOINT ["java", "-jar", "kots-oauth2-host.jar"]
