FROM eclipse-temurin:11-jdk-jammy AS build

ARG CCT_GIT_COMMIT=unknown
ARG CCT_GIT_COMMIT_EPOCH=0

WORKDIR /workspace
COPY . .

RUN cd cardlib \
    && ./gradlew --no-daemon clean install \
        -x test -x junitPlatformTest -x generateHtmlTestReports
RUN cd conformancelib \
    && ./gradlew --no-daemon clean install -x test -x junitPlatformTest
RUN cd tools/85b-swing-gui \
    && ./gradlew --no-daemon clean test shadowJar

RUN mkdir -p /opt/cct/bootstrap \
    && cp tools/85b-swing-gui/build/libs/*-shadow.jar /opt/cct/cct.jar \
    && cp cardlib/src/main/resources/user_log_config.xml /opt/cct/bootstrap/ \
    && cp conformancelib/src/main/resources/pdval.properties /opt/cct/bootstrap/ \
    && cp -R conformancelib/src/main/resources/x509-certs /opt/cct/bootstrap/ \
    && cp conformancelib/testdata/PIV*Cards.db /opt/cct/bootstrap/ \
    && cp tools/85b-swing-gui/src/main/resources/build.version /opt/cct/bootstrap/

FROM eclipse-temurin:11-jre-jammy AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        fontconfig libpcsclite1 libxext6 libxi6 libxrender1 libxtst6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/cct /opt/cct
COPY docker/entrypoint.sh /usr/local/bin/cct-entrypoint
RUN chmod 0755 /usr/local/bin/cct-entrypoint \
    && mkdir -p /data

VOLUME ["/data"]
WORKDIR /data
ENTRYPOINT ["cct-entrypoint"]
