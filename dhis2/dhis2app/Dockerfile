# DHIS2 Docker file for ALKIP Platform

ARG tomcat_version="9.0.85"
FROM tomcat:${tomcat_version}-jdk11

ARG dhis2_minor_version="40.2.1"
ARG dhis2_major_version="40"

EXPOSE 8080 8009

RUN mkdir -p /dhis2/home
RUN mkdir -p /dhis2/templates
ENV DHIS2_HOME /dhis2/home
COPY dhis2/scripts/wait-for-it.sh dhis2/scripts/setEnvParams.sh *.war dhis2/scripts/dhis2-* /dhis2/
COPY dhis2/dhis.conf /dhis2/home
COPY dhis2/dhis.conf /dhis2/templates
COPY dhis2/server.xml /usr/local/tomcat/conf/
COPY dhis2/context.xml /usr/local/tomcat/conf/
COPY dhis2/setenv.sh /usr/local/tomcat/bin/

RUN chmod 500 /dhis2/dhis2-*
RUN chmod +x /dhis2/setEnvParams.sh
RUN chmod +x /usr/local/tomcat/bin/setenv.sh
RUN apt-get update \
    && apt upgrade -y && apt-get install -y curl unzip\
    && rm -rf /var/lib/apt/lists/*

RUN rm -rf /dhis2/dhis.war
# version e.g 2.33/2.33.5   
RUN echo "Building major version:${dhis2_major_version}, minor version:${dhis2_minor_version}"
RUN if [ ! -f /dhis2/dhis.war ]; \
    then \
        #curl -L -k https://releases.dhis2.org/${dhis2_major_version}/dhis2-stable-${dhis2_minor_version}.war -o /dhis2/dhis.war; \
        curl -L -k https://github.com/talexie/dhis2-core/actions/runs/7628643980/artifacts/1189229636 -o /dhis2/dhis.war.zip \
        && unzip /dhis2/dhis.war.zip -d /dhis2 \
    fi; \
    rm -rf /usr/local/tomcat/webapps/* \
    && rm -rf /dhis2/dhis.war.zip \
    && mv /dhis2/dhis.war /usr/local/tomcat/webapps/ROOT.war

ENTRYPOINT ["/dhis2/setEnvParams.sh"]
CMD ["catalina.sh run"]
