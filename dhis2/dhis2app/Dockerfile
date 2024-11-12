# DHIS2 Docker file for ALKIP Platform

ARG tomcat_version="9.0.96"
FROM tomcat:${tomcat_version}-jdk17

ARG dhis2_minor_version="41.2.0"
ARG dhis2_major_version="41"

EXPOSE 8080 8009

RUN mkdir -p /opt/dhis2
RUN mkdir -p /opt/dhis2/templates

ENV DHIS2_HOME /opt/dhis2

COPY dhis2/dhis.conf /opt/dhis2
COPY dhis2/dhis.conf /opt/dhis2/templates
COPY dhis2/server.xml /usr/local/tomcat/conf/
COPY dhis2/context.xml /usr/local/tomcat/conf/
COPY dhis2/setenv.sh /usr/local/tomcat/bin/

RUN chmod +x /usr/local/tomcat/bin/setenv.sh
RUN apt-get update \
    && apt upgrade -y && apt-get install -y curl \
    && rm -rf /var/lib/apt/lists/*

# version e.g 2.33/2.33.5   
RUN echo "Building major version:${dhis2_major_version}, minor version:${dhis2_minor_version}"
RUN if [ ! -f /usr/local/tomcat/webapps/ROOT.war ]; \
    then \
        curl -L -k https://releases.dhis2.org/${dhis2_major_version}/dhis2-stable-${dhis2_minor_version}.war -o /usr/local/tomcat/webapps/ROOT.war; \
    fi; \
    rm -rf /usr/local/tomcat/webapps/ROOT

ENTRYPOINT ["/bin/bash","-c","catalina.sh run && tail -f /"]
