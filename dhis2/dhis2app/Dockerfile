FROM tomcat:9.0.68-jdk11
EXPOSE 8080 8009

RUN mkdir -p /dhis2/home
RUN mkdir -p /dhis2/templates
ENV DHIS2_HOME /dhis2/home
COPY scripts/wait-for-it.sh scripts/setEnvParams.sh *.war scripts/dhis2-* /dhis2/
COPY dhis.conf /dhis2/home
COPY dhis.conf /dhis2/templates
COPY server.xml /usr/local/tomcat/conf/
COPY setenv.sh /usr/local/tomcat/bin/

RUN chmod 500 /dhis2/dhis2-*
RUN chmod +x /dhis2/setEnvParams.sh
RUN chmod +x /usr/local/tomcat/bin/setenv.sh
RUN apt-get update \
    && apt -y upgrade && apt-get install -y curl \
    && rm -rf /var/lib/apt/lists/*
ARG version
RUN rm -rf /dhis2/dhis.war
# version e.g 2.33/2.33.5
RUN if [ ! -f /dhis2/dhis.war ]; \
    then \
        curl -L -k https://releases.dhis2.org/${version}.war -o /dhis2/dhis.war; \
    fi; \
    rm -rf /usr/local/tomcat/webapps/* \
    && mv /dhis2/dhis.war /usr/local/tomcat/webapps/ROOT.war

ENTRYPOINT ["/dhis2/setEnvParams.sh"]
CMD ["catalina.sh run"]
