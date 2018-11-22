FROM tomcat:8
EXPOSE 8080 8009

RUN mkdir -p /dhis2/home
ENV DHIS2_HOME /dhis2/home
COPY scripts/wait-for-it.sh *.war dhis2-* /dhis2/
COPY dhis.conf /dhis2/home
COPY server.xml /usr/local/tomcat/conf/

RUN CHMOD 500 /dhis2/dhis2-*

RUN apt-get update \
    && apt-get install -y curl netcat \
    && rm -rf /var/lib/apt/lists/*
ARG version
RUN if [ ! -f /dhis2/dhis.war ]; \
    then \
        curl -L -k http://s3-eu-west-1.amazonaws.com/releases.dhis2.org/${version}/dhis.war -o /dhis2/dhis.war; \
    fi; \
    rm -rf /usr/local/tomcat/webapps/* \
    && mv /dhis2/dhis.war /usr/local/tomcat/webapps/ROOT.war
CMD ["catalina.sh run"]
