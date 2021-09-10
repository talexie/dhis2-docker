ARG version
FROM postgis/postgis:${version}

ENV POSTGRES_USER dhis
ENV POSTGRES_PASSWORD dhis
ENV POSTGRES_DB dhis

RUN mkdir -p /dhis2/scripts
COPY scripts/dhis2* /usr/bin/
RUN chmod +x /usr/bin/dhis2*
COPY scripts/set-schedule.sh /docker-entrypoint-initdb.d/30_set-schedule.sh
VOLUME /dbbackups
