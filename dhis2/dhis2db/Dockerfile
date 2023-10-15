ARG version
FROM postgis/postgis:${version}
RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get install -y cron \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /dhis2/scripts
COPY dhis2/scripts/dhis2* /usr/bin/
RUN chmod +x /usr/bin/dhis2*

COPY dhis2/scripts/set-schedule.sh  /usr/local/bin/set-schedule.sh
RUN chmod +x /usr/local/bin/set-schedule.sh
VOLUME /dbbackups

# COPY dhis2/scripts/999_postgres_settings.sh /docker-entrypoint-initdb.d/
# RUN chmod a+r /docker-entrypoint-initdb.d/999_postgres_settings.sh

RUN adduser root crontab && adduser postgres crontab
ENTRYPOINT ["/usr/local/bin/set-schedule.sh"]
CMD ["postgres"]
