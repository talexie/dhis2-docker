# Zato Server
# Modified by Alex Tumwesigye <atumwesigye@gmail.com>

FROM ubuntu:16.04
MAINTAINER Dariusz Suchojad <dsuch@zato.io>

RUN ln -s -f /bin/true /usr/bin/chfn

# Install helper programs used during Zato installation
#RUN apt-get update
RUN apt-get update && apt-get install -y apt-transport-https \
    python-software-properties \
    software-properties-common \
    curl \
    libcurl4-openssl-dev \
    telnet \
    wget \
    supervisor

# Add the package signing key
RUN curl -s https://zato.io/repo/zato-0CBD7F72.pgp.asc | apt-key add -

# Add Zato repo to your apt
# update sources and install Zato
RUN apt-add-repository https://zato.io/repo/stable/3.0/ubuntu
RUN apt-get update && apt-get install -y zato

# Install latest updates
WORKDIR /opt/zato/current
RUN git pull
RUN ./bin/pip install -e ./zato-cy

COPY --chown=zato:zato ihisengine/server1/zato_start_server /opt/zato/
COPY --chown=zato:zato ihisengine/server1/zato_create_start_server.sh /opt/zato/
RUN chmod 755 /opt/zato/zato_create_start_server.sh
RUN chmod 755 /opt/zato/zato_start_server

USER zato
WORKDIR /opt/zato

# Prepare additional config files, CA certificates, keys and starter scripts
RUN mkdir /opt/zato/ca
COPY ihisengine/certs/zato.server1.cert.pem /opt/zato/ca/
COPY ihisengine/certs/zato.server1.key.pem /opt/zato/ca/
COPY ihisengine/certs/zato.server1.key.pub.pem /opt/zato/ca/
COPY ihisengine/certs/ca_cert.pem /opt/zato/ca/

# Set server config
RUN mkdir -p /opt/zato/configs
COPY ihisengine/server1/zato_server.config /opt/zato/
COPY ihisengine/server1/supervisord.conf /opt/zato/
COPY --chown=zato:zato ihisengine/server1/zato_server.config /opt/zato/configs/
COPY --chown=zato:zato ihisengine/server1/supervisord.conf /opt/zato/configs/

# Change permissions
USER root
RUN chown zato:zato -R /opt/zato/ca/

USER zato

ENV ZATO_BIN /opt/zato/current/bin/zato

RUN rm -rf /opt/zato/env/qs-1/server && mkdir -p /opt/zato/env/qs-1/server

WORKDIR /opt/zato/env/qs-1/server

RUN $ZATO_BIN from-config /opt/zato/configs/zato_server.config --verbose

RUN sed -i 's/gunicorn_workers=2/gunicorn_workers=1/g' \
    /opt/zato/env/qs-1/server/config/repo/server.conf
RUN sed -i 's/localhost:17010/0.0.0.0:17010/g' \
    /opt/zato/env/qs-1/server/config/repo/server.conf

USER root

EXPOSE 17010
# ENTRYPOINT ["/opt/zato/zato_create_start_server.sh"]

CMD /usr/bin/supervisord -c /opt/zato/configs/supervisord.conf

