# Zato ODB & Cluster
# Modified by Alex Tumwesigye <atumwesigye@gmail.com>

FROM ubuntu:16.04
MAINTAINER Dariusz Suchojad <dsuch@zato.io>

RUN ln -s -f /bin/true /usr/bin/chfn

# Install helper programs used during Zato installation
RUN apt-get update
RUN apt-get install -y apt-transport-https \
    python-software-properties \
    software-properties-common \
    curl \
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


USER zato
RUN mkdir -p /opt/zato/configs
COPY --chown=zato:zato ihisengine/odb_cluster/zato_odb.config /opt/zato/configs/
COPY --chown=zato:zato ihisengine/odb_cluster/zato_cluster.config /opt/zato/configs/
COPY --chown=zato:zato ihisengine/odb_cluster/supervisord.conf /opt/zato/configs/

USER zato

ENV ZATO_BIN /opt/zato/current/bin/zato

WORKDIR /opt/zato

RUN $ZATO_BIN from-config /opt/zato/configs/zato_odb.config
RUN $ZATO_BIN from-config /opt/zato/configs/zato_cluster.config

USER root
# VOLUME /opt/zato/configs

#ENTRYPOINT ["/bin/sh"]
CMD /usr/bin/supervisord -c /opt/zato/configs/supervisord.conf



