# Zato load-balancer
# Modified by Alex Tumwesigye <atumwesigye@gmail.com>

FROM ubuntu:16.04
MAINTAINER Dariusz Suchojad <dsuch@zato.io>

RUN ln -s -f /bin/true /usr/bin/chfn

# Install helper programs used during Zato installation
RUN apt-get update --fix-missing
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

COPY ihisengine/load_balancer/zato_start_load_balancer /opt/zato/
RUN chmod 755 /opt/zato/zato_start_load_balancer

USER zato
WORKDIR /opt/zato

# Get additional config files and starter scripts
RUN mkdir /opt/zato/ca
COPY ihisengine/certs/zato.load_balancer.cert.pem /opt/zato/ca/
COPY ihisengine/certs/zato.load_balancer.key.pem /opt/zato/ca/
COPY ihisengine/certs/zato.load_balancer.key.pub.pem /opt/zato/ca/
COPY ihisengine/certs/ca_cert.pem /opt/zato/ca/


RUN mkdir -p /opt/zato/configs

COPY --chown=zato:zato ihisengine/load_balancer/zato_load_balancer.config /opt/zato/configs/
COPY --chown=zato:zato ihisengine/load_balancer/supervisord.conf /opt/zato/configs/

# Change permissions
USER root
RUN chown zato:zato -R /opt/zato/ca/

USER zato

ENV ZATO_BIN /opt/zato/current/bin/zato

RUN rm -rf /opt/zato/env/qs-1/load-balancer && mkdir -p /opt/zato/env/qs-1/load-balancer

WORKDIR /opt/zato/env/qs-1/load-balancer

RUN $ZATO_BIN from-config /opt/zato/configs/zato_load_balancer.config
RUN sed -i 's/127.0.0.1:11223/0.0.0.0:11223/g' /opt/zato/env/qs-1/load-balancer/config/repo/zato.config
RUN sed -i 's/localhost/0.0.0.0/g' /opt/zato/env/qs-1/load-balancer/config/repo/lb-agent.conf

USER root

EXPOSE 11223 20151

CMD /usr/bin/supervisord -c /opt/zato/configs/supervisord.conf
