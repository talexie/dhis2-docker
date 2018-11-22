# Zato

FROM ubuntu:16.04
MAINTAINER Dariusz Suchojad <dsuch@zato.io>

# Install helper programs used during Zato installation
RUN apt-get update
RUN apt-get install -y \
    apt-transport-https \
    curl \
    software-properties-common \
    htop \
    libcurl4-openssl-dev \
    mc \
    redis-server \
    ssh \
    supervisor \
    vim 
# && rm -rf /var/lib/apt/lists/*

# Add the package signing key
RUN curl -s https://zato.io/repo/zato-0CBD7F72.pgp.asc | apt-key add -

# Add Zato repo and install the package
# update sources and install Zato
RUN apt-add-repository https://zato.io/repo/stable/3.0/ubuntu
RUN apt-get update && apt-get install -y zato

# Install latest updates
WORKDIR /opt/zato/current
RUN git pull
RUN ./bin/pip install -e ./zato-cy 
RUN pip install riak pandas jellyfish luhn
RUN ln -s /usr/local/lib/python2.7/dist-packages ./lib/python2.7/dist-packages

# Setup supervisor
RUN mkdir -p /var/log/supervisor

# Setup sshd
RUN mkdir /var/run/sshd/

# Set a password for zato user
WORKDIR /opt/zato/
RUN touch /opt/zato/zato_user_password /opt/zato/change_zato_password
RUN uuidgen > /opt/zato/zato_user_password
RUN chown zato:zato /opt/zato/zato_user_password
RUN echo 'zato':$(cat /opt/zato/zato_user_password) > /opt/zato/change_zato_password
RUN chpasswd < /opt/zato/change_zato_password

# Switch to zato user and create Zato environment
USER zato

EXPOSE 22 8183 17010 17011 11223

# Get additional config files and starter scripts
WORKDIR /opt/zato
RUN wget -P /opt/zato -i https://raw.githubusercontent.com/zatosource/zato-build/master/docker/quickstart/filelist
RUN chmod 755 /opt/zato/zato_start_load_balancer \
              /opt/zato/zato_start_server1 \
              /opt/zato/zato_start_server2 \
              /opt/zato/zato_start_web_admin \
              /opt/zato/zato_start_scheduler

# Set a password for web admin and append it to a config file
WORKDIR /opt/zato
RUN touch /opt/zato/web_admin_password
RUN uuidgen > /opt/zato/web_admin_password
RUN echo 'password'=$(cat /opt/zato/web_admin_password) >> /opt/zato/update_password.config

ENV ZATO_BIN /opt/zato/current/bin/zato

RUN mkdir -p /opt/zato/env/qs-1
RUN rm -rf /opt/zato/env/qs-1 && mkdir -p /opt/zato/env/qs-1

WORKDIR /opt/zato/env/qs-1
# Use SQLite as database
ENV IHIS_ENGINE_REDIS_HOST localhost
ENV IHIS_ENGINE_REDIS_PORT 6379

RUN $ZATO_BIN quickstart create . sqlite $IHIS_ENGINE_REDIS_HOST $IHIS_ENGINE_REDIS_PORT --verbose \ 
 --kvdb_password ""

# Use PostgreSQL database


RUN $ZATO_BIN from-config /opt/zato/update_password.config

RUN sed -i 's/127.0.0.1:11223/0.0.0.0:11223/g' /opt/zato/env/qs-1/load-balancer/config/repo/zato.config
RUN sed -i 's/gunicorn_workers=2/gunicorn_workers=1/g' /opt/zato/env/qs-1/server1/config/repo/server.conf
RUN sed -i 's/gunicorn_workers=2/gunicorn_workers=1/g' /opt/zato/env/qs-1/server2/config/repo/server.conf

USER root
CMD /usr/bin/supervisord -c /opt/zato/supervisord.conf