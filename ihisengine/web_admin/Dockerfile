# Zato web Admin
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
    libcurl4-openssl-dev \
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

COPY --chown=zato:zato ihisengine/web_admin/zato_start_web_admin /opt/zato/
COPY --chown=zato:zato ihisengine/web_admin/zato_start_scheduler /opt/zato/
RUN chmod 755 /opt/zato/zato_start_web_admin
RUN chmod 755 /opt/zato/zato_start_scheduler

# Set a password for zato user

RUN touch /opt/zato/zato_user_password /opt/zato/change_zato_password
RUN uuidgen > /opt/zato/zato_user_password
RUN chown zato:zato /opt/zato/zato_user_password
RUN echo 'zato':$(cat /opt/zato/zato_user_password) > /opt/zato/change_zato_password
RUN chpasswd < /opt/zato/change_zato_password

USER zato
WORKDIR /opt/zato

# Prepare additional config files, CA certificates, keys and starter scripts
RUN mkdir /opt/zato/ca
COPY ihisengine/certs/zato.web_admin.cert.pem /opt/zato/ca/
COPY ihisengine/certs/zato.web_admin.key.pem /opt/zato/ca/
COPY ihisengine/certs/zato.web_admin.key.pub.pem /opt/zato/ca/
COPY ihisengine/certs/ca_cert.pem /opt/zato/ca/

# Set web admin config
RUN mkdir -p /opt/zato/configs
COPY ihisengine/web_admin/zato_update_password.config /opt/zato/configs/
COPY ihisengine/web_admin/zato_web_admin.config /opt/zato/configs/
COPY ihisengine/web_admin/supervisord.conf /opt/zato/configs/

# Change permissions
USER root
RUN chown zato:zato -R /opt/zato/ca/
RUN chown zato:zato -R /opt/zato/configs/

USER zato

ENV ZATO_BIN /opt/zato/current/bin/zato

RUN rm -rf /opt/zato/env/qs-1/web-admin && mkdir -p /opt/zato/env/qs-1/web-admin

# Set a password for admin user and append it to a config file
WORKDIR /opt/zato
RUN touch /opt/zato/web_admin_password
RUN uuidgen > /opt/zato/web_admin_password
RUN echo 'password'=$(cat /opt/zato/web_admin_password) >> /opt/zato/configs/zato_update_password.config

WORKDIR /opt/zato/env/qs-1/web-admin

RUN $ZATO_BIN from-config /opt/zato/configs/zato_web_admin.config
RUN $ZATO_BIN from-config /opt/zato/configs/zato_update_password.config

RUN sed -i 's/127.0.0.1/0.0.0.0/g' \
    /opt/zato/env/qs-1/web-admin/config/repo/web-admin.conf

USER root

EXPOSE 8183
CMD /usr/bin/supervisord -c /opt/zato/configs/supervisord.conf