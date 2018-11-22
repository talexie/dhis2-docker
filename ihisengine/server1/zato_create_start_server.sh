#!/bin/bash -eux

ZATO_ENV=/opt/zato/env/qs-1
ZATO_CONFIG=/opt/zato/configs
ZATO_BIN=/opt/zato/current/bin/zato


su - zato -c "rm -rf $ZATO_ENV && mkdir -p $ZATO_ENV"
su - zato -c "$ZATO_BIN from-config /opt/zato/configs/zato_server.config --verbose"

#su - zato -c "$ZATO_BIN create server $ZATO_ENV --odb_host $ZATO_ODBHOST --odb_port $ZATO_ODBPORT \
#--odb_user $ZATO_ODBUSER --odb_db_name $ZATO_ODBDATABASE  \
#--kvdb_password $ZATO_KVDBSECRET --odb_password $ZATO_ODBSECRET --secret_key $ZATO_SECRET_KEY \
#--jwt_secret $ZATO_JWTSECRET_KEY --http_port $ZATO_HTTP_PORT \
# $ZATO_ODBTYPE $ZATO_KVDB_HOST $ZATO_KVDB_PORT $ZATO_PUB_KEY_PATH $ZATO_PRIV_KEY_PATH\
# $ZATO_CERT_PATH $ZATO_CA_CERTS_PATH $ZATO_CLUSTERNAME $ZATO_SERVER_NAME"

#usage: zato create server [-h] [--store-log] [--verbose] [--store-config]
#                          [--odb_host ODB_HOST] [--odb_port ODB_PORT]
#                          [--odb_user ODB_USER] [--odb_db_name ODB_DB_NAME]
#                          [--postgresql_schema POSTGRESQL_SCHEMA]
#                          [--odb_password ODB_PASSWORD]
#                          [--kvdb_password KVDB_PASSWORD]
#                          [--secret_key SECRET_KEY] [--jwt_secret JWT_SECRET]
#                          [--http_port HTTP_PORT]
#                          path {mysql,postgresql,sqlite} kvdb_host kvdb_port
#                          pub_key_path priv_key_path cert_path ca_certs_path
#                          cluster_name server_name


su - zato -c "sed -i 's/gunicorn_workers=2/gunicorn_workers=1/g' $ZATO_ENV/server/config/repo/server.conf"
su - zato -c "sed -i 's/localhost:17010/0.0.0.0:17010/g' $ZATO_ENV/server/config/repo/server.conf"