#!/usr/bin/env bash

set -e
#set -x Use this for debugging
# Set optimization settings

#ulimit -n 65535

#sysctl -w net.ipv4.tcp_tw_reuse=1
#sysctl -w net.core.somaxconn=65535
#sysctl -w net.core.netdev_max_backlog=65536

export DHIS2_DB_USER="${DHIS2_DB_USER:-'dhis2'}"
export DHIS2_DB_PASS="${DHIS2_DB_PASS:-'dhis2'}"
export DHIS2_DB_HOST="${DHIS2_DB_HOST:-'dhis2'}"
export DHIS2_DB_PORT="${DHIS2_DB_PORT:-'5432'}"
export DHIS2_DB_NAME="${DHIS2_DB_NAME:-'dhis2'}"
export DHIS2_DB_POOL_TYPE="${DHIS2_DB_POOL_TYPE:-'hikari'}"

#Configure REDIS server
export DHIS2_REDIS_ENABLED="${DHIS2_REDIS_ENABLED:-'true'}"
export DHIS2_REDIS_HOST="${DHIS2_REDIS_HOST:-'localhost'}"
export DHIS2_REDIS_PASS="${DHIS2_REDIS_PASS:-'guest'}"
export DHIS2_REDIS_PORT="${DHIS2_REDIS_PORT:-'6379'}"
export DHIS2_REDIS_TTL="${DHIS2_REDIS_TTL:-'4'}"

#Enable PAT
export DHIS2_PAT_ENABLED="${DHIS2_PAT_ENABLED:-'on'}"

#Configure Rabbit MQ server
export DHIS2_MQ_MODE="${DHIS2_MQ_MODE:-'EMBEDDED'}"
export DHIS2_MQ_HOST="${DHIS2_MQ_HOST:-'localhost'}"
export DHIS2_MQ_PASS="${DHIS2_MQ_PASS:-'guest'}"
export DHIS2_MQ_PORT="${DHIS2_MQ_PORT:-'5672'}"
export DHIS2_MQ_USER="${DHIS2_MQ_USER:-'guest'}"
export DHIS2_MQ_EXCHANGE="${DHIS2_MQ_EXCHANGE:-'dhis2'}"
# Configure JVM HEAP
export DHIS2_JVM_HEAP="${DHIS2_JVM_HEAP:-'4G'}"

#Configure Audit server
export DHIS2_AUDIT_TRACKER_ENABLED="${DHIS2_AUDIT_TRACKER_ENABLED:-'DISABLED'}"
export DHIS2_AUDIT_AGGREGATE_ENABLED="${DHIS2_AUDIT_AGGREGATE_ENABLED:-'DISABLED'}"
export DHIS2_AUDIT_METADATA_ENABLED="${DHIS2_AUDIT_METADATA_ENABLED:-'CREATE;UPDATE;DELETE'}"
export DHIS2_AUDIT_DATABASE="${DHIS2_AUDIT_DATABASE:-'on'}"
export DHIS2_AUDIT_LOGGER="${DHIS2_AUDIT_LOGGER:-'off'}"
# configure monitoring

export DHIS2_MONITORING_API="${DHIS2_MONITORING_API:-'off'}"
export DHIS2_MONITORING_JVM="${DHIS2_MONITORING_JVM:-'off'}"
export DHIS2_MONITORING_DBPOOL="${DHIS2_MONITORING_DBPOOL:-'off'}"
export DHIS2_MONITORING_UPTIME="${DHIS2_MONITORING_UPTIME:-'off'}"
export DHIS2_MONITORING_CPU="${DHIS2_MONITORING_CPU:-'off'}"
export DHIS2_MONITORING_URL="${DHIS2_MONITORING_URL:-'localhost'}"
export DHIS2_MONITORING_USER="${DHIS2_MONITORING_USER:-'dhis'}"
export DHIS2_MONITORING_PASS="${DHIS2_MONITORING_PASS:-'dhis'}"
export DHIS2_MONITORING_PORT="${DHIS2_MONITORING_PORT:-'9090'}"
export DHIS2_TIMEZONE="${DHIS2_TIMEZONE:-'Africa/Kampala'}"
export TZ="${DHIS2_TIMEZONE:-'Africa/Kampala'}"
