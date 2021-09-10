#!/usr/bin/env bash
docker exec -it dhis2_dhis2mq_1 rabbitmqctl $@

set -e
#set -x Use this for debugging
