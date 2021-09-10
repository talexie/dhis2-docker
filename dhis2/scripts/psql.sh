#!/usr/bin/env bash
docker exec -it dhis2_dhis2db_1 psql -U dhis $@

set -e
#set -x Use this for debugging
