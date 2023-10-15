#!/usr/bin/env bash
set -e
# Perform all actions as $POSTGRES_USER
export PGUSER="$POSTGRES_USER"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    alter system set max_connections = 200;
    alter system set shared_buffers = '3GB';
    alter system set work_mem = '24MB';
    alter system set maintenance_work_mem = '1GB';
    alter system set temp_buffers = '16MB';
    alter system set effective_cache_size = '4GB';
    alter system set checkpoint_completion_target = 0.8;
    alter system set synchronous_commit = 'off';
    alter system set wal_writer_delay = '10s';
    alter system set random_page_cost = 1.1;
    alter system set max_locks_per_transaction = 96;
    alter system set track_activity_query_size = 8192;
EOSQL
