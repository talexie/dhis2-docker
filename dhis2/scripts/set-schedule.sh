#!/usr/bin/env bash
set -e
export CRON_SCHEDULE="${CRON_SCHEDULE:-'0 0 * * *'}"
croncmd="/usr/bin/dhis2-backup-local > /dbbackups/backups`date +\%Y-\%m-\%d-\%H-\%M`.log 2>&1"
cronjob="$CRON_SCHEDULE $croncmd"
( crontab -l | grep -v -F "$croncmd" ; echo "$cronjob" ) | crontab -

