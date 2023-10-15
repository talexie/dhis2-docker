#!/usr/bin/env bash
set -Eeo pipefail
# TODO swap to -Eeuo pipefail above (after handling all potentially-unset variables)

export CRON_SCHEDULE="${CRON_SCHEDULE:-'0   0   *   *   *'}"
croncmd="/bin/bash -c '/usr/bin/dhis2-backup-local >> /dbbackups/backups.log 2>&1'"
cronjob="$CRON_SCHEDULE $croncmd"
env | grep DB_ >> /etc/profile.d/db_backup_env.sh
#( crontab -l | grep -v -F "$croncmd" ; echo "$cronjob" ) | sh -c "crontab - " << EOT
crontab - << EOT
$CRON_SCHEDULE  $croncmd
EOT

echo "Added schedule ${CRON_SCHEDULE}";
echo "Starting crontab"
/etc/init.d/cron restart

/bin/bash -c "/usr/local/bin/docker-entrypoint.sh postgres"
