#!/usr/bin/env bash
set -Eeo pipefail
# TODO swap to -Eeuo pipefail above (after handling all potentially-unset variables)
# Set locales
#export LANG="en_US.UTF-8" 
#export LC_ALL="en_US.UTF-8" 
#export LC_CTYPE="en_US.UTF-8"

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
#echo en_US.UTF-8 UTF-8 >> /etc/locale.gen && locale-gen
/bin/bash -c "/usr/local/bin/docker-entrypoint.sh postgres"
