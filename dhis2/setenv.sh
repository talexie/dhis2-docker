#!/bin/sh
#       ____  __  ______________ 
#      / __ \/ / / /  _/ ___/__ \
#     / / / / /_/ // / \__ \__/ /
#    / /_/ / __  // / ___/ / __/ 
#   /_____/_/ /_/___//____/____/
#
# Environment variables used by tomcat
#

# Virtual machine tuning
# Set heap size according to your available memory.
# In most cases this will be all you need to set (be sure
# you have allocated plenty for postgres).

HEAP="${DHIS2_JVM_HEAP:-'4G'}"

# venture below here only if you know what you are doing ....

# sets basic memory size parameters
export CATALINA_OPTS="-Xms$HEAP -Xmx$HEAP -Xss256m"

# some best practice suggestions from https://gist.github.com/terrancesnyder/986029
#export CATALINA_OPTS="$CATALINA_OPTS -XX:+UseG1GC"
export CATALINA_OPTS="$CATALINA_OPTS -XX:+UseParallelGC"
export CATALINA_OPTS="$CATALINA_OPTS -XX:MaxGCPauseMillis=1500"
export CATALINA_OPTS="$CATALINA_OPTS -XX:GCTimeRatio=9"
export CATALINA_OPTS="$CATALINA_OPTS -server"

# You can generally leave these untouched
export CATALINA_PID=$CATALINA_BASE/tomcat.pid
export CATALINA_HOME=/usr/local/tomcat
export DHIS2_HOME=/dhis2/home
# Fix JAVA_OPTS vulnerability issue
export JAVA_OPTS="$JAVA_OPTS -Dlog4j2.formatMsgNoLookups=true"
