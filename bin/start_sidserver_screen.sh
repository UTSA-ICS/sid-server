#!/bin/bash

NL=`echo -ne '\015'`
SIDSERVER_CMD="sudo tail -f /var/log/apache2/sidserver.log & echo \$\! >/opt/stack/status/stack/sid.pid; fg || echo \"key failed to start\" | tee \"/opt/stack/status/stack/sid.failure\""
SIDSERVER_LOGFILE="/opt/stack/logs/screen/screen-sidserver.log"
SCREEN=$(which screen)
if [[ -n "$SCREEN" ]]; then
    SESSION=$(screen -ls | awk '/[0-9].stack/ { print $1 }')
    if [[ -n "$SESSION" ]]; then
        screen -S $SESSION -X screen -t sidserver bash
        screen -S $SESSION -p sidserver -X logfile $SIDSERVER_LOGFILE
        screen -S $SESSION -p sidserver -X log on
        screen -S $SESSION -p sidserver -X stuff "$SIDSERVER_CMD $NL"
    fi
fi
