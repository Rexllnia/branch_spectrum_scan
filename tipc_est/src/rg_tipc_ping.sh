#!/bin/sh

while true
do
    if [ ! -f "/tmp/.ap_sysmac" ] ;then
        sleep 10
        continue
    fi

    ap_sysmac=`cat /tmp/.ap_sysmac` 
    echo "ap_sysmac $ap_sysmac"
    if [ "$ap_sysmac" != ""  ] ;then
        average=`rg_tipc_client_ping $ap_sysmac 1 5 |grep average |awk -F ':'  '{print $2}'`
        echo "$average" > /tmp/.tipc_ping_time
    else 
        echo "timeout" > /tmp/.tipc_ping_time
    fi

    sleep 10
done