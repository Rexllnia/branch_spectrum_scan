#!/bin/sh

WDS_SAVE_PS_FILE="/tmp/wds_save_ps"

LOG_SIZE=10        # 日志文件大小, 单位KB
LOG_ROOT="/tmp/rg_config"
LOG_FILE="$LOG_ROOT/wds_process_monitor.log"
debug()
{
    local cur_time=$(date "+[%Y-%m-%d %H:%M:%S]")
    if [ -f  $LOG_FILE ]; then
       local file_size=$(du -shk $LOG_FILE | awk '{print $1}' | tr -d ' \n\t')

        [ $file_size  -gt $LOG_SIZE ] && {
            mv -f $LOG_FILE ${LOG_FILE}.old
        }
    fi

    echo -e "${cur_time} ${1}" >> $LOG_FILE
}

ps > $WDS_SAVE_PS_FILE 2> /dev/null

check_and_restart_process()
{
    proc="$1"
    restart_cmd="$2"

    if [ -f $WDS_SAVE_PS_FILE ]; then
        proc_num=$(cat $WDS_SAVE_PS_FILE 2> /dev/null |grep -w "$proc" |grep -v grep |wc -l)
        if [ $proc_num -ne 1 ]; then
            #进程个数为0，则重启
            debug "$proc_num $proc not running, start it"
            eval $restart_cmd
        fi
    fi
}

if [ ! -f  $LOG_FILE ]; then
	mkdir -p $LOG_ROOT
	debug "wds process monitor start..."
fi

#check rg_wds_gpio
if [ -f "/sbin/rg_wds_gpio" ]; then
	proc="/sbin/rg_wds_gpio"
	restart_cmd="kill -9 $(ps | grep rg_wds_gpio | grep -v grep | awk '{print $1}') > /dev/null 2>&1; /sbin/rg_wds_gpio & > /dev/null 2>&1"
	check_and_restart_process "$proc" "$restart_cmd"
fi

#check rg_tipc rg_tipc_server_shell
if [ -f "/etc/init.d/rg_tipc" ]; then
	proc="/sbin/rg_tipc_server_shell"
	restart_cmd="/etc/init.d/rg_tipc restart > /dev/null 2>&1"
	check_and_restart_process "$proc" "$restart_cmd"
fi

#check rg_tipc rg_tipc_server_ping
if [ -f "/etc/init.d/rg_tipc" ]; then
	proc="/sbin/rg_tipc_server_ping"
	restart_cmd="/etc/init.d/rg_tipc restart > /dev/null 2>&1"
	check_and_restart_process "$proc" "$restart_cmd"
fi

#check rg_tipc rg_tipc_server_upgrade
if [ -f "/etc/init.d/rg_tipc" ]; then
	proc="/sbin/rg_tipc_server_upgrade"
	restart_cmd="/etc/init.d/rg_tipc restart > /dev/null 2>&1"
	check_and_restart_process "$proc" "$restart_cmd"
fi

#check rg_tipc rg_tipc_server_download
if [ -f "/etc/init.d/rg_tipc" ]; then
	proc="/sbin/rg_tipc_server_download"
	restart_cmd="/etc/init.d/rg_tipc restart > /dev/null 2>&1"
	check_and_restart_process "$proc" "$restart_cmd"
fi

#check spectrum_scan
if [ -f "/etc/init.d/spectrum_scan" ]; then
	proc="spectrum_scan.elf"
	restart_cmd="/etc/init.d/spectrum_scan restart > /dev/null 2>&1"
	check_and_restart_process "$proc" "$restart_cmd"
fi


exit 0

