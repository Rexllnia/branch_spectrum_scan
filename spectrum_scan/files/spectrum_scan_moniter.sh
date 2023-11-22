#!/bin/sh

monitor()
{
	local PROC="spectrum_scan.elf"
	local PROC_RESTART_CMD="/etc/init.d/spectrum_scan restart > /dev/null 2>&1"
	local proc_num

	proc_num=$(ps -w |grep -w "$PROC" |grep -v grep |wc -l)
	if [ $proc_num -eq 0 ]; then
		eval $PROC_RESTART_CMD
	fi
}

#main
monitor

exit 0