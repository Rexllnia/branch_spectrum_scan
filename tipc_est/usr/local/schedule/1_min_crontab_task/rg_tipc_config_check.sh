#!/bin/sh

RG_CONFIG_TMP_DIR="/tmp/rg_config/"
EST_TIPC_CONFIG_CHECK_LOG="${RG_CONFIG_TMP_DIR}tipc_config_check.log"

est_dbg() {
	#log文件大小限5k
	if [ -e ${EST_TIPC_CONFIG_CHECK_LOG} ]; then
		local est_model_log_byte=$(ls -l ${EST_TIPC_CONFIG_CHECK_LOG} | awk '{print $5}')
		[ ${est_model_log_byte} -gt 5000 ] && { mv -f ${EST_TIPC_CONFIG_CHECK_LOG} ${EST_TIPC_CONFIG_CHECK_LOG}.old; }
	fi
	
    local time=$(date "+%H:%M:%S")
    echo -e "[$time][$$]$1"  >> ${EST_TIPC_CONFIG_CHECK_LOG}
}
est_dbg "\n********************$(date "+%Y-%m-%d %H:%M:%S")**********************"

tipc_binding_to_brwan(){
	tipc-config -bd=eth:br-wan
	sleep 1
	tipc-config -be=eth:br-wan
}

is_binding_success(){
	local interface=$(tipc-config -b |grep br-wan)
	if [ -n "$interface" ];then
		#est_dbg "tipc binding brwan success"
		return 1
	fi
	est_dbg "tipc binding brwan fail"
	return 0
}

#60s检测一次tipc是否绑定到了br-wan，没有绑定则重新绑定
is_binding_success
if [ $? == 0 ];then
	est_dbg "tipc binding to brwan "
	tipc_binding_to_brwan
fi

