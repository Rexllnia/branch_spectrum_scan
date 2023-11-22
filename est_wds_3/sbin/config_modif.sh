#!/bin/sh
# 包含统一函数库
local LOG_FILE=/tmp/rg_config/rg_est_config_modif.log
local RG_DEVICE_FILE=/tmp/rg_device/rg_device.json
local uci_mgmt_frame_pwr
local uci_appl_scen
local uci_hide_ssid_idx
local est_wds_df_password="est@wds#mjkf997!"
local EST_WDS_DF_PW_FILE="/etc/rg_config/wds_df_password"
local ENC_OUTPUT_FILE="/tmp/cm_enc_out"
local est_wds_df_pw
local dev_type=$(cat "$RG_DEVICE_FILE" |jq .dev_type| sed 's/\"//g')

debug() 
{
    local time=$(date "+%H:%M:%S")
    if [ -e ${LOG_FILE} ]; then
        wifi_status_monitor_log_byte=$(ls -l ${LOG_FILE} | awk '{print $5}')
        [ ${wifi_status_monitor_log_byte} -gt 10000 ] && { sed -i '1,50d' ${LOG_FILE};}
    fi
    echo -e "[$time][$$]$1"  >> ${LOG_FILE}
}

radiolist=$(jq -r '.wireless.radiolist[]' $RG_DEVICE_FILE)
while [[ -z "${radiolist}" ]]
do
    sleep 2
    radiolist=$(jq -r '.wireless.radiolist[]' $RG_DEVICE_FILE)
done
for row in $(echo "${radiolist}" | jq -r '. | @base64'); do # 遍历radiolist数组中的每一组
    _jq() {
      echo ${row} | base64 --decode | jq -r ${1}
    }
    support_wds=$(_jq '.support_wds') # 获取当前组的support_wds的值
	while [[ -z $support_wds ]]
	do
		sleep 2
		support_wds=$(_jq '.support_wds')
	done
    if [ "$support_wds" == "true" ] ;then # 判断support_wds是否为true
		radioName=$(_jq '.name' $RG_DEVICE_FILE)

		while [[ -z $radioName ]]
		do
			sleep 2
			radioName=$(_jq '.name' $RG_DEVICE_FILE)
		done
		break # 赋值第一个符合条件的值后退出循环
    fi
done
debug "radioName=$radioName"

while true
do
	if [ "$dev_type" != "est" ];then
		debug "It is not the EST device that is not running"
		break
	fi
	
	uci_mgmt_frame_pwr=$(uci -q get wireless.$radioName.mgmt_frame_pwr)
	uci_appl_scen=$(uci -q get wifiinfo.global.appl_scen)
	uci_hide_ssid_idx=$(uci -q get wifiinfo.global.hide_ssid_idx)
	
	if [ "$uci_mgmt_frame_pwr" != "0" ];then
		uci set wireless."$radioName".mgmt_frame_pwr='0'
		uci commit
		wifi reload
		debug "uci set wireless.$radioName.mgmt_frame_pwr='0'"
	fi
	if [ "$uci_appl_scen" != "outdoor" ];then
		uci set wifiinfo.global.appl_scen='outdoor'
		uci commit
		debug "uci set wifiinfo.global.appl_scen='outdoor'"
	fi
	if [ -n "$uci_hide_ssid_idx" ];then
		uci del wifiinfo.global.hide_ssid_idx
		uci commit
		debug "uci del wifiinfo.global.hide_ssid_idx"
	fi
	if [ -e ${EST_WDS_DF_PW_FILE} ];then
		est_wds_df_pw=$(cat ${EST_WDS_DF_PW_FILE})
		
		if [ "$est_wds_df_pw" == "$est_wds_df_password" ];then
			debug "rg_crypto enc -t C -in $EST_WDS_DF_PW_FILE -out $ENC_OUTPUT_FILE"
			rg_crypto enc -t C -in "$EST_WDS_DF_PW_FILE" -out "$ENC_OUTPUT_FILE"
			est_wds_df_pw=$(cat $ENC_OUTPUT_FILE)
			rm $ENC_OUTPUT_FILE
			debug "est_wds_df_pw enc:$est_wds_df_pw"
			echo -n "$est_wds_df_pw" > ${EST_WDS_DF_PW_FILE}
		else
			debug "The default wds pw in file [ $EST_WDS_DF_PW_FILE ] has been encrypted"
		fi
	fi
	uci_mgmt_frame_pwr=$(uci -q get wireless.$radioName.mgmt_frame_pwr)
	uci_appl_scen=$(uci -q get wifiinfo.global.appl_scen)
	uci_hide_ssid_idx=$(uci -q get wifiinfo.global.hide_ssid_idx)
	est_wds_df_pw=$(cat ${EST_WDS_DF_PW_FILE})
	if [ "$uci_mgmt_frame_pwr" == "0" -a "$uci_appl_scen" == "outdoor" -a -z "$uci_hide_ssid_idx" -a "$est_wds_df_pw" != "$est_wds_df_password" ];then
		debug "The modification is complete, delete the script [config_modif.sh]"
		rm /sbin/config_modif.sh
		break
	fi
	debug "modify again "
done

