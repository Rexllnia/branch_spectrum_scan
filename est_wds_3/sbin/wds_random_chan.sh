#!/bin/sh

sleep 60
# 开机1+9分钟内随机时间信道切换模块
RG_CONFIG_TMP_DIR="/tmp/rg_config/"
BOOTAUTOCHAN_LOG="${RG_CONFIG_TMP_DIR}wds_random_chan.log"
DEVINFO_JSON_FILE="/tmp/rg_device/rg_device.json"
radioName=""
debug_bac() {
    local time=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$time][$$]:$1" >> ${BOOTAUTOCHAN_LOG}
}

if [ -e ${BOOTAUTOCHAN_LOG} ]; then
    log_byte=$(ls -l $BOOTAUTOCHAN_LOG | awk '{print $5}')
    [ ${log_byte} -gt 1024 ] && { rm -rf ${BOOTAUTOCHAN_LOG}; }
fi

debug_bac "*****after 60s estBootAutoChan start*****"

radiolist=$(jq -r '.wireless.radiolist[]' $DEVINFO_JSON_FILE)
while [[ -z "${radiolist}" ]]
do
    sleep 2
    radiolist=$(jq -r '.wireless.radiolist[]' $DEVINFO_JSON_FILE)
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
		radioName=$(_jq '.name' $DEVINFO_JSON_FILE)
		wds_bss=$(_jq '.wds_bss' $DEVINFO_JSON_FILE)

		while [[ -z $radioName ]] || [[ -z $wds_bss ]]
		do
			sleep 2
			radioName=$(_jq '.name' $DEVINFO_JSON_FILE)
			wds_bss=$(_jq '.wds_bss' $DEVINFO_JSON_FILE)
		done
		break # 赋值第一个符合条件的值后退出循环
    fi
done
debug "radioName=$radioName"
debug "wds_bss=$wds_bss"

local type
local current_channel

type=$(dev_cap get -m dev_type)
if [ "$type" != "est" ]; then
	debug_bac "The device is not EST"
	return 
fi

role=$(uci -q get wireless.${radioName}.ApCliEnable)
if [ "$role" == "1" ];then
	debug_bac "CPE mode exit"
	return
fi

# 随机1-540秒,使用date命令获取当前时间的纳秒数据作为随机数种子
NANO=$(date +%N)
debug_bac "NANO=$NANO"
random_time=$(($NANO % 540 + 1))
debug_bac "random_time=$random_time waiting..."
sleep $random_time

current_channel="$(uci -q get wireless."$radioName".channel)"
if [ "$current_channel" == "0" ];then 
    iwpriv "$wds_bss" set AutoChannelSel=3 &
	debug_bac "iwpriv $wds_bss set AutoChannelSel=3"
fi

debug_bac "*****************estBootAutoChan end*****"
