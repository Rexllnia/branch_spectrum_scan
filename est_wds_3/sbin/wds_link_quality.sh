#!/bin/sh
# wds_link_quality.sh
# 获取终端信息，并组装成json文件，供rlogv2调用
# 参考sta_list的实现，目前不支持 page 和 size的读取方式(分页读取)
#
# history
# V0.1 : initial version
#

. /usr/share/libubox/jshn.sh

#定义获取项
module="wds_list"
TMP_FILE="/tmp/wdslinkqualityrlog.tmp"
UPLOAD_FILE_DIR="/tmp/ap_log/all/wdslinkquality"
UPLOAD_FILE="/tmp/ap_log/all/wdslinkquality/wdslinkquality"
UPLOAD_LOCK="/tmp/wdslinkquality.lock"
DEVINFO_JSON_FILE="/tmp/rg_device/rg_device.json"
TMP_LIST_FILE="/tmp/wds_info_all.json"

#获取设备信息函数
radiolist=$(jq -r '.wireless.radiolist[]' $DEVINFO_JSON_FILE)
for row in $(echo "${radiolist}" | jq -r '. | @base64'); do # 遍历radiolist数组中的每一组
    _jq() {
      echo ${row} | base64 --decode | jq -r ${1}
    }
    support_wds=$(_jq '.support_wds') # 获取当前组的support_wds的值
    if [ "$support_wds" == "true" ] ;then # 判断support_wds是否为true
		radio_name=$(_jq '.name' $DEVINFO_JSON_FILE)
		wds_bss=$(_jq '.wds_bss' $DEVINFO_JSON_FILE)
		cpe_bridge_interface=$(_jq '.cpe_bridge_interface' $DEVINFO_JSON_FILE)
        break 
		# 输出第一个符合条件的wds_bss值后退出循环
    fi
done

#判断上传目录是否存在，不存在就创建这个目录 
if [ ! -d "$UPLOAD_FILE_DIR" ]; then
	mkdir -p "$UPLOAD_FILE_DIR" >/dev/null 2>&1
fi

exec 33>"$UPLOAD_LOCK"
flock -n 33 || exit 1

role=$(uci -q get wireless.${radio_name}.ApCliEnable)

if [ "$role" = "1" ];then
	role="cpe"
	wds_interface=$cpe_bridge_interface

	content=$(wlanconfig ${wds_interface} show_apcli_list)
	linkStat=$(wlanconfig ${wds_interface} show_apcli_list|grep connStatus|awk -F ':' '{print $2}')
	# 返回值非法(非数字，没有值) ，返回空字符串""   
	pingTime=""
	if [ "$linkStat" = ""  ]; then
			linkStat="0"
	fi
	current_pingTime=$(cat /tmp/.tipc_ping_time)
	#echo "$pingTime_num"|[ -n "'sed -n '/^[0-9][0-9]*$/p''" ]
	if [ "$current_pingTime" = "timeout" ];then
		pingTime=""
	else
		pingTime_num=$(cat /tmp/.tipc_ping_time|awk -F 'm' '{print $1}')  
		pingTime="$pingTime_num"
		   
	fi

	rxFlow=$(echo "${content}" |grep rxflow|awk -F ':' '{print $2}')
	txFlow=$(echo "${content}" |grep txflow|awk -F ':' '{print $2}')
	channf=$(echo "${content}" |grep floornoise|awk -F ':' '{print $2}')
	chutil=$(echo "${content}" |grep utilization|awk -F ':' '{print $2}')
	antenna1=$(echo "${content}" |grep rssiMulti|awk -F ':' '{print $2}'|awk -F '/' '{print $1}')
	antenna2=$(echo "${content}" |grep rssiMulti|awk -F ':' '{print $2}'|awk -F '/' '{print $2}')
	txRate=$(echo "${content}" |grep txrate|awk -F ':' '{print $2}')
	rxRate=$(echo "${content}" |grep rxrate|awk -F ':' '{print $2}')
	peerRaMac=$(echo "${content}" |grep bssid|awk -F 'bssid:' '{print $2}' )
	raMac=$(ifconfig "$wds_interface"|grep HWaddr|awk -F ' ' '{print $5}')
	devMac=$(cat /proc/rg_sys/sys_mac)
	
	if [ ! -f "$TMP_LIST_FILE" ]; then
		echo "the wds_info_all.json is not existed!"
		sn=""
	else
		sn=$(jq -c '.list_all[].list_pair[]' $TMP_LIST_FILE | while IFS= read -r pair; do
			athmac=$(echo "$pair" | jq -r '.athmac' | awk '{print toupper($0)}')
			if [ "$raMac" = "$athmac" ]; then
				echo $(echo "$pair" | jq -r '.sn')
				break
			fi
		done)
		if [ -z "$sn" ]; then
			echo "the sn is null !"
			sn=""
		fi
	fi
	json_init
	json_add_string 'sn' "$sn"
	json_add_string 'role' "$role"
	json_add_string 'devMac' "$devMac"
	json_add_string 'raMac' "$raMac"
	json_add_string 'linkStat' "$linkStat"
	json_add_string 'pingTime' "$pingTime"
	json_add_string 'chutil' "$chutil"
	json_add_string 'channf' "$channf"
	json_add_string 'rxFlow' "$rxFlow"
	json_add_string 'txFlow' "$txFlow"
	
	json_add_array 'devList'
	
	json_add_object '0'
	json_add_string 'peerRaMac' "$peerRaMac"
	json_add_string 'antenna1' "$antenna1"
	json_add_string 'antenna2' "$antenna2"
	json_add_string 'txRate' "$txRate"
	json_add_string 'rxRate' "$rxRate"
	json_close_object
	
	json_close_array

else
	role="ap"
	wds_interface=$wds_bss
	wlanconfig ${wds_interface} list > /tmp/wdslinkqualityrlog.tmp
	sed -i '1d' $TMP_FILE
	peerRaMac=$(cat "${TMP_FILE}"|awk -F ' ' '{print $1}'|tail -n1)
	line_number=$(cat "${TMP_FILE}" |wc -l)
	#echo "line_number=$line_number"
	if [ $line_number -gt 0 ];then
	   linkStat="1"
	else   
	   linkStat="0"
	fi
	   
	   
	# 返回值非法(非数字，没有值) ，返回空字符串""   
	pingTime=""
	rxFlow=""
	txFlow=""
	raMac=$(ifconfig "$wds_interface"|grep HWaddr|awk -F ' ' '{print $5}')
	devMac=$(cat /proc/rg_sys/sys_mac)
	
	if [ ! -f "$TMP_LIST_FILE" ]; then
		echo "the wds_info_all.json is not existed!"
		sn=""
	else
		sn=$(jq -c '.list_all[].list_pair[]' $TMP_LIST_FILE | while IFS= read -r pair; do
			athmac=$(echo "$pair" | jq -r '.athmac' | awk '{print toupper($0)}')
			if [ "$raMac" = "$athmac" ]; then
				echo $(echo "$pair" | jq -r '.sn')
				break
			fi
		done)
		if [ -z "$sn" ]; then
			echo "the sn is null !"
			sn=""
		fi
	fi
	json_init
	json_add_string 'sn' "$sn"
	json_add_string 'role' "$role"
	json_add_string 'devMac' "$devMac"
	json_add_string 'raMac' "$raMac"
	json_add_string 'linkStat' "$linkStat"
	json_add_string 'pingTime' "$pingTime"
	json_add_string 'rxFlow' "$rxFlow"
	json_add_string 'txFlow' "$txFlow"
	json_add_array 'devList'
	#echo ${content} > /tmp/wdslinkqualityrlog.tmp
	line_num="0"
	while read line 
	do
		#echo "line=$line"
		
		channf=$(echo ${line} |awk -F ' ' '{print $10}')
		chutil=$(echo ${line}|awk -F ' ' '{print $9}')
		antenna1=$(echo ${line}|awk -F ' ' '{print $6}'|awk -F '/' '{print $1}')
		antenna2=$(echo ${line}|awk -F ' ' '{print $6}'|awk -F '/' '{print $2}')
		txRate=$(echo ${line}|awk -F ' ' '{print $4}')
		rxRate=$(echo ${line}|awk -F ' ' '{print $5}')
		
		json_add_object '${line_num}'
		json_add_string 'peerRaMac' "$peerRaMac"
		json_add_string 'antenna1' "$antenna1"
		json_add_string 'antenna2' "$antenna2"
		json_add_string 'txRate' "$txRate"
		json_add_string 'rxRate' "$rxRate"
		json_add_string 'chutil' "$chutil"
		json_add_string 'channf' "$channf"
		json_close_object
		line_num=$(expr $line_num + 1)
		
	done < /tmp/wdslinkqualityrlog.tmp
	json_close_array
fi
json_dump > "$UPLOAD_FILE"
flock -u 33
