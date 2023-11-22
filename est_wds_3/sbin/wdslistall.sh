#!/bin/sh
# wdslistall.sh
# 获取终端信息，并组装成json文件，供rlogv2调用
# 参考sta_list的实现，目前不支持 page 和 size的读取方式(分页读取)
#
# history
# V0.1 : initial version
#
. /usr/share/libubox/jshn.sh
WDS_INFO_ALL_FILE="/tmp/wds_info_all.json"
UPLOAD_FILE_DIR="/tmp/ap_log/all/wdslistall"
UPLOAD_FILE="/tmp/ap_log/all/wdslistall/wdslistall"
DEVINFO_JSON_FILE="/tmp/rg_device/rg_device.json"

#获取桥接口的设备信息函数
radiolist=$(jq -r '.wireless.radiolist[]' $DEVINFO_JSON_FILE)
for row in $(echo "${radiolist}" | jq -r '. | @base64'); do # 遍历radiolist数组中的每一组
    _jq() {
      echo ${row} | base64 --decode | jq -r ${1}
    }
    support_wds=$(_jq '.support_wds') # 获取当前组的support_wds的值
    if [ "$support_wds" == "true" ] ;then # 判断support_wds是否为true
                radio_name=$(_jq '.name' $DEVINFO_JSON_FILE)
        break 
                # 输出符合条件的 radio_name 值后退出循环
    fi
done

if [ ! -d "$UPLOAD_FILE_DIR" ]; then
	mkdir -p "$UPLOAD_FILE_DIR" >/dev/null 2>&1
fi

role=$(uci -q get wireless.${radio_name}.ApCliEnable)

if [ "$role" = "1" ];then
	exit;
else
	[ -f "$WDS_INFO_ALL_FILE" ] && {
		cp "$WDS_INFO_ALL_FILE"  "$UPLOAD_FILE"
	}
fi 
