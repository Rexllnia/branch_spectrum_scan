#!/bin/sh
# 一键易联脚本
# history
# V1.0 : initial version
#
. /usr/share/libubox/jshn.sh
. /lib/config/uci.sh
. /usr/bin/adminCheck

LOG_FILE=/tmp/rg_config/one_click_connect.log
debug()
{
    local time=$(date "+%H:%M:%S")
    if [ -e ${LOG_FILE} ]; then
        one_click_connect_log_byte=$(ls -l ${LOG_FILE} | awk '{print $5}')
        [ ${one_click_connect_log_byte} -gt 10000 ] && { sed -i '1,50d' ${LOG_FILE};}
    fi
    echo -e "[$time][$$]$1"  >> ${LOG_FILE}
}

# 从设备能力表获取桥接口和管理口
DEVINFO_JSON_FILE="/tmp/rg_device/rg_device.json"
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
		radio_name=$(_jq '.name' $DEVINFO_JSON_FILE)
		wds_bss=$(_jq '.wds_bss' $DEVINFO_JSON_FILE)
		cpe_wds_name=$(_jq '.cpe_bridge_interface' $DEVINFO_JSON_FILE)

		while [[ -z $radio_name ]] || [[ -z $wds_bss ]] || [[ -z $cpe_wds_name ]]
		do
			sleep 2
			radio_name=$(_jq '.name' $DEVINFO_JSON_FILE)
			wds_bss=$(_jq '.wds_bss' $DEVINFO_JSON_FILE)
			cpe_wds_name=$(_jq '.cpe_bridge_interface' $DEVINFO_JSON_FILE)
		done
    fi
	support_manage=$(_jq '.support_manage') # 获取当前组的 support_manage 的值
	while [[ -z $support_manage ]]
	do
		sleep 2
		support_manage=$(_jq '.support_manage')
	done
	if [ "$support_manage" == "true" ] ;then # 判断support_manage是否为true
		manage_bss=$(_jq '.manage_bss' $DEVINFO_JSON_FILE)
		while [[ -z $manage_bss ]]
		do
			sleep 2
			manage_bss=$(_jq '.manage_bss' $DEVINFO_JSON_FILE)
		done
    fi
done

debug "radio_name=$radio_name"
debug "wds_bss=$wds_bss"
debug "manage_bss=$manage_bss"
debug "cpe_wds_name=$cpe_wds_name"

encrypt()
{
    local passwd=$1
    echo -n "$passwd"| /usr/sbin/rg_crypto enc -t C
}

dev_set_config() {
    local module=$1
    local func=$2
    local json_str=$3

        debug "Call ${func} set -m $module $json_str"
        echo ${func} set -m "${module}" "${json_str}"
        dev_sta_cmd="${func} set -m ${module} ${json_str}"
        debug "dev_sta_cmd=$dev_sta_cmd"
        `eval $dev_sta_cmd`

}

#MTKMTwireless.$radio_name.ApCliEnable字段判断设备模式，1为CPE，0为AP
apcli_enable=`uci -q get wireless.$radio_name.ApCliEnable`
if [ "$apcli_enable" == "1" ] ;then
    wdsmode="sta"
else
    wdsmode="ap"
fi

debug "wdsmode=$wdsmode"

passwd=`uci -q get wireless.$radio_name.ApCliWPAPSK`
ciphertext=`encrypt "$passwd"`
country=`uci -q get wireless.$radio_name.country`
ssidName=`uci -q get wireless.$radio_name.ApCliSsid`


if [ "$wdsmode" == "ap" ] ;then
    #AP的桥接口从设备能力表读出$wds_bss
    iwpriv $wds_bss set one_click_status=1;
    debug "iwpriv $wds_bss set one_click_status=1"
fi
if [ "$wdsmode" == "sta" ] ;then
    #cpe先转换成ap,再一键易联
    json_init;
    json_add_string 'pw' $ciphertext;
    json_add_string 'wdsmode' "ap";
    json_add_string 'country' $country;
    json_add_string 'ssidName' $ssidName;
    filtered_wds_json=$(json_dump)
    wds_json=$(echo "$filtered_wds_json" | tr -d ' ')
    wds_json="'$wds_json'"
    # wds_json="'{\"pw\":\"$ciphertext\",\"wdsmode\":\"ap\",\"country\":\"$country\",\"ssidName\":\"$ssidName\"}'"
    dev_set_cmd="dev_sta set --module \"wdsmode_switch\" ${wds_json}"
    # `eval $dev_set_cmd`
    echo "dev_set_cmd:$dev_set_cmd"
    # echo "OneClickConnect : Switch the AP mode"
    # iwpriv $wds_bss set one_click_status=1;
fi
#dev_sta set --module 'wdsmode_switch' '{ "pw": "U2FsdGVkX19\/FuiLm+tLA8IkXzV73YGDh8fZ3qV4Q91ARsMswkcSuw+S68VrcBgk", "wdsmode": "ap", "country": "CN", "ssidName": "@Ruijie-wds-0809" }'


