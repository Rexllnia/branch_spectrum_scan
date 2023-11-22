#!/bin/sh
# 包含统一函数库
sleep 10
. /usr/share/libubox/jshn.sh
local LOG_FILE=/tmp/rg_config/wds_gpio_sh.log
debug() 
{
    local time=$(date "+%H:%M:%S")
    if [ -e ${LOG_FILE} ]; then
        wifi_status_monitor_log_byte=$(ls -l ${LOG_FILE} | awk '{print $5}')
        [ ${wifi_status_monitor_log_byte} -gt 10000 ] && { sed -i '1,50d' ${LOG_FILE};}
    fi
    echo -e "[$time][$$]$1"  >> ${LOG_FILE}
}

DEVINFO_JSON_FILE="/tmp/rg_device/rg_device.json"
dev_model=$(jq -r '.dev_model' $DEVINFO_JSON_FILE)
while [[ -z $dev_model ]]
do
    sleep 2
    dev_model=$(jq -r '.dev_model' $DEVINFO_JSON_FILE)
done
debug "dev_model=$dev_model"

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
		break # 赋值第一个符合条件的值后退出循环
    fi
done
debug "radio_name=$radio_name"
debug "wds_bss=$wds_bss"
debug "cpe_wds_name=$cpe_wds_name"

rssi_light_mode=$(jq -r '.rssi_light_mode' $DEVINFO_JSON_FILE)
debug "rssi_light_mode=$rssi_light_mode"

r1_blink_r2_off_r3_off()
{
    led_send_message "sysrssi;wds_blink" > /dev/null
    led_send_message "rssi;worse" > /dev/null
}
r1_on_r2_off_r3_off()
{
    led_send_message "sysrssi;wds_on" > /dev/null
    led_send_message "rssi;bad" > /dev/null
}
r1_on_r2_blink_r3_off()
{
    led_send_message "sysrssi;wds_on" > /dev/null
	led_send_message "rssi;weak" > /dev/null
}
r1_on_r2_on_r3_off()
{
    led_send_message "sysrssi;wds_on" > /dev/null
	led_send_message "rssi;normal" > /dev/null
}
r1_on_r2_on_r3_blink()
{
    led_send_message "sysrssi;wds_on" > /dev/null
	led_send_message "rssi;good" > /dev/null
}
r1_on_r2_on_r3_on()
{
    led_send_message "sysrssi;wds_on" > /dev/null
    led_send_message "rssi;better" > /dev/null
}

wds_status()
{
    ap_status="0"
    #MTK用MT7663_1.ApCliEnable字段判断设备模式，1为CPE，0为AP
    apcli_enable=`uci -q get wireless.$radio_name.ApCliEnable`
    debug "apcli_enable=$apcli_enable"
    if [ "$apcli_enable" == "1" ] ;then
        ap_mode="sta"
    else
        ap_mode="ap"
    fi
    debug "ap_mode=$ap_mode"
    #判断是否有设备桥接
    if [ "$ap_mode" == "ap" ] ;then
        #AP的桥接口从设备能力表读出$wds_bss
        ap_wds=`wlanconfig $wds_bss list | grep $wds_bss | wc -l`
        if [ $ap_wds -ge 1 ] ;then
            ap_status="1"
        fi
    fi
    if [ "$ap_mode" == "sta" ] ;then
	    #cpe的wds口暂时只有apcli0或者apclii0
	    apcli_connStatus=`wlanconfig $cpe_wds_name show_apcli_info|awk -F ':' '{print $2}'`
        if [ "$apcli_connStatus" == "1" ] ;then
            ap_status="1"
        fi
    fi	
    # 0 表示没有设备接入，两个灯闪烁  	
    if [ "$ap_status" == "0" ] ;then
	    led_send_message "sysrssi;wds_blink" > /dev/null
        #兼容est300，其他est产品没有这个指示灯，不会有影响
        led_send_message "rssi;default" > /dev/null
    fi
    debug "ap_status=$ap_status"
    # 1 表示目前有桥接设备接入，但是需要判断信号强度来闪烁
    if [ "$ap_status" == "1" ] ;then
	    if [ "$ap_mode" == "ap" ] ;then
            assoc_list=`wlanconfig $wds_bss list| grep $wds_bss | awk '{print $6}' | grep -v RSSI | awk -F '/' 'BEGIN{n=1;max=-1000;nu=0}{for(n=1;n<=NF;n++){a[$n]=$n;if(a[$n]!=0&&a[$n]>=max)max=a[$n]}{print max}{max=-1000}}'`
			assoc_item_tmp=-1000
            for assoc_item in $assoc_list ;do
                if [[ $assoc_item -ge $assoc_item_tmp ]] ;then
                    assoc_item_tmp=$assoc_item
                fi
            done
		fi
        if [ "$ap_mode" == "sta" ] ;then
            assoc_item=`wlanconfig $cpe_wds_name show_apcli_list| grep rssi: | awk -F ':' '{printf $2}'`  
            assoc_item_tmp=-1000
            if [ $assoc_item -ge $assoc_item_tmp ] ;then
                assoc_item_tmp=$assoc_item
            fi		
        fi
        debug "assoc_item_tmp=$assoc_item_tmp"
        if [ "$rssi_light_mode" == "2" -o "$rssi_light_mode" == "" ]; then
        #echo "rssi:$assoc_item_tmp"
            if [ $assoc_item_tmp -lt -75 ] ;then
                r1_blink_r2_off_r3_off
            elif [ $assoc_item_tmp -ge -75 -a $assoc_item_tmp -lt -73 ] ;then
                r1_on_r2_off_r3_off
            elif [ $assoc_item_tmp -ge -73 -a $assoc_item_tmp -lt -71 ] ;then
                r1_on_r2_blink_r3_off
            elif [ $assoc_item_tmp -ge -71 -a $assoc_item_tmp -lt -68 ] ;then
                r1_on_r2_on_r3_off
            elif [ $assoc_item_tmp -ge -68 -a $assoc_item_tmp -lt -64 ] ;then
                r1_on_r2_on_r3_blink
            elif [ $assoc_item_tmp -ge -64 ] ;then
                r1_on_r2_on_r3_on
            fi
        elif [ "$rssi_light_mode" == "1" ] ;then                                          
            if [ $assoc_item_tmp -lt -78 ] ;then
                r1_blink_r2_off_r3_off
			elif [ $assoc_item_tmp -ge -78 -a $assoc_item_tmp -lt -72 ] ;then
                r1_on_r2_off_r3_off
            elif [ $assoc_item_tmp -ge -72 -a $assoc_item_tmp -lt -65 ] ;then
                r1_on_r2_on_r3_off
            elif [ $assoc_item_tmp -ge -65 ] ;then
                r1_on_r2_on_r3_on
            fi
        fi
    fi
}

while true
do
    wds_status
    sleep 5s
done
