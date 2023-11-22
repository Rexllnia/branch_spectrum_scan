#!/bin/sh
sleep 10
LOG_FILE=/tmp/rg_config/wds_manage_ssid.log
debug() 
{
    local time=$(date "+%H:%M:%S")
    if [ -e ${LOG_FILE} ]; then
        wifi_status_monitor_log_byte=$(ls -l ${LOG_FILE} | awk '{print $5}')
        [ ${wifi_status_monitor_log_byte} -gt 10000 ] && { sed -i '1,50d' ${LOG_FILE};}
    fi
    echo -e "[$time][$$]$1"  >> ${LOG_FILE}
}
# 倒计时变量
timer_start=0
# 总倒计时
countdown=7200
countdown=`expr $countdown / 5`
# 关联掉线
link_down=60
# 关联掉线时长
link_time=300
link_time=`expr $link_time / 5`
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

# 连接状态标志位，0-断桥，1-桥接
ap_status=0

#自身获取端口状态，生成状态文件
port_status=$(swconfig dev switch0 show | grep port:0 |awk -F ':' '{printf $4}')
debug "$port_status"
if [ "$port_status" != "down" ]
then  
touch /tmp/rg_config/wan_state_up 
debug "touch wan_state_up byself"
fi

#
#获取当前桥接状态
#返回值：0-桥接上  1-未桥接
#
get_ap_status()
{
    ap_status=0
	#MTKMTwireless.$radio_name.ApCliEnable字段判断设备模式，1为CPE，0为AP
    apcli_enable=`uci -q get wireless.$radio_name.ApCliEnable`
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
            ap_status=1
			link_down=0
			return 0
        fi		
    fi
    if [ "$ap_mode" == "sta" ] ;then
	    #cpe固定wds口为apcli0
        sta_wds=`iwconfig $cpe_wds_name| grep 'ESSID'|awk -F ':' '{printf $2}' | sed 's/\"//g'`
        if [ $sta_wds ] ;then
            ap_status=1
			link_down=0
			return 0
        fi
    fi
    return 1	
}

#
# 检查关联连续断线5min,释放管理ssid
#返回值：0-未断联5min  1-断联已达5min
#


ssid_hidde_state()
{
	local hidde=$1
	local ssid=$2
	local uci_hidde=$(uci -q get wireless.$manage_bss.hidden)
	if [ "$hidde" != "$uci_hidde" ] ;then
		`uci set wireless.$manage_bss.hidden=$hidde`
		`uci commit wireless`
		`iwpriv $manage_bss set HideSSID=$hidde`
		debug "iwpriv $manage_bss set HideSSID=$hidde && iwpriv $manage_bss set SSID=$ssid"
	fi
}

check_link_drop_five()    #
{
    if [ $link_down -ge $link_time ]; then
        timer_start=0
        drv_hide_value=` uci get wireless.$manage_bss.hidden`
		
		debug "link down > 5min,release ssid!!!"
		[ $drv_hide_value -eq 1 ] && ssid_hidde_state "0" "$1"
		
        sleep 5
        return 1
    fi
	get_ap_status
    # 如果倒计时过程中出现关联掉线，重新开始倒计时
	if [ $? -eq 1 ] ;then
		let "link_down+=1"
	else
		link_down=0
	fi
    return 0
}

#
# 检查ap-cpe状态是否有切换
# 返回值：0-ap/cpe已切换   1-ap/cpe未切换
#
ap_cpe_switch()
{ 
    #AP默认ApCliEnable字段为空，故ApCliEnable为空或0时，都代表是AP
	apcli_enable_tmp=`uci -q get wireless.$radio_name.ApCliEnable`
    if [ "$apcli_enable_tmp" == "1" ] ;then
        ap_mode_tmp="sta"
    else
        ap_mode_tmp="ap"
    fi		                    
    if [ $ap_mode_tmp != $ap_mode ]; then
        ap_mode=$ap_mode_tmp
        timer_start=0
		debug "ap-cpe mode changes"
        return 0
    fi
    return 1
}


#非桥接设备无该功能
dev_type=$(dev_cap get -m dev_type)
[ $dev_type = "eap" ] && return

while true
do
    debug "ap_status=$ap_status"
    debug "timer_start=$timer_start"
    debug "link_down=$link_down"
    # 如果原始管理ssid被disable，就不进入隐藏流程
    if [ $(uci -q get wireless.$manage_bss.ssid_usrcfg) -eq 1 ]; then   
    # 将倒计时隐藏的参数清零，重新开始倒计时
        timer_start=0
        debug "manage ssid have been setting by user!!!"
        sleep 5
        continue
    fi
	
	uci_ssid=$(uci -q get wireless.$manage_bss.ssid)
	debug "ssid=$uci_ssid"
	
	# 如果端口down，强制释放管理ssid
	if [ ! -f "/tmp/rg_config/wan_state_up" ] && [ -f "/etc/hotplug.d/port/99-manage_ssid.sh" ];then	
		ssid_hidde_state "0" "$uci_ssid"
		timer_start=0
		debug "wan port state down"
	else
		get_ap_status				# 检测关联连接状态	
		if [ $? -eq 0 ] ;then
			ap_cpe_switch           
			for timer_start in `seq $timer_start $countdown`
			do
				if [ $(uci -q get wireless.$manage_bss.ssid_usrcfg) -eq 1 ]; then
				# 将倒计时隐藏的参数清零，重新开始倒计时
					timer_start=0
					debug "manage ssid have been setting by user!!!"
					break
				fi
				if [ ! -f "/tmp/rg_config/wan_state_up" ] && [ -f "/etc/hotplug.d/port/99-manage_ssid.sh" ];then 
					# 将倒计时隐藏的参数清零，重新开始倒计时
					timer_start=0
					debug "wan state down !!!"
					break					
				fi				
				get_ap_status
				[ $(echo $?) -eq 1 ] && break 
				ap_cpe_switch
				[ $(echo $?) -eq 0 ] && break				
				drv_hide_value=`uci get wireless.$manage_bss.hidden`  
				if [ ${drv_hide_value} -eq 1 ]; then
					debug "timer_start=$timer_start < $countdown[two hours],release"
					ssid_hidde_state "0" "$uci_ssid"
				fi
				debug "In circulation,timer_start=$timer_start"
				sleep 5
			done
			if [ ${timer_start} -ge $countdown ]; then    #关联时长达到2小时，隐藏ssid
				debug "timer_start=$timer_start >= $countdown[two hours],hide!!!!"
				ssid_hidde_state "1" "$uci_ssid"
				let "timer_start+=1"
			fi
		else
			check_link_drop_five "$uci_ssid"       #检测是否断开关联5min
			[ $(echo $?) -eq 1 ] && continue
			drv_hide_value=`uci get wireless.$manage_bss.hidden`
			if [ ${drv_hide_value} -eq 0 ]; then
				debug "link down < 5min,continue release ssid."
			else
				debug "link down < 5min,continue hidde ssid."
			fi
		fi
	fi
    sleep 5
done


#log文件大小限20k
if [ -e ${EST_MODEL_LOG} ]; then
    local est_model_log_byte=$(ls -l ${EST_MODEL_LOG} | awk '{print $5}')
    [ ${est_model_log_byte} -gt 20000 ] && { mv -f ${EST_MODEL_LOG} ${EST_MODEL_LOG}.old; }
fi