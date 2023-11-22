#!/bin/sh
ath_name=""
DEF_SSID="@Ruijie-wds"

wds_status()
{
    ap_status="0"
    ap_mode=`uci -q get wireless.@wifi-iface[0].mode`

    #判断是否有设备桥接
    ap_list=`ls /sys/class/net/ | grep ath` 
    for ap_item in $ap_list ;do
        #echo "$ap_item"
        wds_flag=`iwpriv $ap_item get_wds | awk -F ':' '{print $2}'`
        #echo "wds_flag $wds_flag"
        wds_flag=`echo $wds_flag`
        if [ "$wds_flag" == "1" ] ;then
            ath_name=$ap_item
            wds=`wlanconfig $ap_item list | wc -l`
            #echo "wds $wds"
            if [ $wds -gt 1 ] ;then
                ap_status="1"
                #echo "$ap_status"
                break
            fi
        fi
    done

    if [ "$ap_status" == "0" ] ;then
        # 0 表示没有设备接入，两个灯闪烁
        #echo "led blink"
        led_send_message "rssi1;wds_off" > /dev/null
        led_send_message "rssi2;wds_off" > /dev/null
        return
    fi

    # 1 表示目前有桥接设备接入，但是需要判断信号强度来闪烁
    if [ "$ap_status" == "1" ] ;then
        assoc_list=`wlanconfig $ath_name list| awk '{print $6}' | grep -v RSSI` 
        assoc_item_tmp=1000
        for assoc_item in $assoc_list;do
            assoc_item=`expr $assoc_item - 95`
            if [ $assoc_item -lt $assoc_item_tmp ] ;then
                assoc_item_tmp=$assoc_item
            fi
        done
        #echo "assoc_item_tmp $assoc_item_tmp"
        if [ $assoc_item_tmp -lt -69 ] ;then
            #echo "rssi led two light"
            led_send_message "rssi1;wds_blink" > /dev/null
            led_send_message "rssi2;wds_off" > /dev/null
        elif [ $assoc_item_tmp -ge -69 -a $assoc_item_tmp -lt -59 ] ;then
            led_send_message "rssi1;wds_on" > /dev/null
            led_send_message "rssi2;wds_off" > /dev/null
        elif [ $assoc_item_tmp -ge -59  ] ;then
            #echo "rssi led one light"
            led_send_message "rssi1;wds_on" > /dev/null
            led_send_message "rssi2;wds_on" > /dev/null
        fi
    fi
}

lock_led="3"
ap_value="2"
lock_value="1"
wds_lock_led()
{
    ap_mode=`uci -q get wireless.@wifi-iface[0].mode |tr -d ' '`
    now_value=`cat /sys/class/gpio/gpio$lock_led/value`
    bssid=`uci -q get wireless.@wifi-iface[0].bssid 2>/dev/null |tr -d ' ' |awk -F ':' '{print $6}'`
	ssid=`uci -q get wireless.@wifi-iface[0].ssid`
    maclist=`uci -q get wireless.@wifi-iface[0].maclist 2>/dev/null`
    # now_value 1 锁
    if [ "$now_value" == "1" ];then
        #echo "lock led light"
        #sta 模式下为空闪烁
        if [ "$ap_mode" == "sta" -a "$bssid" == "" -a "$ssid" == "$DEF_SSID" ] ;then
            led_send_message "lock;lock_off" > /dev/null
		#sta 模式下不为空，led、sys灯常亮
        elif [ "$ap_mode" == "sta" -a "$bssid" != "" ]; then
			led_send_message "lock;lock_on" > /dev/null
			led_send_message "wds_sync;begin" > /dev/null
		# sta 模式，桥接ssid为非缺省ssid时，lock/sys灯根据当前解锁状态闪烁
		elif [ "$ap_mode" == "sta" -a "$ssid" != "$DEF_SSID" ]; then
			undefault_ssid_unlock
		# AP模式下，缺省ssid且白名单列表为空，lock灯显示常暗
        elif [ "$ap_mode" == "ap" -a "$maclist" == "" -a "$ssid" == "$DEF_SSID" ] ;then
            led_send_message "lock;lock_off" > /dev/null
		# AP模式，桥接ssid为非缺省ssid时，lock/sys灯根据是否真正锁定，led灯分情况闪烁
		elif [ "$ap_mode" == "ap" -a "$ssid" != "$DEF_SSID" ]; then
			undefault_ssid_unlock
		#AP模式、lock状态，缺省ssid时且有白名单，lock灯常亮。sys灯指示cpe掉线情况
        elif [ "$ap_mode" == "ap" -a "$maclist" != "" ] ;then
            led_send_message "lock;lock_on" > /dev/null
            #在root模式下，如果白名单和实际的接入cpe个数不一致，system闪烁
            asso_list=`wlanconfig $ath_name  list | wc -l`
            if [ "$asso_list" != "0" ] ;then
                asso_list=`expr $asso_list - 1`
            fi

            # 总的白名单个数
            i=0
            for item_tmp in $maclist
            do
                i=`expr $i + 1`
            done

            #echo "maclist_num $i asso_list $asso_list maclist $maclist"
            if [ "$asso_list" == "$i" ] ;then
                #正常状态
                led_send_message "wds_sync;clear" > /dev/null
            else
                #非正常状态
                for item_tmp in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 18 16 18;
                do
                    #echo "asso_list $asso_list item_tmp $item_tmp"
                    if [ "$asso_list" == "$item_tmp"  ] ;then
                        led_send_message "wds_sync;end" > /dev/null
                        break
                    fi

                    led_send_message "wds_sync;begin" > /dev/null
                    sleep 1
                    led_send_message "wds_sync;end" > /dev/null
                    sleep 1
                    led_send_message "wds_sync;end" > /dev/null
                done
            fi
        fi
    else
        # lock 没有锁
        led_send_message "lock;lock_blink" > /dev/null
    fi
}

undefault_ssid_unlock()
{
	# 非锁定，即临时解锁状态，lock灭，sys灯闪烁关联个数
	tmp_lock=$(ls /tmp/ | grep tmp_lock)
	if [ -n "$tmp_lock" ]; then
		led_send_message "lock;lock_off" > /dev/null
	else # 锁定状态，lock/sys灯常亮
		led_send_message "lock;lock_on" > /dev/null
		led_send_message "wds_sync;begin" > /dev/null
	fi
}

#
# 物理锁定时，修改ssid名称为非缺省ssid，清除相应的配置
#
modify_ssidname_clear_config()
{
    ap_mode=`cat /sys/class/gpio/gpio${ap_value}/value`
    lock_value=`cat /sys/class/gpio/gpio${lock_led}/value`
	wds_ssid=$(uci -q get wireless.@wifi-iface[0].ssid)
	if [ "$wds_ssid" != "$DEF_SSID" ] && [ $lock_value -eq 1 ]; then
		if [ $ap_mode -eq 1 ]; then
			uci -q del wireless.@wifi-iface[0].macfilter
			uci -q del wireless.@wifi-iface[0].maclist
			iwpriv $ath_name maccmd 3
			iwpriv $ath_name maccmd 0
		elif [ $ap_mode -eq 0 ]; then
			uci -q del wireless.@wifi-iface[0].bssid
		fi
		uci commit wireless
	fi
}

while true
do
    wds_status
    wds_lock_led
	modify_ssidname_clear_config
    sleep 5
done
