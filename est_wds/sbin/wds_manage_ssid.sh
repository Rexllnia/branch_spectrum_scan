#!/bin/sh

lock_led=3
mode_value=2
lock_value=1
idx=0
ath_cnt=0
# 倒计时变量
timer_start=0
total_time=0
# 总倒计时
countdown=7200
countdown=`expr $countdown / 5`
# 关联掉线
link_down=0
# 关联掉线时长
link_time=300
link_time=`expr $link_time / 5`

#
# 获取ath的索引值
#
get_ath_index()
{
	wireless=`eval dev_cap get --module "wireless"`
	DEF_IFACE_MAX=$(echo $wireless | jq -r '.ap_wlan_num')
	vap_max_num=`expr $DEF_IFACE_MAX - 1`
	
	ap_list=`ls /sys/class/net/ | grep ath`
	for ap_item in $ap_list
	do
		wds_flag=`iwpriv $ap_item get_wds | awk -F ':' '{print $2}' | tr -d '"'`
		[ $wds_flag -eq 0 ] && ath_name=$ap_item
		[ $wds_flag -eq 1 ] && wds_ath=$ap_item && continue
		for idx in `seq 0 $vap_max_num`
		do
			[ -z "$(uci -q get wireless.@wifi-iface[$idx])" ] && return 1
			essid_val=`iwconfig $ath_name | grep ESSID | awk -F ':' '{print $2}' | tr -d '"'`
			if [ $essid_val = `uci -q get wireless.@wifi-iface[$idx].ssid` ] ; then
				return 0
			fi
		done
	done
	return 1
}

# 非桥接设备无该功能
dev_type=$(dev_cap get -m dev_type)
[ $dev_type = "eap" ] && return

#
# 检查关联连续断线5min,释放管理ssid
#
check_link_drop_five()
{
	if [ $link_down -ge $link_time ]; then
		timer_start=0
		link_down=0
		drv_hide_value=`iwpriv $ath_name get_hide_ssid | cut -d ':' -f 2`
		[ $drv_hide_value -eq 1 ] && `iwpriv $ath_name hide_ssid 0`
		return 1
	fi
	wds_list=$(wlanconfig $wds_ath list)
	# 如果倒计时过程中出现关联掉线，重新开始倒计时
	[ -z "${wds_list}" ] && let "link_down+=1" || link_down=0

	return 0
}

#
# 检查ap-cpe状态是否有切换
# 返回值：0-ap/cpe已切换   1-ap/cpe未切换
#
ap_cpe_switch()
{
	tmp_mode=$(cat /sys/class/gpio/gpio${mode_value}/value)
	if [ $tmp_mode != $ap_mode ]; then
		ap_mode=$tmp_mode
		timer_start=0
		return 0
	fi
	return 1
}

ap_mode=$(cat /sys/class/gpio/gpio${mode_value}/value)
while true
do
	if [ ${ath_cnt} -eq 0 ]; then
		sleep 5
		ath_cnt=`ls /sys/class/net/ | grep ath | wc -l`
		if [ ${ath_cnt} -gt 0 ]; then
			get_ath_index
			ret=$(echo $?)
			if [ $ret -eq 1 ]; then
				echo "ath_name $ath_name" >> /tmp/manage_ssid.log
				echo "idx $idx" >> /tmp/manage_ssid.log
				return
			fi
		fi
		[ ${ath_cnt} -eq 0 ] && continue
	fi
	if [ ${total_time} -eq 0 ]; then
		if [ $(uci -q get wireless.@wifi-iface[$idx].hidden) -eq 0 ]; then
			`uci set wireless.@wifi-iface[$idx].hidden=1 && uci commit wireless`
		fi
	fi
	lock_value=$(cat /sys/class/gpio/gpio$lock_led/value)
	if [ ${lock_value} = "1" ]; then
		# 物理锁定2小时后，检查ap-cpe状态切换
		ap_cpe_switch
		# 锁定时，当整机重启需要进行倒计时隐藏。
		if [ ${timer_start} -eq 0 ]; then
			for timer_start in `seq 1 $countdown`
			do
				# 检测关联连接状态
				check_link_drop_five
				[ $(echo $?) -eq 1 ] && break
				drv_hide_value=`iwpriv $ath_name get_hide_ssid | cut -d ':' -f 2`
				# 倒计时2小时内出现wifi重启，ssid重新释放。
				if [ ${drv_hide_value} -eq 1 ]; then
					`iwpriv $ath_name hide_ssid 0`
				fi
				# 如果检测到lock状态发生变化，停止倒计时
				[ $(cat /sys/class/gpio/gpio$lock_led/value) -eq 0 ] && timer_start=0 && break
				# 物理锁定2小时内，检查ap-cpe状态切换
				ap_cpe_switch
				[ $(echo $?) -eq 0 ] && break
				sleep 5
			done
			if [ ${timer_start} -ge $countdown ]; then
				`iwpriv $ath_name hide_ssid 1`
			fi
		else
			# 检测关联连接状态
			check_link_drop_five
			[ $(echo $?) -eq 1 ] && continue
			drv_hide_value=`iwpriv $ath_name get_hide_ssid | cut -d ':' -f 2`
			if [ ${drv_hide_value} -eq 0 ]; then
				`iwpriv $ath_name hide_ssid 1`
			fi
		fi
	else
		# lock-->unlock重置锁定标志位和倒计时变量值
		timer_start=0
		link_down=0
		drv_hide_value=`iwpriv $ath_name get_hide_ssid | cut -d ':' -f 2`
		# 如果驱动已经隐藏管理ssid，则释放出管理ssid 
		if [ ${drv_hide_value} -eq 1 ]; then
			`iwpriv $ath_name hide_ssid 0`
		fi
	fi
	let "total_time+=1"
	sleep 5
done
