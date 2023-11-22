#!/bin/sh

set_sta_bssid() {
	line_count=`wlanconfig ath0 list sta | wc -l`
	sta_count=`wlanconfig ath0 list sta | grep -c "ADDR"`

	#setting the white list of mac address.
	`iwpriv ath0 maccmd 1`
	if [ ${sta_count} != "0" ] ;then
		for i in `seq 2 ${line_count}`
		do
			sta_bssid=`wlanconfig ath0 list sta | sed -n ${i}p | cut -d ' ' -f 1`
			`uci add_list wireless.wds.sta_bssid=${sta_bssid}`
			maccmd_val=$(iwpriv ath0 get_maccmd | awk -F ':' '{print $2}')
			if [ ${maccmd_val} = "0" ] ; then
					`iwpriv ath0 maccmd 1`
			fi
			`iwpriv ath0 addmac ${sta_bssid}`
		done
		`uci commit wireless`
	fi
}

#check whether the lock_value was "1",if yes, exeuting write wireless driver.
while true
do
	# check wds AP/CPE mode.
	wds_mode=$(uci get wireless.wds.mode)

	# AP mode, setting the sta bssid.
	if [ ${wds_mode} = "ap" ] ; then
		lock_value=`cat /sys/class/gpio/gpio3/value`
		if [ ${lock_value} = "1" ] ; then
			if [ $(cat /etc/config/wireless | grep -c "sta_bssid") = "0" ] ; then
				set_sta_bssid
			else
				maccmd_val=$(iwpriv ath0 get_maccmd | awk -F ':' '{print $2}')
				# unreasonable reboot. checking current wireless configuration, and then, write sta_bssid to driver.
				if [ ${maccmd_val} = "0" ] ; then
					`iwpriv ath0 maccmd 1`

					# haved to read the last saved sta_bssid from the wds configuration.
					# Note: can't read data from the associated list, because
					# other device suddenly association when AP reboot.
					colon_val=$(uci get wireless.wds.sta_bssid | tr -cd : | wc -c)
					loop_cnt=`expr ${colon_val} / 5`
					for i in `seq 1 ${loop_cnt}`
					do
						sta_bssid=$(uci get wireless.wds.sta_bssid | cut -d ' ' -f $i)
						`iwpriv ath0 addmac ${sta_bssid}`
					done
				else
					# method: Preventing the configurations of wireless are not taking effect
					if [ $(iwpriv ath0 getmac | wc -l) = "0" ] ; then
						colon_val=$(uci get wireless.wds.sta_bssid | tr -cd : | wc -c)
						loop_cnt=`expr ${colon_val} / 5`
						for i in `seq 1 ${loop_cnt}`
						do
							sta_bssid=$(uci get wireless.wds.sta_bssid | cut -d ' ' -f $i)
							`iwpriv ath0 addmac ${sta_bssid}`
						done
					fi
				fi
			fi
		else
			if [ $(cat /etc/config/wireless | grep -c "sta_bssid") != "0" ] ; then
				`uci del wireless.wds.sta_bssid | uci commit wireless | iwpriv ath0 maccmd 0 | iwpriv ath0 maccmd 3`
			fi
		fi
	else
		# CPE mode, writting AP's bssid into the driver.
		echo "writting AP's bssid into the driver."
	fi
	sleep 2
done
