#!/bin/sh

# 功能说明：本功能是由于cpe模式下新增管理ssid引入兼容新问题
# 新增全网管理ssid时，将隐藏管理ssid disable，删除全网管理ssid时，将隐藏管理ssid enable。始终保持桥接ssid的mac地址为06
# 注：兼容新问题（黑白名单下，cpe新增管理ssid会导致桥接ssid的mac地址分配变为0A，而白名单列表中mac地址为06）
RMT_MNGSSID_LOG="/tmp/rg_config/HYStest.log"
echo "HYSHYSHYSHYSHYSHYSY" >> "$RMT_MNGSSID_LOG"
[ -z "$1" ] && echo "sn is nil!" && return

if [ "$2" == "false" ]; then
    value=0
elif [ "$2" == "true" ]; then
    value=1
else
    echo "param2 error!"
    return
fi

# 如果sn为本机的话，直接使用uci配置
if [ "$1" == "$(cat /proc/rg_sys/serial_num)" ]; then
    uci set wireless.@wifi-iface[1].disabled=$value && uci commit wireless
    return
fi

# 如果sn不是本机的话，使用tipc远程调用
rg_est_wds_sync $1 << EOF 
uci set wireless.@wifi-iface[1].disabled=$value && uci commit wireless
EOF
