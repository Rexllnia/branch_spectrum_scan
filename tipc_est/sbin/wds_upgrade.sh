#!/bin/sh
serial_number=$1
version_name=$2

rm -rf /tmp/firmware.img 2>/dev/null
[ "$serial_number" ==  "" ] && echo "serial_number is NULL!please input sn"  && exit 0
[ "$version_name" ==  "" ] && echo "version_name is NULL!please input version_name"  && exit 0
cd /tmp/
# 如果tipc下载过程中出现错误，返回值一定不是“DOWNLOAD-OK”字符串
strerr=$(rg_tipc_client_download $serial_number $version_name)
#echo "strerr $strerr"
[ "$strerr" != "DOWNLOAD-OK" ] && rm -rf /tmp/firmware.img 2>/dev/null
