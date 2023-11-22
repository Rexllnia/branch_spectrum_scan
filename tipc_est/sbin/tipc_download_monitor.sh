#!/bin/sh

period_cnt=5
ageing_time=240
loop_cnt=`expr $ageing_time / $period_cnt`

# 检查rg_tipc_client_download是否正在下载，如果正在下载将该进程先删除，重新启动
tftp_num=$(ps |grep -w rg_tipc_client_download | grep -v grep | wc -l)
if [ $tftp_num -gt 0 ]; then
    killall rg_tipc_client_download && echo "rg_tipc_client_download is downloading bin!!! kill!!!"
    return
fi

# 五分钟的老化时间。如果五分钟不到就完成下载，则结束。如果五分钟还没下载完成
# 需要将tftp-hpa进程杀掉，并删除下载的临时文件。
for i in $(seq 1 $loop_cnt)
do
    sleep 5
    tftp_num=$(ps |grep -w rg_tipc_client_download | grep -v grep | wc -l)
    [ $tftp_num -eq 0 ] && echo "rg_tipc_client_download end!" && return
    echo "i $i"

    sev_upgrd_num=$(ps |grep -w rg_tipc_server_upgrade | grep -v grep | wc -l)
    [ $sev_upgrd_num -eq 0 ] && echo "master process no exist!!!" && killall rg_tipc_client_download
done

tftp_num=$(ps |grep -w rg_tipc_client_download | grep -v grep | wc -l)
if [ $tftp_num -gt 0 ]; then
    rm -rf /tmp/firmware.img && killall rg_tipc_client_download && echo "rg_tipc_client_download timeout!!! kill!!!"
    return
fi