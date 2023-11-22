#!/bin/sh

MODE_GPIO=2
LOCK_GPIO=3

est_wds_gpio_read() {
    local gpio_value=$1
    local dev_type=$2
    local gpio_result
    local uci_mode

    gpio_result=$(cat /sys/class/gpio/gpio${gpio_value}/value) 2>/dev/null
    if [ $gpio_value -eq $MODE_GPIO ]; then
        if [ "$dev_type" == "p2p" ]; then
            uci_mode=$(uci -q get wireless.@wifi-iface[0].mode)
            [ "$uci_mode" == "sta" ] && gpio_result=0
            [ "$uci_mode" == "ap" ] && gpio_result=1
        fi
    elif [ $gpio_value -eq $LOCK_GPIO ]; then
        # p2p模式没有拨码按键，锁按键全部虚拟为lock状态
        if [ "$dev_type" == "p2p" ] || [ "$gpio_result" == "" ]; then
            gpio_result=1
        fi
    fi
    echo "$gpio_result"
}
