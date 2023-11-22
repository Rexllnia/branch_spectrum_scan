if [ "$ACTION" = "up" ] && [ "$DEVICE" = "switch0" ] ;then
		touch /tmp/rg_config/wan_state_up
elif [ "$ACTION" = "down" ] && [ "$DEVICE" = "switch0" ];then                          
		rm -rf /tmp/rg_config/wan_state_up
fi

