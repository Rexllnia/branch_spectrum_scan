#include "rg_wds.h"

#define WDS_GET_GPIO_CMD_MODE_NUM                    "jq .wds_ypye /tmp/rg_device/rg_wds_gpio.json  | tr -d \"\\\""
#define WDS_GET_GPIO_CMD_LOCK_NUM                    "jq .wds_ypye /tmp/rg_device/rg_wds_gpio.json  | tr -d \"\\\""
#define WDS_GET_GPIO_CMD_MODE_AP_VALUVE              "jq .wds_ypye /tmp/rg_device/rg_wds_gpio.json  | tr -d \"\\\""
#define WDS_GET_GPIO_CMD_MODE_CPE_VALUE              "jq .wds_ypye /tmp/rg_device/rg_wds_gpio.json  | tr -d \"\\\""

#define WDS_GET_GPIO_CMD_MODE_LOCK_VALUVE            "jq .wds_ypye /tmp/rg_device/rg_wds_gpio.json  | tr -d \"\\\""
#define WDS_GET_GPIO_CMD_MODE_UNLOCK_VALUE           "jq .wds_ypye /tmp/rg_device/rg_wds_gpio.json  | tr -d \"\\\""

char rg_wds_gpio_read(struct gpio_info *rg_gpio_info_t);

char rg_wds_gpio_init(struct gpio_info *rg_gpio_info_t)
{
	rg_gpio_info_t->gpio_lock_num = LOCK_GPIO;
	rg_gpio_info_t->gpio_mode_num = MODE_GPIO;
	rg_wds_gpio_read(rg_gpio_info_t);
	rg_gpio_info_t->gpio_lock_value_last = rg_gpio_info_t->gpio_lock_value;
	rg_gpio_info_t->gpio_mode_value_last= rg_gpio_info_t->gpio_mode_value;
}

char rg_wds_gpio_read(struct gpio_info *rg_gpio_info_t)
{
	char str_buffer[50];
	int gpio_fd;

	memset(str_buffer,0,sizeof(str_buffer));
	sprintf(str_buffer,"/sys/class/gpio/gpio%d/value",rg_gpio_info_t->gpio_lock_num);
	gpio_fd = open(str_buffer,O_RDONLY);
	if (gpio_fd > 0) {
		memset(str_buffer,0,sizeof(str_buffer));
		read(gpio_fd,str_buffer,1);
		rg_gpio_info_t->gpio_lock_value= atoi(str_buffer);
		close(gpio_fd);
	}

	memset(str_buffer,0,sizeof(str_buffer));
	sprintf(str_buffer,"/sys/class/gpio/gpio%d/value",rg_gpio_info_t->gpio_mode_num);
	gpio_fd = open(str_buffer,O_RDONLY);
	if (gpio_fd > 0) {
		memset(str_buffer,0,sizeof(str_buffer));
		read(gpio_fd,str_buffer,1);
		rg_gpio_info_t->gpio_mode_value= atoi(str_buffer);
		close(gpio_fd);
	}

	//DEBUG("rg_gpio_info_t->gpio_mode_value %d rg_gpio_info_t->gpio_lock_value %d",rg_gpio_info_t->gpio_mode_value,rg_gpio_info_t->gpio_lock_value);
}

char rg_wds_gpio_lock_change(struct gpio_info *rg_gpio_info_t)
{
	char ret = 0;
	if (rg_gpio_info_t->gpio_lock_value != rg_gpio_info_t->gpio_lock_value_last) {
		if (rg_gpio_info_t->gpio_lock_value == UNLOCK ) {
			rg_gpio_info_t->gpio_event = rg_gpio_info_t->gpio_event | (1 << LOOK_UNLOOK_EVENT_BIT);
		} else if (rg_gpio_info_t->gpio_lock_value == LOCK ) {
			rg_gpio_info_t->gpio_event = rg_gpio_info_t->gpio_event | (1 << UNLOOK_LOOK_EVENT_BIT);
		}
		rg_gpio_info_t->gpio_lock_value_last = rg_gpio_info_t->gpio_lock_value;
	}

	return ret;
}

char rg_wds_gpio_mode_change(struct gpio_info *rg_gpio_info_t)
{
	char ret = 0;

	if (rg_gpio_info_t->gpio_mode_value_last != rg_gpio_info_t->gpio_mode_value) {
		if (rg_gpio_info_t->gpio_mode_value == MODE_CPE) {
			//说明从AP模式切换到STA模式
			rg_gpio_info_t->gpio_event = rg_gpio_info_t->gpio_event | (1 << AP_STA_EVENT_BIT);
		} else if (rg_gpio_info_t->gpio_mode_value == MODE_AP) {
			//说明从CPE模式切换到AP模式
			rg_gpio_info_t->gpio_event = rg_gpio_info_t->gpio_event | (1 << STA_AP_EVENT_BIT);
		}
		rg_gpio_info_t->gpio_mode_value_last = rg_gpio_info_t->gpio_mode_value;
	}
	return ret;
}

char rg_wds_gpio_change(struct gpio_info *rg_gpio_info_t)
{
	rg_wds_gpio_mode_change(rg_gpio_info_t);
	rg_wds_gpio_lock_change(rg_gpio_info_t);
}

char rg_wds_gpio_process(struct gpio_info *rg_gpio_info_t,struct ath_info *rg_ath_info_t)
{
	rg_wds_gpio_read(rg_gpio_info_t);
	rg_wds_gpio_change(rg_gpio_info_t);
}
