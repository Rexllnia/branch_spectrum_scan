#ifndef _AUTOMATIC_RANGE_H
#define    _AUTOMATIC_RANGE_H

#define AR_SUCESS       0
#define AR_FAIL        -1
#define INVALID         0
#define VALID           1
#define DEF_PERIOD      5       //默认5秒设置一次，加上中间采集需要的1.9s，一次采集就是5+1.9=6.9s
#define VARIANCE_MAX    5
#define RADIO_AUTOMATIC_RANGE    "/tmp/automatic_range_flag"
#define WIRELESS_UCI_CONFIG_FILE "/etc/config/wireless"

//默认各距离信号强度阈值
enum{
    lev1 = 39,
    lev2 = 36,
    lev3 = 35,
    lev4 = 33,
    lev5 = 29,
};

int automatic_range_run(void);
int write_uci(char* uci_pkg, char *uci_config, char *uci_option, char *uci_value);
int read_uci( char* uci_config_file,char *uci_config, char* uci_option, char *uci_value);

#endif 