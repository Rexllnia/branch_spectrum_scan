#ifndef _AUTOMATIC_RANGE_H
#define    _AUTOMATIC_RANGE_H

#define AR_SUCESS       0
#define AR_FAIL        -1
#define INVALID         0
#define VALID           1
#define DEF_PERIOD      5       //Ĭ��5������һ�Σ������м�ɼ���Ҫ��1.9s��һ�βɼ�����5+1.9=6.9s
#define VARIANCE_MAX    5
#define RADIO_AUTOMATIC_RANGE    "/tmp/automatic_range_flag"
#define WIRELESS_UCI_CONFIG_FILE "/etc/config/wireless"

//Ĭ�ϸ������ź�ǿ����ֵ
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