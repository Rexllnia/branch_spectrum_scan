#include "rg_wds.h"
#include "automatic_range.h"
#include "rg_wds_pair_assioc.h"

/******************Automatic range****************/
typedef struct pair_rssi{
    unsigned char mac[20];
    int rssi_arr[20];
    int state;
    //struct pair_rssi* p_next;
} pair_rssi;

//写uci
int write_uci(char* uci_pkg, char *uci_config, char *uci_option, char *uci_value)
{   
    int resoult = AR_FAIL;
    if (NULL == uci_pkg || NULL == uci_config || NULL == uci_option || NULL == uci_value) {
        GPIO_DEBUG("(err) parameter is NULL");
        return resoult;
    }
    struct uci_context* ctx = uci_alloc_context();
    if (NULL == ctx) {
        GPIO_DEBUG("uci_alloc_context error");
        return resoult;
    }
    char uci_name[50];
    struct uci_ptr ptr;
    memset(&ptr, 0, sizeof(ptr));
    memset(uci_name, 0, sizeof(uci_name));
    snprintf(uci_name, sizeof(uci_name), "%s.%s.%s",uci_pkg, uci_config, uci_option);
    GPIO_DEBUG("%s() uci_name=%s", __func__, uci_name);
    if (UCI_OK != uci_lookup_ptr(ctx, &ptr, uci_name, true)) {
        GPIO_DEBUG("(err)%s no found!", uci_name);
        goto wu_end;
    }
    ptr.value = uci_value;
    if (0 != uci_set(ctx, &ptr)) {
        GPIO_DEBUG("uci_set AR_FAIL");
        goto wu_end;
    }
    uci_commit(ctx, &ptr.p, false);
    resoult = AR_SUCESS;
wu_end:
    uci_unload(ctx, ptr.p);
    uci_free_context(ctx);
    return resoult;
}

/*********************功能读取uci************************ 
*
*parm1 uci_config_file: uci配置文件(/etc/config/wireless)
*parm2 uci_config: 节点名，如wireless.wifi1中的wifi1就是节点
*parm3 uci_option: 配置名，如wireless.wifi1.distance中的distance
*parm4 读取的值存放地址， 如wireless.wifi1.distance=1000中的1000
*
*/  
// load_config("/etc/config/wireless", test, lev1, &value)

int read_uci( char* uci_config_file,char *uci_config, char* uci_option, char *uci_value)
{
    static struct uci_context * ctx = NULL; //定义一个UCI上下文的静态变量.
    struct uci_package * pkg = NULL;  
    struct uci_element *e;  
   //"/etc/config/wireless"
  
    ctx = uci_alloc_context(); // 申请一个UCI上下文.
    if (UCI_OK != uci_load(ctx, uci_config_file, &pkg)) 
        goto cleanup; //如果打开UCI文件失败,则跳到末尾 清理 UCI 上下文.
    /*遍历UCI的每一个节*/  
    uci_foreach_element(&pkg->sections, e)
    {  
        struct uci_section *s = uci_to_section(e);
        char *value=NULL;
        // 将一个 element 转换为 section类型, 如果节点有名字,则 s->anonymous 为 false.  
        // 此时通过 s->e.name 来获取
        
        if(strcmp(s->e.name, uci_config) != 0 ){
            
            continue;
        }
        //printf("name::::%s\n", s->e.name);
        // 此时 您可以通过 uci_lookup_option()来获取 当前节下的一个值.  
        if (NULL != (value = uci_lookup_option_string(ctx, s, uci_option)))
        {  
            //如果您想持有该变量值，一定要拷贝一份。当 pkg销毁后value的内存会被释放。
            
            strncpy(uci_value, value, strlen(value));
            //printf("=====uci_value=%s===\n", value);
        }
        // 如果您不确定是 string类型 可以先使用 uci_lookup_option() 函数得到Option 然后再判断.  
        // Option 的类型有 UCI_TYPE_STRING 和 UCI_TYPE_LIST 两种.  

    }  
    uci_unload(ctx, pkg); // 释放 pkg   
cleanup:  
    uci_free_context(ctx);  
    ctx = NULL;
    if(strlen(uci_value)!=0){
       
        return AR_SUCESS;
    }else{
        return AR_FAIL;
    }
}

//求采集的一组信号强度的平均值ave
double average_arr(int * rssi_arr, int arr_len)
{
    int i;
    double sum  = 0, ave = 0;
    for(i=0; i<arr_len; i++){
        sum += rssi_arr[i];
    }
    ave = sum/arr_len;
    return ave;
}

//求采集的一组信号强度的方差var
double variance_arr(int *rssi_arr, int arr_len)
{
    double ave=0, sum_v=0;
    int i;
    char s_rssi[100];
    memset(s_rssi, 0, sizeof(s_rssi));
    ave = average_arr(rssi_arr, arr_len);
    for (i = 0; i < arr_len; i++){
        sprintf(s_rssi+strlen(s_rssi), " %d", rssi_arr[i]);
        //sum_v += pow(rssi_arr[i] - ave, 2);
    }
    sprintf(s_rssi+strlen(s_rssi), "[ave:%.2f]", ave);
    GPIO_DEBUG("%s", s_rssi);
    return sum_v / arr_len;
}

int is_range_switch_on(void)
{
    char  uci_distance[16];
    memset(uci_distance, 0, sizeof(uci_distance));
    if(read_uci(WIRELESS_UCI_CONFIG_FILE, rg_dev_capacity_table.wifi_name, "distance", uci_distance) == AR_FAIL){
        GPIO_ERROR("read distance fail");
    }
    if (strcmp(uci_distance, "auto") == AR_SUCESS ) {
        GPIO_WARNING("range switch on.");
        return true;
    }
    GPIO_WARNING("range switch off.");
    return false;
}

int read_uci_period(void)
{
    char  uci_value[30];
    int period = DEF_PERIOD;
    memset(uci_value, 0, sizeof(uci_value));
    
    //读取循环间隔时间
    if(read_uci(WIRELESS_UCI_CONFIG_FILE, "test", "period", uci_value) == AR_SUCESS){
        period = atoi(uci_value);
    }
    return period;
}

//读取uci信号强度阈值
static void read_uci_rssi(int *lev_arr, int arr_len)
{
    char lev[10], uci_value[10];
    int i = 0;
    for (i=0; i<arr_len; i++) {
        memset(lev, 0, sizeof(lev));
        memset(uci_value, 0, sizeof(uci_value));
        sprintf(lev, "lev%d", i+1);
        if  (read_uci(WIRELESS_UCI_CONFIG_FILE, "test", lev, uci_value) == AR_FAIL) {
            GPIO_DEBUG("read %s AR_FAIL; will use default value %d", lev, lev_arr[i]);
            continue;
        }else{
            lev_arr[i] = atoi(uci_value);
        }
    }
}
static int set_distance(double ave_rssi)
{
    char  uci_value[10], set_distance_cmd[50];
    int distance = 0, current_distance= 0 , result = AR_FAIL;
    int rssi_lev[5]={lev1, lev2, lev3, lev4, lev5};
    //int lev1 = 39, lev2 = 37, lev3 = 35, lev4 = 33, lev5 = 31;
    if(0 == ave_rssi){
        return 0;
    }
    //读取距离信号强度阈值
    read_uci_rssi(rssi_lev, sizeof(rssi_lev)/sizeof(rssi_lev[0]));
    GPIO_DEBUG("lev1=%d, lev2=%d, lev3=%d, lev4=%d, lev5=%d",  lev1, lev2, lev3, lev4, lev5);
    
    if (ave_rssi >= rssi_lev[0]) {
        distance = 1000;
    } else if (ave_rssi >= rssi_lev[1]) {
        distance = 2000;
    } else if (ave_rssi >= rssi_lev[2]) {
        distance = 3000;
    } else if (ave_rssi >= rssi_lev[3]) {
        distance = 4000;
    } else if (ave_rssi >= rssi_lev[4]) {
        distance = 5000;
    } else {
        distance = 8000;
    }
    GPIO_DEBUG("ave_rssi=%f, distance = %d", ave_rssi, distance);
    memset(uci_value, 0, sizeof(uci_value));
    if (read_uci(WIRELESS_UCI_CONFIG_FILE, rg_dev_capacity_table.wifi_name, "distance", uci_value) == AR_SUCESS){
        GPIO_DEBUG("wireless.%s.distance:%s", rg_dev_capacity_table.wifi_name, uci_value);
        current_distance = atoi(uci_value);
        if(distance == current_distance){
            GPIO_DEBUG("distance == current_distance ==%d", distance);
            result = 2;
            goto sd_end;
        }
    } else {
        GPIO_DEBUG("read uci wireless.%s.distance is fail", rg_dev_capacity_table.wifi_name);
    }
    memset(set_distance_cmd, 0, sizeof(set_distance_cmd));
    sprintf(set_distance_cmd, "iwpriv %s distance %d", rg_dev_capacity_table.wifi_name, distance);
    if(system(set_distance_cmd) == -1){
        GPIO_DEBUG("%s fail", set_distance_cmd);
        goto sd_end;;
    }
    memset(uci_value, 0, sizeof(uci_value));
    sprintf(uci_value, "%d", distance);
    if(write_uci("wireless", rg_dev_capacity_table.wifi_name, "distance", uci_value) == AR_FAIL){
        GPIO_DEBUG("wirte_uci distance is err");
        goto sd_end;
    }
    GPIO_DEBUG("distance is set %d", distance);
    result = AR_SUCESS;
sd_end:
    return result;
}

//16进制mac到字符串mac转换
static int hmac_to_smac(char* smac, int size, u_int8_t hmac[6]){
    int i;
	i = snprintf(smac, size, "%02x:%02x:%02x:%02x:%02x:%02x",
		hmac[0], hmac[1], hmac[2], hmac[3], hmac[4], hmac[5]);
	return(i>size?AR_FAIL:AR_SUCESS);
}

static int get_asso_mac_rssi(pair_rssi* arr_rssi, int arr_len)
{
    uint8_t *buf;
    struct iwreq iwr;
    uint8_t *cp;
    int s, req_space = 0, dev_index = 0;
    u_int64_t len = 0;

	buf = malloc(LIST_STATION_ALLOC_SIZE);
	if (!buf) {
	  fprintf (stderr, "Unable to allocate memory for station list\n");
	  return AR_FAIL;
	}

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		free(buf);
		err(1, "socket(SOCK_DRAGM)");
	}

	(void) memset(&iwr, 0, sizeof(iwr));
	if (strlcpy(iwr.ifr_name, rg_ath_info_t.ath_wds_name, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
		fprintf(stderr, "ifname too long: %s\n", rg_ath_info_t.ath_wds_name);
        close(s);
		free(buf);
		return AR_FAIL;
	}

	iwr.u.data.pointer = (void *) buf;
	iwr.u.data.length = LIST_STATION_ALLOC_SIZE;

    iwr.u.data.flags = 0;
    //Support for 512 client
    req_space = ioctl(s, IEEE80211_IOCTL_STA_INFO, &iwr);
	if (req_space < 0 ) {
		free(buf);
        close(s);
		return AR_FAIL;
    }  else if(req_space > 0) {
        free(buf);
        buf = malloc(req_space);
        if(!buf) {
            fprintf (stderr, "Unable to allocate memory for station list\n");
            close(s);
            return AR_FAIL;
        }
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = req_space;
        if(iwr.u.data.length < req_space)
            iwr.u.data.flags = 1;
        if (ioctl(s, IEEE80211_IOCTL_STA_INFO, &iwr) < 0 ){
            free(buf);
            close(s);
            return AR_FAIL;
        }
        len = req_space;

    } else {
        len = iwr.u.data.length;
    }

    if (len < sizeof(struct ieee80211req_sta_info)) {
        free(buf);
        close(s);
        return AR_FAIL;
    }
	cp = buf;
	do {
		struct ieee80211req_sta_info *si;
		uint8_t *vp;
		si = (struct ieee80211req_sta_info *) cp;
		if (dev_index < arr_len) {   //暂时是五个后续用链表
            hmac_to_smac(arr_rssi[dev_index].mac, 20, si->isi_macaddr);//获取mac
            arr_rssi[dev_index].rssi_arr[0]=si->isi_rssi;//这里获取一次信号强度  后续再获取19次共20次取平均值 
            GPIO_DEBUG("arr_rssi[%d].rssi_arr[0]:%d,arr_rssi[%d].mac:%s, si_mac:%02x:%02x:%02x:%02x:%02x:%02x", dev_index, arr_rssi[dev_index].rssi_arr[0], dev_index, arr_rssi[dev_index].mac, si->isi_macaddr[0],\
            si->isi_macaddr[1],si->isi_macaddr[2],si->isi_macaddr[3],si->isi_macaddr[4],si->isi_macaddr[5]);
        }
		vp = (u_int8_t *)(si+1);
		cp += si->isi_len, len -= si->isi_len;
        dev_index++;
	} while (len >= sizeof(struct ieee80211req_sta_info));
    
	free(buf);
    close(s);
    return AR_SUCESS;
}

static int get_asso_rssi(pair_rssi* arr_rssi,int arr_len)
{
    uint8_t *buf;
    struct iwreq iwr;
    uint8_t *cp;
    int s, req_space, dev_index;
    u_int64_t len, len_tmp;
    int i=0;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
    	err(1, "socket(SOCK_DRAGM)");
        return AR_FAIL;
    }
    for (i=1; i<20; i++) { //这里获取19次信号强度共20次用来取平均值
        req_space = 0; dev_index = 0; len = 0; len_tmp = 0;
        buf = malloc(LIST_STATION_ALLOC_SIZE);
    	if (!buf) {
    	  fprintf (stderr, "Unable to allocate memory for station list\n");
	  close(s);
    	  return AR_FAIL;
    	}
    	(void) memset(&iwr, 0, sizeof(iwr));
    	if (strlcpy(iwr.ifr_name, rg_ath_info_t.ath_wds_name, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
    		fprintf(stderr, "ifname too long: %s\n", rg_ath_info_t.ath_wds_name);
            close(s);
    		free(buf);
    		return AR_FAIL;
    	}

    	iwr.u.data.pointer = (void *) buf;
    	iwr.u.data.length = LIST_STATION_ALLOC_SIZE;

        iwr.u.data.flags = 0;
        //Support for 512 client
        req_space = ioctl(s, IEEE80211_IOCTL_STA_INFO, &iwr);
    	if (req_space < 0 ) {
    		free(buf);
            close(s);
    		return AR_FAIL;
        }  else if(req_space > 0) {
            free(buf);
            buf = malloc(req_space);
            if(!buf) {
                fprintf (stderr, "Unable to allocate memory for station list\n");
                close(s);
                return AR_FAIL;
            }
            iwr.u.data.pointer = (void *) buf;
            iwr.u.data.length = req_space;
            if(iwr.u.data.length < req_space)
                iwr.u.data.flags = 1;
            if (ioctl(s, IEEE80211_IOCTL_STA_INFO, &iwr) < 0 ){
                free(buf);
                close(s);
                return AR_FAIL;
            }
            len = req_space;

        } else {
            len = iwr.u.data.length;
        }

        if (len < sizeof(struct ieee80211req_sta_info)) {
            free(buf);
            close(s);
            return AR_FAIL;
        }
        
         for (dev_index=0; dev_index<arr_len; dev_index++) {
            
            if(strlen(arr_rssi[dev_index].mac) == 0){
                //GPIO_DEBUG("arr_rssi[%d].mac is null", dev_index);
                break;
            }
            cp = buf; len_tmp = len;
            char mac_str[20];
            do {
        		struct ieee80211req_sta_info *si;
        		uint8_t *vp;
        		si = (struct ieee80211req_sta_info *) cp;
                memset(mac_str, 0, sizeof(mac_str));
                hmac_to_smac(mac_str, sizeof(mac_str)/sizeof(mac_str[0]),si->isi_macaddr);
        		if(strncmp(arr_rssi[dev_index].mac, mac_str, sizeof(arr_rssi[dev_index].mac)) == 0){
                    //GPIO_DEBUG("arr_rssi[%d].rssi_arr[%d]=%d", dev_index, i, si->isi_rssi);
                    arr_rssi[dev_index].rssi_arr[i]=si->isi_rssi;
                    break;
                }
        		vp = (u_int8_t *)(si+1);
        		cp += si->isi_len, len_tmp -= si->isi_len;
    	    } while (len_tmp >= sizeof(struct ieee80211req_sta_info));
            if (len_tmp < sizeof(struct ieee80211req_sta_info)) {
               arr_rssi[dev_index].state = INVALID;  //没有找到此mac说明此设备断桥，这个设备的rssi不再计算距离，数据作废
               GPIO_DEBUG("Mac [%s] is INVALID", arr_rssi[dev_index].mac);
            }
         }
    	free(buf);
        buf = NULL;
        usleep(100*1000);//每次采集完隔100ms一段时间再次采集。
    }
    close(s);
    return AR_SUCESS;
}


//读取平方差阈值
static int read_variance(int * variance_max)
{
    char uci_value[10];
    int resoult = AR_SUCESS;
    memset(uci_value, 0, sizeof(uci_value));
    if(read_uci(WIRELESS_UCI_CONFIG_FILE, "test", "variance", uci_value) == AR_FAIL){
        resoult = AR_FAIL;
        GPIO_DEBUG("uci variance is null");
        goto var_end;
    }else{
        *variance_max = atoi(uci_value);
    }
    
    GPIO_DEBUG("uci_variance=%s", uci_value);
var_end:
    return resoult;
}

//方差合格率
static double variance_pass_ratio(pair_rssi *rssi_arr, int rssi_arr_len)
{
    int dev_index = 0, valid_num = 0, dev_num = 0, variance_max = VARIANCE_MAX;
    double pass_ratio = 0, var;
 
    //每对，rssi的方差合格数
    for (dev_index=0; dev_index<rssi_arr_len; dev_index++) {
        var = 0;
        if (strlen(rssi_arr[dev_index].mac) == 0) {
            GPIO_DEBUG("rssi arr valid num is [%d]", dev_index);
            break;
        }
        if(rssi_arr[dev_index].state != INVALID){   //节点无效也是这组数据不合格中的一个所以节点总数不减1
            var = variance_arr(rssi_arr[dev_index].rssi_arr, 20);
            GPIO_DEBUG("rss_arr[%d]:variance = %.2f", dev_index, var);
            if (read_variance(&variance_max)  == AR_FAIL ){
                GPIO_DEBUG("Read 'variance' failure");
            }
            GPIO_DEBUG("variance_max:%d", variance_max);
            if(var < variance_max){
                valid_num++;
            }
        }
    }

    dev_num = dev_index; //记录关联的设备数量
    GPIO_DEBUG("dev_num=%d,valid_num=%d", dev_num, valid_num);
    //计算合格率
    pass_ratio = (float)valid_num / dev_num;
    GPIO_DEBUG("pass_ratio=%.2f", pass_ratio);
    return pass_ratio;
}

//求所有关联设备的rssi的最小平均值
static double average_rssi_min(pair_rssi* rssi_arr, int arr_len)
{
    double ave_tmp, ave_min = 0;
    int dev_index = 0;
    for(dev_index=0; dev_index<arr_len; dev_index++){
        if (strlen(rssi_arr[dev_index].mac) == 0) {
            break;
        }
        if (rssi_arr[dev_index].state != INVALID) {
            ave_tmp = average_arr(rssi_arr[dev_index].rssi_arr, 20);
            GPIO_DEBUG("rssi_arr[%d]:average=%.2f", dev_index, ave_tmp);
            if (0 == dev_index) {
                ave_min = ave_tmp;
            } else if (ave_tmp < ave_min) {
                ave_min = ave_tmp;
            }
        }
    }
    return ave_min;
}

//初始化所用节点状态
static void pair_rssi_arr_init(pair_rssi* rssi_arr, int arr_len){
    memset(rssi_arr, 0, arr_len * sizeof(pair_rssi));
    int i = 0;
    for (i=0; i<arr_len; i++) {
        rssi_arr[i].state = VALID; //默认此节点有效
    }
}

static void auto_set_distance(void)
{
    double ave_min = 0, arr_len;
    int resoult = AR_FAIL;
    pair_rssi pair_rssi_arr[5];
    
    //初始化所用节点状态
    arr_len = sizeof(pair_rssi_arr) / sizeof(pair_rssi_arr[0]);
    pair_rssi_arr_init(pair_rssi_arr, arr_len);
    GPIO_DEBUG("pair_rssi_arr init complete");
    
    //记录桥接上的设备的mac
    if (get_asso_mac_rssi(pair_rssi_arr, arr_len) == AR_FAIL) {
        GPIO_DEBUG("get_asso_mac AR_FAIL");
        goto atsd_end;
    }
    GPIO_DEBUG("get_asso_mac complete");
    
    //获取相应mac对应的rssi
    if (get_asso_rssi(pair_rssi_arr, arr_len) == AR_FAIL) {
        GPIO_DEBUG("get_asso_rssi AR_FAIL");
        goto atsd_end;
    }
    GPIO_DEBUG("get_asso_rssi complete");
    
    //合格率大于百分之50才会求rssi最小平均值
    if (variance_pass_ratio(pair_rssi_arr, arr_len) < 0.5) {
        GPIO_DEBUG("variance_pass_ratio less than 0.5");
        goto atsd_end;
    }

    //求最新平均值
    ave_min = average_rssi_min(pair_rssi_arr, arr_len);
    GPIO_DEBUG("ave_min %.0f", ave_min);
    
    //用最小平均值设置距离
    resoult = set_distance(ave_min);

atsd_end:
    if (resoult == AR_FAIL) {
        GPIO_DEBUG("Setting distance failed");
    } else {
        if (resoult = 2) {
            GPIO_DEBUG("Distance is no change, so no set");
        }
        GPIO_DEBUG("Complete automatic ranging!!");
   }
}

//Automatic range 
int automatic_range_run(void)
{

    while (1) {
        
        if (is_range_switch_on()){
            GPIO_DEBUG("start execote auto_set_distance");
            auto_set_distance();
        }
        
        sleep(read_uci_period());
    }
   
}


/*
pair_rssi pair_rssi_arr[5];
int collect_num;
int i;
int pair_max_num = 0;
float last_rssi = 0;

void auto_set_distance(void)
{
    char get_opposite_mac_cmd[50];
    char get_rssi_cmd[50];
    char opposite_mac[20];
    char rssi[5];
    int j, n,m;
    //初始化256个链表，就是最大桥接个数
    
    //for(j=0; j<256; j++){
      //  link_init(&pair_rssi_arr[i]);
    //}
   
    //记录桥接上的设备的mac，20次中只开始的时候记录
    if(0 == collect_num){
        memset(pair_rssi_arr, 0, sizeof(pair_rssi_arr));
        while(1){
            memset(get_opposite_mac_cmd, 0, sizeof(get_opposite_mac_cmd));
            sprintf(get_opposite_mac_cmd, "wlanconfig ath1 list | grep AWPSM | awk '{print $1}' | sed -n '%dp'", ++i);
            memset(opposite_mac, 0, sizeof(opposite_mac));
            rg_wds_misc_cmd(get_opposite_mac_cmd, opposite_mac, sizeof(opposite_mac));
            DEBUG("opposite_mac:%s-----", opposite_mac);
            if(strlen(opposite_mac) == 0){
                DEBUG("A total of %d pairs of equipment were successfully bridged", --i);
                break;
            }
            //link_append(&pair_rssi_arr[i], atoi(rssi));
            if(i <= 5){     //暂时是五个后续用链表
                memset(pair_rssi_arr[i-1].mac, 0, sizeof(pair_rssi_arr[i-1].mac));
                memcpy(pair_rssi_arr[i-1].mac, opposite_mac, strlen(opposite_mac));
                pair_rssi_arr[i-1].state = VALID;  //默认有效
            }
        }
    }

    //获取相应mac对应的rssi
    for(n=0; n<i; n++){
        memset(get_rssi_cmd, 0, sizeof(get_rssi_cmd));
        if(strlen(pair_rssi_arr[n].mac)!=0){
            sprintf(get_rssi_cmd, "wlanconfig ath1 list | grep %s | awk '{print $6}'", pair_rssi_arr[n].mac);
            memset(rssi, 0, sizeof(rssi));
            rg_wds_misc_cmd(get_rssi_cmd, rssi, sizeof(rssi));
            //DEBUG("rssi:%s", rssi);
            if(strlen(rssi) == 0){
                pair_rssi_arr[n].state=INVALID;
                DEBUG("Failed to get the RSSI for the device (mac:%s)", pair_rssi_arr[n].mac);
                continue;
            }
            pair_rssi_arr[n].rssi_arr[collect_num] = atoi(rssi);
            GPIO_DEBUG("pair_rssi_arr[%d].rssi_arr[%d]:%d", n, collect_num, pair_rssi_arr[n].rssi_arr[collect_num]);
        }
    }
    
    DEBUG("------------collect_num:%d,i=%d", collect_num, i);
    collect_num++; //采集完一次rssi计数加一，20次做一次计算
    
    if(20 == collect_num){
        collect_num = 0;
        int valid_num = 0;
        
        //每对，rssi的方差合格数
        DEBUG("i=%d", i);
        for (n=0; n<i; n++) {
            double var = 0;
            DEBUG("pair_rssi_arr[%d].state=%d", n, pair_rssi_arr[n].state);
            if(pair_rssi_arr[n].state != INVALID){
                printf("pair_rssi_arr[%d].rssi_arr[", n);
                var = variance_arr(pair_rssi_arr[n].rssi_arr, 20);
                DEBUG("pair_rss_arr[%d]:variance = %.2f", n, var);
                DEBUG("variance_max is %d"
, variance_max)
                if(var < variance_max){
                    valid_num++;
                }
            }
           
        }
        //合格率大于百分之50才会求rssi品均值进行距离设置
        DEBUG("valid_num=%d", valid_num);
        double effective_rate = 0;
        effective_rate = (float)valid_num / i;
        printf("effective_rate=%.2f\n", effective_rate);
        if(effective_rate > 0.5){
            double ave_tmp, ave_min = 0;
            for(n=0; n<i; n++){
                if(pair_rssi_arr[n].state != INVALID){
                    ave_tmp = average_arr(pair_rssi_arr[n].rssi_arr, 20);
                    DEBUG("pair_rssi_arr[%d]:average=%.2f", n, ave_tmp);
                    if(0 == n){
                        ave_min = ave_tmp;
                    } else if(ave_tmp < ave_min){
                        ave_min = ave_tmp;
                    }
                }
            }

            //当信号强度和上次一样无需再次设置。
            DEBUG("last_rssi=%.2f, ave_min=%.2f", last_rssi, ave_min);
            if(ave_min != last_rssi){
                last_rssi=ave_min;
                DEBUG("last_rssi change:%f", last_rssi);
                if(set_distance(last_rssi) == 0){
                    last_rssi = 0;//设置失败，为了下次可以继续设置,所以设置为0
                    DEBUG("Setting distance failed");
                }else{
                        DEBUG("Distance is set sucess!!");
                    }
            }else{
                DEBUG("last_rssi == ave_min");
            }
            
        }
        i=0;
    }
*/
 /*
    if(i>pair_max_num){   //记录计算一次平均数，所出现的最多的对数，都要释放内存，防止内存泄漏
        pair_max_num = i;
    }
    float pair_rssi_ave[256], pair_rssi_var[256];
    int valid_data_num;
    if(link_size(&pair_rssi_arr[i]) == 20){
        int num;
        //计算几组数据的方差
        for(num = 0; num < pair_max_num; num++){
            if(variance(&pair_rssi_arr[num], &pair_rssi_var[num]) == 0){
                DEBUG("(warn)Failure to calculate variance(pair %d)", num);
                continue;
            }
            if(pair_rssi_var[num]<5){
                valid_data_num++;
            }
        }
        //有不少于百分之五十的对数数据合理就继续，否则丢弃
        if(valid_data_num/i >= 0.5){
            float ave_tmp;
            //取平均rssi最小的作为最后距离设置的根据
            for(num = 0; num < pair_max_num; num++){
                if(average(&pair_rssi_arr[num], &pair_rssi_ave[num]) == 0){
                    DEBUG("(warn)Failure to calculate average(pair %d)", num);
                    continue;
                }
                if(0 ==num){
                    ave_tmp = pair_rssi_ave[num];
                }else if(pair_rssi_ave[num] < ave_tmp){
                    ave_tmp = pair_rssi_ave[num];
                }
            }
            //根据rssi设置距离生效
            if(set_distance(ave_tmp)==0){
                DEBUG("Setting distance failed");
            }
        }

        //申请了几个链表，就删除几个
        for(num = 0; num < pair_max_num; num++){
            link_deinit(&pair_rssi_arr[num]);
        }
    }

}
*/



