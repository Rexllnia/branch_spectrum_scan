#include "rg_wds.h"

//json 鑾峰彇鏁版嵁锛岀涓�绾х殑
char rg_wds_json_first(char *file_name,char *option,char *buf,char len) {
    struct json_object *obj_all_p_1 = NULL;
    struct json_object *obj_all_p = NULL;
    char ret;

    obj_all_p_1 = json_object_from_file(file_name);
	if (obj_all_p_1 == NULL) {
        DEBUG("can not open json file %s",file_name);
        ret = FAIL;
        goto realese;
	}

    obj_all_p = json_object_object_get(obj_all_p_1, option);
    if(obj_all_p == NULL) {
        DEBUG("can not find option %s",option);
        ret = FAIL;
        goto realese;
    }
    memcpy(buf,json_object_to_json_string(obj_all_p) + 1,strlen(json_object_to_json_string(obj_all_p)) - 2);
    ret = SUCESS;

realese:
    if (obj_all_p) {
	    json_object_put(obj_all_p);
    }

    if (obj_all_p) {
	    json_object_put(obj_all_p_1);
    }

    return ret;
}

//json 鑾峰彇鏁版嵁锛岀浜岀骇鐨?
char rg_wds_json_second(char *file_name,char *first_option,char *second_option,char *buf,char len) {
    return ;
}

/*
root@Ruijie:/sbin# jq . /tmp/wds_info.json
{
  "LIST": [
    {
      "SN": "G1MQ4XG001441",
      "MAC": "00:74:9c:aa:54:5e",
      "ATHMAC": "06:74:9c:aa:54:60",
      "HOSTNAME": "Ruijie",
      "SOFTVERSION": "AP_3.0(1)B2P11,Release(05221006)",
      "ROLE": "cpe",
      "STATUS": "ON",
      "LOCK": "LOCK",
      "IP_ADDRESS": "192.168.123.40",
      "RATE": "200",
      "RSSI": "72"
    }
  ]
}

输入:/tmp/wds_info.json SN G1MQ4XG001441
输出:00:74:9c:aa:54:5e
*/
char rg_wds_json_second_cmp(char *file_name,char *first_option,char *second_option,char *cmp_src,char *buf,char len) {
    struct json_object *obj_all_p;
    char ret;
    char i;

    obj_all_p = json_object_from_file(file_name);
	if (obj_all_p == NULL) {
        DEBUG("can not open json file %s",file_name);
        ret = FAIL;
        goto realese;
	}

    obj_all_p = json_object_object_get(obj_all_p,first_option);
    if(obj_all_p == NULL) {
        DEBUG("can not find option %s",first_option);
        ret = FAIL;
        goto realese;
    }

	for(i = 0; i < json_object_array_length(obj_all_p); i++) {
		json_object *section= json_object_array_get_idx(obj_all_p, i);
		json_object *cmp_des= json_object_object_get(section,second_option);
        if(memcmp(cmp_src,json_object_to_json_string(cmp_des) + 1,strlen(json_object_to_json_string(cmp_des)) - 2)) {
            DEBUG("cmp_src %s ",json_object_to_json_string(cmp_des));
        }
    }

    memcpy(buf,json_object_to_json_string(obj_all_p) + 1,strlen(json_object_to_json_string(obj_all_p)) - 2);
    ret = SUCESS;

realese:
	json_object_put(obj_all_p);
    return ret;
}

/*
{
  "LIST": [
    {
      "ATHMAC": "00:d0:f8:15:08:4a",
      "SOFTVERSION": "AP_3.0(1)B2P10,Release(05201716)\n"
    },
    {
      "ATHMAC": "06:d0:f8:15:08:ce",
      "SOFTVERSION": ""
    },
    {
      "ATHMAC": "00:00:00:00:00:00",
      "SOFTVERSION": ""
    }
  ]
}
传入参数 first_option LIST，second_option ATHMAC，cmp_src 00:d0:f8:15:08:4a
返回:SOFTVERSION对应的值
*/
char rg_wds_json_second_cmp_2(char *file_name,char *first_option,char *cmp_option,char *cmp_value,char *dst_option,char *dst_value) {
    struct json_object *obj_all_p1;
    struct json_object *obj_all_p2;

    char ret;
    char i;

    obj_all_p1 = json_object_from_file(file_name);
	if (obj_all_p1 == NULL) {
        DEBUG("can not open json file %s",file_name);
        ret = FAIL;
        goto realese;
	}

    obj_all_p2 = json_object_object_get(obj_all_p1,first_option);
    if(obj_all_p2 == NULL) {
        DEBUG("can not find option %s",first_option);
        ret = FAIL;
        goto realese;
    }

	for(i = 0; i < json_object_array_length(obj_all_p2); i++) {
		json_object *section= json_object_array_get_idx(obj_all_p2, i);
		json_object *cmp_des= json_object_object_get(section,cmp_option);
        json_object *dst_item= json_object_object_get(section,dst_option);
        if(memcmp(cmp_value,json_object_to_json_string(cmp_des) + 1,strlen(json_object_to_json_string(cmp_des)) - 2) == 0) {
            memcpy(dst_value,json_object_to_json_string(dst_item) + 1,strlen(json_object_to_json_string(dst_item)) - 2);
        }

    }
    ret = SUCESS;

realese:
	json_object_put(obj_all_p1);
    return ret;
}

//json 操作接口，修订值
char rg_wds_second_set(char *file_name,char *first_option,char *second_option,char *buf) {
    struct json_object *obj_all_p,*p1;
    char ret;
    char i;

    obj_all_p = json_object_from_file(file_name);
    p1 = obj_all_p;
	if (obj_all_p == NULL) {
        DEBUG("can not open json file %s",file_name);
        ret = FAIL;
        goto realese;
	}

    obj_all_p = json_object_object_get(obj_all_p,first_option);
    if(obj_all_p == NULL) {
        DEBUG("can not find option %s",first_option);
        ret = FAIL;
        goto realese;
    }

    DEBUG("obj_all_p %s second_option %s buf %s %d",json_object_to_json_string(obj_all_p),second_option,buf,json_object_array_length(obj_all_p));
	for(i = 0; i < json_object_array_length(obj_all_p); i++) {
		json_object *section= json_object_array_get_idx(obj_all_p, i);
		json_object *src_str= json_object_object_get(section,second_option);
        json_object_object_add(section,second_option,json_object_new_string(buf));
        break;
    }

    rg_wds_misc_clear_file(file_name);

    const char *str = json_object_to_json_string(p1);
    int fd;

    fd = open(file_name, O_CREAT | O_RDWR,0644);
    if (fd > 0) {
        write(fd,str,strlen(str));
        close(fd);
    }


realese:
	json_object_put(obj_all_p);
    json_object_put(p1);
    return ret;
}
