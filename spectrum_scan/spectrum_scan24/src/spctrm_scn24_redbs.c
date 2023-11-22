#include "spctrm_scn24_redbs.h"
#ifdef REDBS_ENABLE
static redbs_t* wds_list_all_dbs = NULL;

static int wds_list_all_scan_cb(const redbs_t* dbs, redbs_pubsub_msg_t* msg, void* arg) {
	WWdsinfo__InfoTable* info_table;
	WWdsinfo__InfoTableKey* info_key;
    char sn[SN_LEN];
    spctrm_scn24_common_get_sn(sn);

	if (msg->error != 0) {
		// WDS_LIST_DEBUG("error occur %d\n", msg->error);
		return FAIL;
	}

	if (msg->cmd == REDBS_CMD_SCAN) {
		if (msg->flag == 0) {   							/* ��ʼscan */
			// WDS_LIST_DEBUG("[wds_list_all] start\n");
		} else if (msg->flag == REDBS_SCAN_OVER) {  		/* ����scan */
			// WDS_LIST_DEBUG("[wds_list_all] end\n");
		}
	} else if (msg->cmd == REDBS_CMD_HSET || msg->cmd == REDBS_CMD_SET) {
		info_table = (WWdsinfo__InfoTable*) (msg->value);
		printf("%s\r\n",info_table->keys->sn);
        if (strcmp(info_table->keys->sn,sn) == 0) {
		printf("find \r\n");
        }
        
	}

	return SUCCESS;
}

static int get_wds_list_all(void) {
	WWdsinfo__InfoTable info_table = W_WDSINFO__INFO_TABLE__INIT;
	WWdsinfo__InfoTableKey info_key = W_WDSINFO__INFO_TABLE_KEY__INIT;
	int ret;

	info_table.keys = &info_key;
	ret = redbs_scan(wds_list_all_dbs, REDBS_HOST_DB, (const redbs_obj*) &info_table, 0, wds_list_all_scan_cb, NULL);
	return ret;
}

int spctrm_scn24_redbs_get_dev_list_info()
{
    void* arg = NULL;
	redbs_obj info_table = W_WDSINFO__INFO_TABLE__INIT;
	WWdsinfo__InfoTableKey info_key = W_WDSINFO__INFO_TABLE_KEY__INIT;
	int ret;

    wds_list_all_dbs = redbs_init("WDS_LIST_ALL_REDBS", NULL);
	if (wds_list_all_dbs == NULL) {
		return -1;
	}

	if (redbs_connect(wds_list_all_dbs, REDBS_HOST_DB, NULL, arg) != 0) {
		// WDS_LIST_DEBUG("wds_list_all connect REDBS_NCDB_DB failed!\n");
		wds_all_redis_disconnect();
		return -1;
	}

	get_wds_list_all();
	wds_all_redis_disconnect();


}
#endif