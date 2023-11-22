#include "spctrm_scn24_config.h"
#include <libubox/blobmsg_json.h>
#include "libubus.h"

int spctrm_scn24_rlog_module_enable(const char *module);
int spctrm_scn24_rlog_upload_stream(char *module,char *data);