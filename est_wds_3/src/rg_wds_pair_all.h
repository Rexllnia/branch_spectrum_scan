#include "rg_wds_json.h"

#define TYPE_SET  1
#define TYPE_GET  2
#define TYPE_INFO 3
#define TYPE_CRYPTO 4

#define UN_CRYPTO_LEN       1024*2      //明文数据最大总长度          
#define EN_CRYPTO_LEN       1024*3      //加密后最大总长度
#define UN_CRYPTO_PART_LEN  1024        //加密函数单次最多支持加密明文长度
#define EN_CRYPTO_PART_LEN  1024+512    //单次最大1024字节明文加密完长度大概是1.5倍数
#define CRYPTO_SPLIT_FLAG   "###"       //特殊的分割标识符号
#define STOP_SEND_CNT       300         //5mins count,if recv 50002,reset 5mins
#define MTU_DATA_LEN        1400        //UDP的MTU最大1500字节，部分头占用一些字节，所以单次就发1400字节       

#define PWDLEN          	20
#define PWDF            	"RjYkh"
#define PWDS            	"wzx$20"
#define PWDFALSE1       	"S@alwXCuc2ZzPw"
#define PWDFALSE2       	"Yf&j8ceh6yxLmI"
#define PWDT            	"18!"

