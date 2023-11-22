#define BUFSIZE         1024*16
#define BSIZE           (8*1024)
#define ENCRYPT			1
#define DECRYPT			0
#define PWDLEN          20
#define PWDF            "RjYkh"
#define PWDS            "wzx$20"
#define PWDT            "18!"
#define PWDFALSE1       "S@alwXCuc2ZzPw"
#define PWDFALSE2       "Yf&j8ceh6yxLmI"
#define AES_128_CBC     "aes-128-cbc"
#define AES_256_CBC     "aes-256-cbc"

#define CILENT_OUTF_FILE	"/tmp/client_outf_"	//存放client加密后数据的文件
#define CILENT_INF_FILE		"/tmp/client_inf_"	//存放命令和md5值组合起来的明文文件
#define SERVER_OUTF_FILE	"/tmp/server_outf"	//存放解密后命令和md5值组合起来的明文文件
#define SERVER_INF_FILE		"/tmp/server_inf"	//存放server端收到的加密文件
#define CRYPTO_MARK_STR		"###" 				//特殊标识符，用于server区分是否是加密数据
#define NEW_TIPC_TIME		"08201116" 			//时间标记，标识此版本开始支持TIPC加密通讯08201116
#define NEW_TIPC_ITEM		"58" 				//项目标记，暂定大于等于58的为支持

//需要支持的指令集模糊匹配字符串
#define TIPC_DEV_CONFIG_GET			    "dev_config get -m"
#define TIPC_DEV_CONFIG_SET			    "dev_config set -m"
#define TIPC_DEV_CONFIG_SET_NETWORK     "dev_config set -m network"
#define TIPC_DEV_STA_GET			    "dev_sta get -m"
#define TIPC_DEV_STA_SET			    "dev_sta set -m"

#define TIPC_SERVER_LOG1 "/tmp/tipc_server1.log"
#define TIPC_SERVER_LOG2 "/tmp/tipc_server2.log"
#define TIPC_CLIENT_LOG1 "/tmp/tipc_client1.log"
#define TIPC_CLIENT_LOG2 "/tmp/tipc_client2.log"

unsigned char *md5_coding(char *data);
int aes_coding(char *inf, char *outf, char *type, int enc);
int file_size(char* filename);
int write_log_file(char* filename,char *buf);


