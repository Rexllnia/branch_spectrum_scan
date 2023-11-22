#include "rg_tipc.h"
#include "rg_tipc_crypto.h"
#include <sys/resource.h>
#include <stdio.h>
#include "librg_crypto.h"
#ifdef EST_SUPPORT_REDIS
#include "rg_tipc_redis.h"
int tipc_redis_check(unsigned int ser_node,unsigned int cli_node){
    //printf("tipc ser_node:%x cli_node:%x\n",ser_node,cli_node);
    int ret = 0;
    unsigned char str[100];
    unsigned char *ser_pwd = NULL;
    unsigned char *cli_pwd = NULL;
    struct tipc_redis_info *ser_info = NULL;
    struct tipc_redis_info *cli_info = NULL;
    
    ser_info = malloc(sizeof(struct tipc_redis_info));
    if(!ser_info){
        ret = -1;
        goto end;
    }
    cli_info = malloc(sizeof(struct tipc_redis_info));
    if(!cli_info){
        ret = -1;
        goto end;
    }
    memset(ser_info, 0, sizeof(struct tipc_redis_info));
    memset(cli_info, 0, sizeof(struct tipc_redis_info));
    
    if(redbs_tipc_get_pub(ser_node,ser_info) == 0){
        memset(str, 0, sizeof(str));
        strcpy(str,ser_info->passwd);
        ser_pwd = rg_crypto_buf_decrypt(str, strlen(str), 'c');
        if(ser_pwd == NULL) {   
            ret = -1;
            goto end;
        }
        //printf("ser_pwd:%s\n",ser_pwd);
        if(strcmp(ser_info->networkid,DEF_NETWORKID) == 0 && strcmp(ser_pwd,EWEB_DEF_PW) == 0){
            ret = 0;//default networkid and eweb pwd
        } else {
            if(redbs_tipc_get_pub(cli_node,cli_info) == 0){
                //printf("tipc sid:%s,cid:%s,spwd:%s,cpwd:%s\n",ser_info->networkid,cli_info->networkid,ser_info->passwd,cli_info->passwd);
                memset(str, 0, sizeof(str));
                strcpy(str,cli_info->passwd);
                cli_pwd = rg_crypto_buf_decrypt(str, strlen(str), 'c');
                if(cli_pwd == NULL) { 
                    ret = -1;
                    goto end;

                }
                //printf("cli_pwd:%s\n",cli_pwd);
                if(strcmp(ser_info->networkid,cli_info->networkid) == 0 || strcmp(ser_pwd,cli_pwd) == 0){
                    ret = 0;//networkid or eweb pwd same
                } else {
                    ret = 1;//networkid and eweb pwd not same,need check cmd 
                }
            } else {
                ret = -1;//get redis fail
            }
        }
    } else {
        ret = -1;//get redis fail
    }
end:
    if(cli_info != NULL){
        free(cli_info);
    }
    if(ser_info != NULL){
        free(ser_info);
    }
    if(ser_pwd != NULL){
        rg_crypto_buf_free(ser_pwd);
    }
    if(cli_pwd != NULL){
        rg_crypto_buf_free(cli_pwd);
    }
    return ret;
}
#endif

void rg_error_msg(int ret,char *buf)
{
	switch(ret){
	case -1:
		printf("Error:Command not support\n\n");
		strcpy(buf,"sucess Error:Command not support");
		break;
	case -2:
		printf("Error:illegal symbol\n\n");
		strcpy(buf,"sucess Error:illegal symbol");
		break;
	case -3:
		printf("Error:md5sum error\n\n");
		strcpy(buf,"sucess Error:md5sum error");
		break;
	default:
		printf("Error:Unexpected error\n\n");
		strcpy(buf,"sucess Error:Unexpected error");
		break;
	}
}

int tipc_cmd_check(char *buf)
{
	if((strstr(buf,"&")==NULL) && (strstr(buf,"|")==NULL) && (strstr(buf,";")==NULL)){
		if((strstr(buf,TIPC_DEV_CONFIG_GET) != NULL) || (strstr(buf,TIPC_DEV_CONFIG_SET) != NULL)
			||(strstr(buf,TIPC_DEV_STA_GET) != NULL) ||(strstr(buf,TIPC_DEV_STA_SET) != NULL)){
			printf("The command parsed success\n");
			return 0;
		}else{
			return -1;
		}
	}else{
		return -2;
	}
}

int main()
{
	struct sockaddr_tipc server_addr;
	struct sockaddr_tipc client_addr;
	socklen_t alen = sizeof(client_addr);
	int sd;
	char buf[BUF_SIZE];
    unsigned int instant = 0;
    unsigned char mac[20];
	int ret = 0;
    char cmd[BUF_SIZE];
	char md5str[64];
    unsigned char *md5buf;
    FILE *inf_fd;
    FILE *outf_fd;
    char *inf  = SERVER_INF_FILE; 
    char *outf = SERVER_OUTF_FILE;
    struct timeval timeout={4,0};
#ifdef EST_SUPPORT_REDIS
    int check_flag = 0;
    static __u32 server_addr_node = 0;
    pthread_t thread_tipc_redis;
#endif
#ifdef CONFIG_TIPC_CORE_DUBUG
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limit);
#endif

begin:
    memset(mac,0,sizeof(mac));
    rg_misc_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);
    //printf("%s %d mac %s \n",__func__,__LINE__,mac);

    instant = rg_mist_mac_2_nodeadd(mac);
    if (instant == 0) {
        printf("%s %d error exit instant %d\n",__func__,__LINE__,instant);
        exit(0);
    }

	server_addr.family = AF_TIPC;
	server_addr.addrtype = TIPC_ADDR_NAMESEQ;
	server_addr.addr.nameseq.type = SERVER_TYPE;
	server_addr.addr.nameseq.lower = instant;
	server_addr.addr.nameseq.upper = instant;
	server_addr.scope = TIPC_ZONE_SCOPE;

	sd = socket(AF_TIPC,SOCK_RDM,0);

	if (0 != bind(sd,(struct sockaddr *)&server_addr,sizeof(server_addr))){
		printf("Server: failed to bind port name\n");
        sleep(10);
        goto begin;
	}

#ifdef EST_SUPPORT_REDIS
    instant = (1 << 30) | (1 << 28) | instant;
    if (0 != pthread_create(&thread_tipc_redis,NULL,rg_tipc_redis_thread,NULL)) 
    {
		printf("Create thread tipc redis fail\n");
	}
#endif

    while(1){
		ret = 0;
        memset(buf,0,sizeof(buf));
        if (0 >= recvfrom(sd,buf,sizeof(buf) - 1,0,(struct sockaddr *)&client_addr,&alen)){
            perror("Server: unexpected message");
            continue;
        }
       
#ifdef EST_SUPPORT_REDIS
        //0.check networkid and eweb pwd      
        check_flag = tipc_redis_check(instant,client_addr.addr.id.node);
        if (check_flag < 0){
            perror("TIPC get redis fail perror");
            continue;
        }
#endif
        //1.兼容旧设备明文指令,末尾是CRYPTO_MARK_STR，则认为是已加密，送去解密，否则直接认为是明文
        if(strcmp((buf+strlen(buf)-strlen(CRYPTO_MARK_STR)),CRYPTO_MARK_STR) == 0){
			//2.AES解密将接收到的加密数据写入 SERVER_INF_FILE 进行解密
			inf_fd = fopen(SERVER_INF_FILE, "w+");
			if (inf_fd == NULL) {
				perror("TIPC inf_fd open fail perror");
                //write_log_file(TIPC_SERVER_LOG1,"TIPC inf_fd open fail perror\n");
				continue;
			}
			//末尾的CRYPTO_MARK_STR不属于加密文件，不能写进去
			fwrite(buf,strlen(buf)-strlen(CRYPTO_MARK_STR),1,inf_fd);
			fclose(inf_fd);
            inf_fd = NULL;
			if (0 != aes_coding(inf, outf, AES_128_CBC, DECRYPT)){
                continue;
            }
			//打开解密 SERVER_OUTF_FILE 文件，读取aes_coding函数DECRYPT以后的解密数据
			memset(buf,0,sizeof(buf));
			outf_fd = fopen(SERVER_OUTF_FILE, "r");
			if (outf_fd == NULL) {
				perror("TIPC outf_fd open fail perror");
                //write_log_file(TIPC_SERVER_LOG1,"TIPC outf_fd open fail perror\n");
				continue;
			}
			fread(buf,1,sizeof(buf),outf_fd);
			fclose(outf_fd);
            outf_fd = NULL;
			//printf("outf:%s\n\n",buf);
			
			//将解密数据的命令部分和MD5值部分进行分离，数据格式为命令加末尾32位MD5值
			memset(cmd,0,sizeof(cmd));
			memset(md5str,0,sizeof(md5str));
			strncpy(cmd,buf,strlen(buf)-32);
			strncpy(md5str,buf+strlen(buf)-32,32+1);
            
			//3.将cmd数据的MD5值和md5str进行对比校验
			md5buf = md5_coding(cmd);
			if(strcmp(md5buf,md5str)==0){
			    memset(buf,0,sizeof(buf));
			    strncpy(buf,cmd,strlen(cmd));
			}else{
				ret = -3;
			}
        }
#ifdef EST_SUPPORT_REDIS
        //3.5 check if set network cmd
        if (check_flag == 1) {
            if(strstr(buf,TIPC_DEV_CONFIG_SET_NETWORK) != NULL){
                ret = 0;
            } else {
                ret = -1;
            }
        }
#endif		
		//4.过滤非安全指令集指令 
		if(ret == 0){
			ret = tipc_cmd_check(buf);
		}

		//5.发送命令执行结果
		if(ret == 0){
        	rg_exe_shell(buf,sizeof(buf) - 1);
		}else{
			memset(buf,0,sizeof(buf));
			rg_error_msg(ret,buf);
		}
        setsockopt(sd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(struct timeval));
        if (0 > sendto(sd,buf,strlen(buf),0,(struct sockaddr *)&client_addr,sizeof(client_addr))){
            perror("Server: failed to send");
        }
    }
}
