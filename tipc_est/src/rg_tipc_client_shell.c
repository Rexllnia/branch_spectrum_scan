#include "rg_tipc.h"
#include "rg_tipc_crypto.h"
#include <stdio.h>
#include <sys/resource.h>

int rg_analyze_softversion(unsigned char *softversion,unsigned char *item_number,unsigned char *time_number)
{
    unsigned char *softver, *tmp_version;

    if (!softversion) {
        //TIPC_DEBUG("native software-version is NULL");
        return FAIL;
    }

    if (!item_number) {
        //TIPC_DEBUG("item_number is NULL");
        return FAIL;
    }

    if (!time_number) {
        //TIPC_DEBUG("time_number is NULL");
        return FAIL;
    }
	
	//softver:AP_3.0(1)B11P58,Release(08191201)

	//第一次遇到','取出项目编号58
    softver = softversion;
    tmp_version = strchr(softver, ',');
    if (!tmp_version) {
        return FAIL;
    }
	strncpy(item_number, tmp_version - 2, 2);

	//最后一次遇到'（'取出版本时间信息08191201
    tmp_version = strrchr(softver, '(');
    if (!tmp_version) {
        return FAIL;
    }
	strncpy(time_number, tmp_version + 1, 8);

	//printf("item_num:%s,time_num:%s\n",item_number,time_number);
	
    return SUCESS;
}

int main(int argc,char *argv[])
{
	int sd;
	struct sockaddr_tipc server_addr;
    unsigned int instance = 0;
    unsigned char buf[BUF_SIZE];
	unsigned char *md5buf;
    char *tmp;
    int flag;
    struct timeval timeout={4,0};
    unsigned char mac[20];
	unsigned char send_mac[20];
	unsigned char softversion[64], item_num[8], time_num[16];
	int ret = 0;
	char count = 0;
    
    pid_t process_id;
    char pid[8] = "";
    char client_outf_file[32]= CILENT_OUTF_FILE;
    char client_inf_file[32] = CILENT_INF_FILE;
    int i;
#ifdef CONFIG_TIPC_CORE_DUBUG
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limit);
#endif

    process_id = getpid();
    sprintf(pid,"%d",process_id);
    
    if (argc != 2) {
        perror("Tip:rg_tipc_client_shell aa:bb:cc:dd:ee:ff\n");
        exit(1);
    }

    if (strlen(argv[1]) != 17 && !strchr(argv[1],':')) {
        memset(mac,0,sizeof(mac));
        char num = 0;
        while(1){
            rg_sn_to_mac(argv[1],mac);
            if (num++>3 || strlen(mac) == 17) {
                break;
            }
        }
        if (strlen(mac) != 17) {
            printf("error\n");
            return 0;
        }
        instance = rg_mist_mac_2_nodeadd(mac);
		strcpy(send_mac,mac);
		//printf("sn send_mac %s\n",send_mac);
    } else {
        instance = rg_mist_mac_2_nodeadd(argv[1]);
		strcpy(send_mac,argv[1]);
		//printf("argv send_mac %s\n",send_mac);
    }

	//1.根据mac地址获取软件版本号（表示时间的8位），判断是否支持新TIPC通讯协议
	memset(softversion,0,sizeof(softversion));
    while(1){
        rg_mac_to_softver(send_mac,softversion);
        if (count++>3 || strlen(softversion) > 0) {
                break;
    	}
    }
	//printf("softversion:%s\n",softversion);
	if (strlen(softversion) == 0) {
        //printf("softversion recv error\n");
        return 0;
    }

    if (instance == 0) {
        printf("error\n");
        return;
    }

	//2.校验获取到的版本信息，选择数据发送方式
	//strcpy(softversion,"AP_3.0(1)B11P58,Release(08191201)");
	memset(item_num, 0, sizeof(item_num));
    memset(time_num, 0, sizeof(time_num));
	ret = rg_analyze_softversion(softversion,item_num,time_num);
	if(ret != 0){
		printf("error.\n");
		return;
	}
    memset(buf,0,sizeof(buf));
    gets(buf);
	if (wait_for_server(SERVER_TYPE,instance,3000) == FAIL){
        printf("error\n");
        return;
    }

	sd = socket(AF_TIPC, SOCK_RDM, 0);

	server_addr.family = AF_TIPC;
	server_addr.addrtype = TIPC_ADDR_NAME;
	server_addr.addr.name.name.type = SERVER_TYPE;
	server_addr.addr.name.name.instance = instance;
	server_addr.addr.name.domain = 0;
   
	if(strcmp(item_num,NEW_TIPC_ITEM) >= 0 && strcmp(time_num,NEW_TIPC_TIME) >= 0){
		//3.计算MD5值并填充到命令数据buf的末尾准备一次性发送
		md5buf = md5_coding(buf);
		memcpy(buf+strlen(buf),md5buf,strlen(md5buf));
		//printf("cmd+md5:%s\n\n",buf);
		
        //组合出新的文件名
        strcat(client_inf_file,pid);
        strcat(client_outf_file,pid);

		//4.将命令数据和MD5值作为一个整体写入 CILENT_INF_FILE,进行加密  
		FILE *inf_fd;
		inf_fd = fopen(client_inf_file, "w+");
		if (inf_fd == NULL) {
	        printf("error\n");
			return;
	    }
		fwrite(buf,strlen(buf),1,inf_fd);
		fclose(inf_fd);
		inf_fd = NULL;
        
		char *inf  = client_inf_file; 
		char *outf = client_outf_file;
	    aes_coding(inf, outf, AES_128_CBC, ENCRYPT);
        
        i = 0;
        for(i=0;i<5;i++){
           if(remove(client_inf_file) == 0){
            break;
           }else{
            printf("error\n");
           }
        }
		//5.读取aes_coding生成的加密文件的数据准备发送
		memset(buf,0,sizeof(buf));
		FILE *outf_fd;
		outf_fd = fopen(client_outf_file, "r");
		if (outf_fd == NULL) {
	        printf("error remove\n");
			return;
	    }
		fread(buf,1,sizeof(buf),outf_fd);
		fclose(outf_fd);
        outf_fd = NULL;

        i = 0;
        for(i=0;i<5;i++){
           if(remove(client_outf_file) == 0){
            break;
           }else{
            printf("error remove\n");
           }
        }
        
		//6.发送buf末尾增加 CRYPTO_MARK_STR 区分新旧通讯方式，供server区分
		strncpy((buf+strlen(buf)-1),CRYPTO_MARK_STR,sizeof(CRYPTO_MARK_STR));
		}
    setsockopt(sd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(struct timeval));
	if (0 > sendto(sd,buf,strlen(buf)+1,0,(struct sockaddr*)&server_addr,sizeof(server_addr))) {
        printf("error\n");
        goto end;
	}

    setsockopt(sd,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(struct timeval));
    memset(buf,0,sizeof(buf));
	if (0 >= recv(sd,buf,sizeof(buf) - 1,0)) {
        printf("error\n");
        goto end;
    }
    tmp = buf + strlen("sucess\n");
    printf("%s\n",tmp);
  
end:
    close(sd);
    return;
}
