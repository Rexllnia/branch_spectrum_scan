#include "rg_wds.h"
#define BUFFER_MAX 2048

enum{
    NORMAL_PKT  = 1, //正序数据包一个0x55加一个0xaa
    REVERSE_PKT = 2, //反序数据包一个0xaa加一个0x55
    SINGLE_PKT  = 3, //单个数据包0x55
    NOMATCH_PKT = 4  //本次数据包未匹配到
};

void rg_get_packet_func(const u_char * packet)
{
    struct mac_ip_udp_wds_packet *mac_all_date;
	struct wds_date_head *wds_receve;
	u_int16_t len;

	//过滤本机
	if (memcmp(rg_ath_info_t.root_mac_hex,packet + 6,6) == 0) {
		return;
	}

    pthread_mutex_lock(&rg_pair_mtx);
    /* 设置ssid前进行二层、三层、四层、保活数据位、以及桥接关联等情况来判断置上version_flag */
    if (rg_wds_check_all_packet_validity(packet) == -1) {
        pthread_mutex_unlock(&rg_pair_mtx);
        return;
    }
    pthread_mutex_unlock(&rg_pair_mtx);

    rg_wds_lock_status_update(packet);

    len = *((unsigned short *)&packet[16]) - 20 - 8 - sizeof(struct mac_ip_udp_wds_packet);
    wds_receve = (struct wds_packet *)((u_char *)packet + 44);
    switch (wds_receve->sync_flag) {
        case SYNC_KEEP_LIVE:
            rg_wds_get_keep_date((u_char *)packet,len);
            break;
        case SYNC_VERSION:
            rg_wds_version_get((u_char *)packet,len);
            break;
        case SYNC_SOFTWARE_VERSION:
            rg_wds_get_softversion((u_char *)packet,len);
            break;
        default:
            GPIO_DEBUG("50001 unknow type:%d",wds_receve->sync_flag);
            break;
    }
}

void rg_get_packet_func_2(const u_char * packet) {
    struct mac_ip_udp_wds_packet *mac_all_date;
	u_int16_t len;
    char *p;

    p = (struct wds_packet *)((u_char *)packet + 44);
    //字符串合格性校验
    if (p[0] != '#' || p[strlen(p) - 1] != '#') {
        GPIO_DEBUG("udp data check # error");
        return;
    }
    GPIO_DEBUG("udp data get:\n%s",p);
    rg_wds_message_dev_process(p,false);
}

void rg_get_packet_handle(char *crypto_buf,const u_char * packet,bool b_start) {
	u_int16_t len;
    char *p;
    char *p2;
    if(b_start == true){
        memcpy(crypto_buf,packet,BUFFER_MAX);
    } else {
        p = (struct wds_packet *)((u_char *)packet + 44);
        p2= (struct wds_packet *)((u_char *)crypto_buf + 44);
        strcat(p2,p);
    }
}

void* thread_pool_pkt_task(void *arg) {
    rg_get_packet_func_2(arg);
    free(arg);
    return NULL;
}

void* thread_pool_pkt_push(thread_pool *pool ,char *packet) {
    char *argdata = malloc(BUFFER_MAX);
    if(argdata == NULL){
       return;
    }
    memcpy(argdata,packet,BUFFER_MAX);
    pool_task_t *task = malloc(sizeof(pool_task_t));
    if(task  == NULL){
        free(argdata);
        return;
    } 
    task->function = &thread_pool_pkt_task;
    task->arg = argdata;

    pthread_mutex_lock(&(pool->mutex));
    while(pool->count == MAX_TASKS) { 
        pthread_cond_wait(&(pool->cond_not_full), &(pool->mutex));
    }
    pool->tasks[pool->head] = task;
    pool->head = (pool->head + 1) % THREAD_POOL_SIZE;
    pool->count++;
    pthread_cond_signal(&(pool->cond_not_empty));
    pthread_mutex_unlock(&(pool->mutex));
    return;
                    
}

void* thread_pool_func(void *arg) {
    thread_pool* pool = (thread_pool*)arg;
    while(1) {
        pthread_mutex_lock(&(pool->mutex));
        while(pool->count == 0) {
            pthread_cond_wait(&(pool->cond_not_empty), &(pool->mutex));
        }

        pool_task_t *task = pool->tasks[pool->tail];
        pool->tail = (pool->tail + 1) % THREAD_POOL_SIZE;
        pool->count--;
        pthread_cond_signal(&(pool->cond_not_full));
        pthread_mutex_unlock(&(pool->mutex));

        task->function(task->arg);
        free(task);
    }
}

int thread_pool_init(thread_pool *pool) {
    int i=0;
    pool->count = 0;
    pool->head = 0;
    pool->tail = 0;
    pthread_mutex_init(&(pool->mutex), NULL);
    pthread_cond_init(&(pool->cond_not_empty), NULL);
    pthread_cond_init(&(pool->cond_not_full), NULL);

    //动态分配以后再说吧
    for(i=0; i<THREAD_POOL_SIZE; ++i){
        pthread_create(&(pool->threads[i]), NULL, thread_pool_func, pool);
    }
    return 0;
}

void ringbuffer_packet_write(       RingBuffer *ringbuf,char *packet) {
    pthread_mutex_lock(&ringbuf->lock);
    if ((ringbuf->tail + 1) % RINGBUF_MAX == ringbuf->head) { // Buffer is full
        GPIO_DEBUG("ringbuffer is full delete oldest data");
        ringbuf->head = (ringbuf->head + 1) % RINGBUF_MAX; // Move start index to next packet
    }
    char *p;
    char *p2;
    p = (struct wds_packet *)((u_char *)packet + 44);
    memcpy(ringbuf->buffer[ringbuf->tail], packet, MTU_SIZE); // Copy new data into buffer, overwriting old data
    p2 = (struct wds_packet *)((u_char *)(ringbuf->buffer[ringbuf->tail]) + 44);
    ringbuf->tail = (ringbuf->tail + 1) % RINGBUF_MAX; // Move end index to next position
    pthread_cond_signal(&ringbuf->cond); // Signal that new data has arrived
    pthread_mutex_unlock(&ringbuf->lock); 
}

char* ringbuffer_packet_read(RingBuffer *ringbuf) {
    pthread_mutex_lock(&ringbuf->lock);
    while (ringbuf->head == ringbuf->tail) { // If buffer is empty...
        pthread_cond_wait(&ringbuf->cond, &ringbuf->lock); // ...wait for new data to arrive
    }
    char *data = malloc(MTU_SIZE);
    memcpy(data, ringbuf->buffer[ringbuf->head], MTU_SIZE); 
    ringbuf->head = (ringbuf->head + 1) % RINGBUF_MAX;
    pthread_mutex_unlock(&ringbuf->lock);
    return data;
}

int ringbuffer_pkt_match(char *prev_pkt, char *curr_pkt) {
    char *p_prev,*p_curr;
    unsigned char prev_mac[6],curr_mac[6];
    
    p_prev = prev_pkt + 34;
    p_curr = curr_pkt + 34;
    
    memset(prev_mac, 0, sizeof(prev_mac));
    memset(curr_mac, 0, sizeof(curr_mac));

    prev_mac[0] = prev_pkt[6]&0XFF;
    prev_mac[1] = prev_pkt[7]&0XFF;
    prev_mac[2] = prev_pkt[8]&0XFF;
    prev_mac[3] = prev_pkt[9]&0XFF;
    prev_mac[4] = prev_pkt[10]&0XFF;
    prev_mac[5] = prev_pkt[11]&0XFF;

    curr_mac[0] = curr_pkt[6]&0XFF;
    curr_mac[1] = curr_pkt[7]&0XFF;
    curr_mac[2] = curr_pkt[8]&0XFF;
    curr_mac[3] = curr_pkt[9]&0XFF;
    curr_mac[4] = curr_pkt[10]&0XFF;
    curr_mac[5] = curr_pkt[11]&0XFF;
    //GPIO_DEBUG("------->prev_mac %02x:%02x:%02x:%02x:%02x:%02x curr_mac %02x:%02x:%02x:%02x:%02x:%02x",
    //     prev_mac[0], prev_mac[1], prev_mac[2], prev_mac[3], prev_mac[4], prev_mac[5],
    //     curr_mac[0], curr_mac[1], curr_mac[2], curr_mac[3], curr_mac[4], curr_mac[5]);

    //类型0x55，且match值为0，表示是单个包，不需要拼接的
    if((p_curr[2]&0XFF) == 0x55 && (p_curr[3]&0XFF) == 0){
       GPIO_DEBUG("------->handle packet OK single");
       return SINGLE_PKT;
    }

    //比较当前包和前一个包的mac地址和match值是否一样，一样就认为是一组
    if(memcmp(prev_mac,curr_mac,6) == 0 && (p_prev[3]&0XFF) == (p_curr[3]&0XFF)){
        if((p_curr[2]&0XFF) == 0xAA){
            GPIO_DEBUG("------->handle packet OK normal");
            return NORMAL_PKT; 
        }else {
            GPIO_DEBUG("------->handle packet OK reverese");
            return REVERSE_PKT;
        }
    }
    //GPIO_DEBUG("------->handle packet no match");
    return NOMATCH_PKT;   
}

void ringbuffer_pkt_recv_pthread(void* arg)
{
    int sock,n_read,proto;
    char *ethhead, *iphead,*p, *buffer;
    RingBuffer *ringbuf = (RingBuffer*)arg;
begin:
    if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
    {
        printf("create socket error\n");
        sleep(3);
        goto begin;
    }
    
begin2:    
    buffer = malloc(BUFFER_MAX);
    if (buffer == NULL) {
        sleep(3);
        goto begin2;
    }
    
    while(1)
    {
        memset(buffer,0,BUFFER_MAX);
        n_read = recvfrom(sock, buffer, BUFFER_MAX, 0, NULL, NULL);
           /*
           14   6(dest)+6(source)+2(type or length)
           +
           20   ip header
           +
           8   icmp,tcp or udp header
           = 42
           */
        if(n_read < 42)
        {
            fprintf(stdout, "Incomplete header, packet corrupt\n");
            continue;
        }

        ethhead = buffer;
        p = ethhead;

        iphead = ethhead + 14;
        p = iphead + 12;

        proto = (iphead + 9)[0];
        p = iphead + 20;

        if (proto == IPPROTO_UDP && ((p[0]<<8)&0XFF00 | p[1]&0XFF) == 50001) {
            rg_get_packet_func(buffer);
        } else if (proto == IPPROTO_UDP && ((p[0]<<8)&0XFF00 | p[1]&0XFF) == 50002) {
            rg_get_packet_func_2(buffer);
        } else if (proto == IPPROTO_UDP && ((p[0]<<8)&0XFF00 | p[1]&0XFF) == 50003) {
            if((p[2]&0XFF) == 0x55){
                GPIO_DEBUG("------->get 0x55 ok %02x:%02x:%02x:%02x:%02x:%02x match_val:%d", ethhead[6]&0XFF,ethhead[7]&0XFF,
                ethhead[8]&0XFF,ethhead[9]&0XFF,ethhead[10]&0XFF,ethhead[11]&0XFF,p[3]&0XFF);
                ringbuffer_packet_write(ringbuf, buffer);
            } else if((p[2]&0XFF) == 0xAA){
                GPIO_DEBUG("------->get 0xAA ok %02x:%02x:%02x:%02x:%02x:%02x match_val:%d", ethhead[6]&0XFF,ethhead[7]&0XFF,
                ethhead[8]&0XFF,ethhead[9]&0XFF,ethhead[10]&0XFF,ethhead[11]&0XFF,p[3]&0XFF);
                ringbuffer_packet_write(ringbuf, buffer);   
            }  
        }
    }
}

void ringbuffer_pkt_handle_pthread(void *arg) {
    char *pkt1,*pkt2;
    int ret;
    thread_args* args = (thread_args*)arg;
    RingBuffer* ringbuf = args->ringbuf;
    thread_pool* pool = args->pool;
    //RingBuffer* ringbuf = (RingBuffer*)arg;
begin1:    
    pkt1 = malloc(BUFFER_MAX);
    if (pkt1 == NULL) {
        sleep(3);
        goto begin1;
    }
    
begin2:    
    pkt2 = malloc(BUFFER_MAX);
    if (pkt2 == NULL) {
        sleep(3);
        goto begin2;
    }

    while(1){
        pthread_mutex_lock(&ringbuf->lock);
        while (ringbuf->head == ringbuf->tail) { // If buffer is empty...
            GPIO_DEBUG("ringbuffer empty cpu hangs ok");
            pthread_cond_wait(&ringbuf->cond, &ringbuf->lock); // ...wait for new data to arrive    
        }
        memset(pkt2, 0, 2048);
        char *p;
        p = (struct wds_packet *)((u_char *)(ringbuf->buffer[ringbuf->head]) + 44);
        
        memcpy(pkt2, ringbuf->buffer[ringbuf->head], MTU_SIZE); 
        ringbuf->head = (ringbuf->head + 1) % RINGBUF_MAX;
        pthread_mutex_unlock(&ringbuf->lock);
        
        ret = ringbuffer_pkt_match(pkt1, pkt2);
        switch (ret) {
            case NORMAL_PKT:
                rg_get_packet_handle(pkt1,pkt2,false);
                thread_pool_pkt_push(pool,pkt1);
                GPIO_DEBUG("push normal packet to thread pool done");
                break;
            case REVERSE_PKT:
                rg_get_packet_handle(pkt2,pkt1,false);
                thread_pool_pkt_push(pool,pkt2);
                GPIO_DEBUG("push reverse packet to thread pool done");
                memset(pkt1, 0 ,BUFFER_MAX);
                break;
            case SINGLE_PKT:
                thread_pool_pkt_push(pool,pkt2);
                GPIO_DEBUG("push single packet to thread pool done");
                break;
            case NOMATCH_PKT:
                memset(pkt1, 0 ,BUFFER_MAX);
                memcpy(pkt1, pkt2, BUFFER_MAX);
                break;
            default:
                memset(pkt1, 0 ,BUFFER_MAX);
                memcpy(pkt1, pkt2, BUFFER_MAX);
                GPIO_DEBUG("unknow packet");
                break;
        }
    }
}

int ringbuffer_init(     RingBuffer *ringbuf) {
    int i = 0;
    for (i = 0; i < RINGBUF_MAX; i++) {
        begin:
        ringbuf->buffer[i] = malloc(MTU_SIZE);
        memset(ringbuf->buffer[i],0,MTU_SIZE);
        if(ringbuf->buffer[i] == NULL){
            sleep(3);
            goto begin;
        }
    }
    ringbuf->head = 0;
    ringbuf->tail = 0;
    pthread_mutex_init(&ringbuf->lock, NULL);
    pthread_cond_init(&ringbuf->cond, NULL);
    GPIO_DEBUG("ring buffer init success");
    return 0;
}

