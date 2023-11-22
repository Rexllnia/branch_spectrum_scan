#include "rg_wds.h"

void rg_wds_lock_status_update(char *data) {
    if (rg_pair_info_heap_t == NULL) {
        return;
    }

    pthread_mutex_lock(&rg_pair_mtx);
    struct wds_date_head *wds_receve;
    char *mac;
    struct pair_dev_ath_info *p = rg_pair_info_heap_t;

    mac = data + 6;
    wds_receve = (struct wds_packet *)((u_char *)data + 44);

    while (p) {
        if (memcmp(mac,p->mac,6) == 0) {
            p->lock_info_t.gpio_lock_value = wds_receve->lock;
            break;
        }
        p = p->next;
    }
    pthread_mutex_unlock(&rg_pair_mtx);
}

