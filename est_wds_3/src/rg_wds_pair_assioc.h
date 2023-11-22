#ifndef _RG_WDS_PAIR_ASSIOC_H__
#define _RG_WDS_PAIR_ASSIOC_H__
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;

typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef unsigned long long u_int64_t;

typedef unsigned int size_t;
typedef unsigned int u_int;
typedef unsigned long u_long;


#define IEEE80211_RATE_MAXSIZE  44
#define IEEE80211_ADDR_LEN      6
#define LIST_STATION_ALLOC_SIZE 24*1024
#define	IEEE80211_IOCTL_STA_INFO	(SIOCDEVPRIVATE + 0x06)
#define IEEE80211_RATE_VAL              0x7f
#define IEEE80211_AID(b)    ((b) &~ 0xc000)

#define SSID_IFNMAE_LEN         20
#define SSID_LEN                128
#define CLI_MAC_LEN             20
#define ADDR_LEN                17
#define REASON_LEN              52

#define	 RJ80211_MAC_CNT   32

#define MAC_TAB_LEN  6000    //sizeof(RJ80211_MAC_TABLE)+sizeof(rj_stainfo_t)
    					     //			16 			   +     152        *    32(cpe)  = 4880 < 5120

#define  REBOOT_WIFI	1
#define  REBOOT_DEV		2

#define WAS_GET_STAINFO                    (1 << 0)
#define WAS_GET_STAEXPINFO                 (1 << 1)

/*
 * Station information block; the mac address is used
 * to retrieve other data like stats, unicast key, etc.
 */
 
struct ieee80211req_sta_info {
        u_int16_t       isi_len;                /* length (mult of 4) */
        u_int16_t       isi_freq;               /* MHz */
        u_int32_t       awake_time;             /* time is active mode */
        u_int32_t       ps_time;                /* time in power save mode */
        u_int32_t       isi_flags;      /* channel flags */
        u_int16_t       isi_state;              /* state flags */
        u_int8_t        isi_authmode;           /* authentication algorithm */
        int8_t          isi_rssi;
        int8_t          isi_min_rssi;
        int8_t          isi_max_rssi;
        u_int16_t       isi_capinfo;            /* capabilities */
        u_int8_t        isi_athflags;           /* Atheros capabilities */
        u_int8_t        isi_erp;                /* ERP element */
        u_int8_t        isi_ps;         /* psmode */
        u_int8_t        isi_macaddr[IEEE80211_ADDR_LEN];
        u_int8_t        isi_nrates;
                                                /* negotiated rates */
        u_int8_t        isi_rates[IEEE80211_RATE_MAXSIZE];
        u_int8_t        isi_txrate;             /* index to isi_rates[] */
        u_int32_t       isi_txratekbps; /* tx rate in Kbps, for 11n */
        u_int16_t       isi_ie_len;             /* IE length */
        u_int16_t       isi_associd;            /* assoc response */
        u_int16_t       isi_txpower;            /* current tx power */
        u_int16_t       isi_vlan;               /* vlan tag */
        u_int16_t       isi_txseqs[17];         /* seq to be transmitted */
        u_int16_t       isi_rxseqs[17];         /* seq previous for qos frames*/
        u_int16_t       isi_inact;              /* inactivity timer */
        u_int8_t        isi_uapsd;              /* UAPSD queues */
        u_int8_t        isi_opmode;             /* sta operating mode */
        u_int8_t        isi_cipher;
        u_int32_t       isi_assoc_time;         /* sta association time */
        struct timespec isi_tr069_assoc_time;   /* sta association time in timespec format */


        u_int16_t   isi_htcap;      /* HT capabilities */
        u_int32_t   isi_rxratekbps; /* rx rate in Kbps */
                                /* We use this as a common variable for legacy rates
                                   and lln. We do not attempt to make it symmetrical
                                   to isi_txratekbps and isi_txrate, which seem to be
                                   separate due to legacy code. */
        /* XXX frag state? */
        /* variable length IE data */
        u_int8_t isi_maxrate_per_client; /* Max rate per client */
        u_int16_t   isi_stamode;        /* Wireless mode for connected sta */
        u_int32_t isi_ext_cap;              /* Extended capabilities */
        u_int8_t isi_nss;         /* number of tx and rx chains */
        u_int8_t isi_is_256qam;    /* 256 QAM support */
        u_int8_t isi_operating_bands : 2; /* Operating bands */
#if ATH_SUPPORT_EXT_STAT
        u_int8_t  isi_chwidth;            /* communication band width */
        u_int32_t isi_vhtcap;             /* VHT capabilities */
#endif
#ifndef CONFIG_NOT_RGOS
        u_int32_t       isi_time_delay;         /* sta recv signal delayed time*/
        u_int32_t       isi_pkt_loserate;       /* sta recv packet lose rate */
        u_int64_t       isi_wifiup_byte;             /* sta down flow count */
        u_int64_t       isi_wifidown_byte;           /* sta up flow count */
#endif
};


#endif

