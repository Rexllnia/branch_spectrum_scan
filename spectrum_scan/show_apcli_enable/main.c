#include "main.h"

int main() 
{
    char ifname[IFNAMSIZ];
    spctrm_scn_wireless_get_band_5G_apcli_ifname(ifname);
    spctrm_scn_wireless_show_apcli_enable(ifname);

    return 0;
}