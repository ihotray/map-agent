#ifndef BACKHAUL_H
#define BACKHAUL_H

void backhaul_bssid_clear(struct agent *a, struct netif_bk *bk);
void backhaul_blacklist_clear(struct agent *a);
bool backhaul_blacklist_update(struct agent *a);
bool backhaul_blacklist_update_ifname(struct agent *a, char *ifname);
bool backhaul_blacklist_contains(struct agent *a, struct netif_bk *bk,
				   uint8_t *bssid);
bool backhaul_blacklist_add(struct agent *a, struct netif_bk *bk,
			      uint8_t *bssid);
bool backhaul_blacklist_del(struct agent *a, struct netif_bk *bk,
			      uint8_t *bssid);
bool backhaul_mod_blacklist(struct agent *a, char *port, char *ssid,
			     uint8_t ssidlen, uint8_t *bssid);

#endif