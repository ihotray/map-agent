/*
 * wifi_scanresults.h - scan cache structs and defines
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: filip.matusiak@iopsys.eu
 *
 */
#ifndef _WIFI_SCAN_RESULTS_H_
#define _WIFI_SCAN_RESULTS_H_

struct wifi_scanresults_entry {
	struct wifi_bss bss;
#define SCANRESULTS_MAX_AGE	300000    /* 5 mins */
	struct timespec tsp;
	uint8_t opclass;
	bool expired;
};

struct wifi_scanresults {
#define SCANRESULTS_MAX_NUM	128
	int entry_num;
	struct wifi_scanresults_entry entry[SCANRESULTS_MAX_NUM];
};

struct wifi_scanresults_entry *wifi_scanresults_get_entry(
		struct wifi_scanresults *results, uint8_t *bssid);
int wifi_scanresults_add(struct wifi_scanresults *results,
		struct wifi_radio_opclass *opclass, struct wifi_bss *bsss,
		int bss_num);
void wifi_scanresults_mark_expired(struct wifi_scanresults *results);

struct wifi_bss *wifi_scanresults_get_bss(char *ifname, uint8_t *bssid,
		struct wifi_bss *out);

#endif /* _WIFI_SCAN_RESULTS_H_ */
