/*
 * wifi_scanresults.c - scan results cache functions
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: filip.matusiak@iopsys.eu
 *
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <easy/easy.h>

#include "utils/utils.h"
#include "utils/debug.h"

#include "wifi.h"
#include "wifi_opclass.h"
#include "wifi_scanresults.h"

static int _wifi_scanresults_update(struct wifi_scanresults *results,
		struct wifi_radio_opclass *opclass, struct wifi_bss *bss)
{
	struct wifi_scanresults_entry *entry;
	bool found = false;
	int i;

	if (!results)
		return -1;

	if (!bss)
		return -1;

	/* lookup entry in results by bssid */
	for (i = 0; i < results->entry_num; i++) {
		entry = &results->entry[i];

		if (!memcmp(bss->bssid, entry->bss.bssid, 6)) {
			/* entry found */
			found = true;
			break;
		}
	}

	if (!found) {
		if (results->entry_num < SCANRESULTS_MAX_NUM) {
			/* add new entry at the end */
			entry = &results->entry[results->entry_num];
			results->entry_num++;
		} else {
			dbg("%s: error getting entry for bssid " MACFMT "\n",
			    __func__, MAC2STR(bss->bssid));
			return -1;
		}
	}

	timestamp_update(&entry->tsp);
	entry->expired = false;
	/* copy */
	memcpy(&entry->bss, bss, sizeof(struct wifi_bss));
	/* always calculate opclass */
	entry->opclass = wifi_opclass_get_id(opclass,
					     bss->channel,
					     20); /* TODO: curr_bw */

	return 0;
}

int wifi_scanresults_add(struct wifi_scanresults *results,
		struct wifi_radio_opclass *opclass, struct wifi_bss *bsss,
		int bss_num)
{
	trace("%s: --->\n", __func__);

	int i;

	for (i = 0; i < bss_num; i++)
		_wifi_scanresults_update(results, opclass, &bsss[i]);

	return 0;
}

/* Check for outdated scan results and mark as 'expired' */
void wifi_scanresults_mark_expired(struct wifi_scanresults *results)
{
	int i;
	struct wifi_scanresults_entry *en;

	for (i = 0; i < results->entry_num; i++) {
		en = &results->entry[i];

		if (en->expired == false &&
				timestamp_expired(&en->tsp, SCANRESULTS_MAX_AGE))
			en->expired = true;
	}
}

static struct wifi_bss *bss_get_fresh(char *ifname,
		uint8_t *bssid, struct wifi_bss *out)
{
	struct wifi_bss *bsss;
	char *data;
	/* void *a; */
	int num;
	int i;

	num = 256;
	data = calloc(num, sizeof(struct wifi_bss));
	if (!data) {
		warn("OOM scan results\n");
		return NULL;
	}
	bsss = (struct wifi_bss *)data;
	if (wifi_get_scan_results(ifname, bsss, &num) != 0) {
		dbg("error getting scanresults '%s'\n", ifname);
		goto out_free;
	}

	for (i = 0; i < num; i++) {
		if (!memcmp(bsss[i].bssid, bssid, 6)) {
			if (out)
				memcpy(out, &bsss[i], sizeof(struct wifi_bss));
			free(data);
			return out;
		}
	}
	dbg("Neighbor " MACFMT " NOT in scanresults\n", MAC2STR(bssid));
out_free:
	free(data);
	return NULL;
}

struct wifi_bss *wifi_scanresults_get_bss(char *ifname,
		uint8_t *bssid, struct wifi_bss *out)
{
	/* FIXME use stored scan results instead of fresh */
	return bss_get_fresh(ifname, bssid, out);
}
