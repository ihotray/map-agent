#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <easy/easy.h>
#include "utils/utils.h"
#include "easymesh.h"
#include "utils/debug.h"
#include "wifi_opclass.h"

static const struct wifi_radio_opclass e4 = {
	.entry_num = 20,
	.entry = {
		{
			.id = 81,
			.bandwidth = 20,
			.channel_num = 13,
			.channel = {
				{ .channel = 1, .ctrl_channels = {1}},
				{ .channel = 2, .ctrl_channels = {2}},
				{ .channel = 3, .ctrl_channels = {3}},
				{ .channel = 4, .ctrl_channels = {4}},
				{ .channel = 5, .ctrl_channels = {5}},
				{ .channel = 6, .ctrl_channels = {6}},
				{ .channel = 7, .ctrl_channels = {7}},
				{ .channel = 8, .ctrl_channels = {8}},
				{ .channel = 9, .ctrl_channels = {9}},
				{ .channel = 10, .ctrl_channels = {10}},
				{ .channel = 11, .ctrl_channels = {11}},
				{ .channel = 12, .ctrl_channels = {12}},
				{ .channel = 13, .ctrl_channels = {13}},
			}
		},
		{
			.id = 82,
			.bandwidth = 20,
			.channel_num = 1,
			.channel = {
				{ .channel = 14, .ctrl_channels = {14}},
			}
		},
		{
			.id = 83,
			.bandwidth = 40,
			.channel_num = 9,
			.channel = {
				{ .channel = 1, .ctrl_channels = {1}},
				{ .channel = 2, .ctrl_channels = {2}},
				{ .channel = 3, .ctrl_channels = {3}},
				{ .channel = 4, .ctrl_channels = {4}},
				{ .channel = 5, .ctrl_channels = {5}},
				{ .channel = 6, .ctrl_channels = {6}},
				{ .channel = 7, .ctrl_channels = {7}},
				{ .channel = 8, .ctrl_channels = {8}},
				{ .channel = 9, .ctrl_channels = {9}},
			}
		},
		{
			.id = 84,
			.bandwidth = 40,
			.channel_num = 9,
			.channel = {
				{ .channel = 5, .ctrl_channels = {5}},
				{ .channel = 6, .ctrl_channels = {6}},
				{ .channel = 7, .ctrl_channels = {7}},
				{ .channel = 8, .ctrl_channels = {8}},
				{ .channel = 9, .ctrl_channels = {9}},
				{ .channel = 10, .ctrl_channels = {10}},
				{ .channel = 11, .ctrl_channels = {11}},
				{ .channel = 12, .ctrl_channels = {12}},
				{ .channel = 13, .ctrl_channels = {13}},
			}
		},
		{
			.id = 115,
			.bandwidth = 20,
			.channel_num = 4,
			.channel = {
				{ .channel = 36, .ctrl_channels = {36}},
				{ .channel = 40, .ctrl_channels = {40}},
				{ .channel = 44, .ctrl_channels = {44}},
				{ .channel = 48, .ctrl_channels = {48}},
			}
		},
		{
			.id = 116,
			.bandwidth = 40,
			.channel_num = 2,
			.channel = {
				{ .channel = 36, .ctrl_channels = {36}},
				{ .channel = 44, .ctrl_channels = {44}},
			}
		},
		{
			.id = 117,
			.bandwidth = 40,
			.channel_num = 2,
			.channel = {
				{ .channel = 40, .ctrl_channels = {40}},
				{ .channel = 48, .ctrl_channels = {48}},
			}
		},
		{
			.id = 118,
			.bandwidth = 20,
			.channel_num = 4,
			.channel = {
				{ .channel = 52, .ctrl_channels = {52}},
				{ .channel = 56, .ctrl_channels = {56}},
				{ .channel = 60, .ctrl_channels = {60}},
				{ .channel = 64, .ctrl_channels = {64}},
			}
		},
		{
			.id = 119,
			.bandwidth = 40,
			.channel_num = 2,
			.channel = {
				{ .channel = 52, .ctrl_channels = {52}},
				{ .channel = 60, .ctrl_channels = {60}},
			}
		},
		{
			.id = 120,
			.bandwidth = 40,
			.channel_num = 2,
			.channel = {
				{ .channel = 56, .ctrl_channels = {56}},
				{ .channel = 64, .ctrl_channels = {64}},
			}
		},
		{
			.id = 121,
			.bandwidth = 20,
			.channel_num = 12,
			.channel = {
				{ .channel = 100, .ctrl_channels = {100}},
				{ .channel = 104, .ctrl_channels = {104}},
				{ .channel = 108, .ctrl_channels = {108}},
				{ .channel = 112, .ctrl_channels = {112}},
				{ .channel = 116, .ctrl_channels = {116}},
				{ .channel = 120, .ctrl_channels = {120}},
				{ .channel = 124, .ctrl_channels = {124}},
				{ .channel = 128, .ctrl_channels = {128}},
				{ .channel = 132, .ctrl_channels = {132}},
				{ .channel = 136, .ctrl_channels = {136}},
				{ .channel = 140, .ctrl_channels = {140}},
				{ .channel = 144, .ctrl_channels = {144}},
			}
		},
		{
			.id = 122,
			.bandwidth = 40,
			.channel_num = 6,
			.channel = {
				{ .channel = 100, .ctrl_channels = {100}},
				{ .channel = 108, .ctrl_channels = {108}},
				{ .channel = 116, .ctrl_channels = {116}},
				{ .channel = 124, .ctrl_channels = {124}},
				{ .channel = 132, .ctrl_channels = {132}},
				{ .channel = 140, .ctrl_channels = {140}},
			}
		},
		{
			.id = 123,
			.bandwidth = 40,
			.channel_num = 6,
			.channel = {
				{ .channel = 104, .ctrl_channels = {104}},
				{ .channel = 112, .ctrl_channels = {112}},
				{ .channel = 120, .ctrl_channels = {120}},
				{ .channel = 128, .ctrl_channels = {128}},
				{ .channel = 136, .ctrl_channels = {136}},
				{ .channel = 144, .ctrl_channels = {144}},
			}
		},
		{
			.id = 124,
			.bandwidth = 40,
			.channel_num = 4,
			.channel = {
				{ .channel = 149, .ctrl_channels = {149}},
				{ .channel = 153, .ctrl_channels = {153}},
				{ .channel = 157, .ctrl_channels = {157}},
				{ .channel = 161, .ctrl_channels = {161}},
			}
		},
		{
			.id = 125,
			.bandwidth = 20,
			.channel_num = 6,
			.channel = {
				{ .channel = 149, .ctrl_channels = {149}},
				{ .channel = 153, .ctrl_channels = {153}},
				{ .channel = 157, .ctrl_channels = {157}},
				{ .channel = 161, .ctrl_channels = {161}},
				{ .channel = 164, .ctrl_channels = {164}},
				{ .channel = 169, .ctrl_channels = {169}},
			}
		},
		{
			.id = 126,
			.bandwidth = 40,
			.channel_num = 2,
			.channel = {
				{ .channel = 149, .ctrl_channels = {149}},
				{ .channel = 157, .ctrl_channels = {157}},
			}
		},
		{
			.id = 127,
			.bandwidth = 40,
			.channel_num = 2,
			.channel = {
				{ .channel = 153, .ctrl_channels = {153}},
				{ .channel = 161, .ctrl_channels = {161}},
			}
		},
		{
			.id = 128,
			.bandwidth = 80,
			.channel_num = 6,
			.channel = {
				{ .channel = 42, .ctrl_channels = {36, 40, 44, 48}},
				{ .channel = 58, .ctrl_channels = {52, 56, 60, 64}},
				{ .channel = 106, .ctrl_channels = {100, 104, 108, 112}},
				{ .channel = 122, .ctrl_channels = {116, 120, 124, 128}},
				{ .channel = 138, .ctrl_channels = {132, 136, 140, 144}},
				{ .channel = 155, .ctrl_channels = {149, 153, 157, 161}},
			}
		},
		{
			.id = 129,
			.bandwidth = 160,
			.channel_num = 2,
			.channel = {
				{ .channel = 50, .ctrl_channels = {36, 40, 44, 48, 52, 56, 60, 64}},
				{ .channel = 114, .ctrl_channels = {100, 104, 108, 112, 116, 120, 124, 128}},
			}
		},
		{
			.id = 130,
			.bandwidth = 80,
			.channel_num = 6,
			.channel = {
				{ .channel = 42, .ctrl_channels = {36, 40, 44, 48}},
				{ .channel = 58, .ctrl_channels = {52, 56, 60, 64}},
				{ .channel = 106, .ctrl_channels = {100, 104, 108, 112}},
				{ .channel = 122, .ctrl_channels = {116, 120, 124, 128}},
				{ .channel = 138, .ctrl_channels = {132, 136, 140, 144}},
				{ .channel = 155, .ctrl_channels = {149, 153, 157, 161}},
			}
		},
	},
};

const struct wifi_radio_opclass *wifi_opclass_e4(struct wifi_radio_opclass *dst)
{
	if (dst)
		memcpy(dst, &e4, sizeof(e4));

	return &e4;
}

struct wifi_radio_opclass_entry *wifi_opclass_find_entry(struct wifi_radio_opclass *opclass, uint8_t id)
{
	struct wifi_radio_opclass_entry *entry;
	int i;

	if (WARN_ON(!opclass))
		return NULL;

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];
		if (entry->id != id)
			continue;

		return entry;
	}

	return NULL;
}

struct wifi_radio_opclass_entry *wifi_opclass_new_entry(struct wifi_radio_opclass *opclass)
{
	struct wifi_radio_opclass_entry *entry;

	if (opclass->entry_num >= ARRAY_SIZE(opclass->entry))
		return NULL;

	entry = &opclass->entry[opclass->entry_num];
	opclass->entry_num++;
	timestamp_update(&opclass->entry_time);

	return entry;
}

struct wifi_radio_opclass_channel *wifi_opclass_find_channel(struct wifi_radio_opclass_entry *entry, uint8_t chan)
{
	struct wifi_radio_opclass_channel *channel;
	int i;

	for (i = 0; i < entry->channel_num; i++) {
		channel = &entry->channel[i];
		if (channel->channel != chan)
			continue;

		return channel;
	}

	return NULL;
}

struct wifi_radio_opclass_channel *wifi_opclass_find_ctrl_channel(struct wifi_radio_opclass_entry *entry, uint8_t chan)
{
	struct wifi_radio_opclass_channel *channel;
	int i, j;

	for (i = 0; i < entry->channel_num; i++) {
		channel = &entry->channel[i];

		if (channel->channel == chan)
			return channel;

		for (j = 0; j < ARRAY_SIZE(channel->ctrl_channels); j++) {
			if (!channel->ctrl_channels[j])
				break;

			if (channel->ctrl_channels[j] == chan)
				return channel;
		}
	}

	return NULL;
}

struct wifi_radio_opclass_channel *wifi_opclass_new_channel(struct wifi_radio_opclass_entry *entry)
{
	struct wifi_radio_opclass_channel *channel;

	if (entry->channel_num >= ARRAY_SIZE(entry->channel))
		return NULL;

	channel = &entry->channel[entry->channel_num];
	entry->channel_num++;

	return channel;
}

int wifi_opclass_add_channel(struct wifi_radio_opclass_entry *entry, struct wifi_radio_opclass_channel *new)
{
	struct wifi_radio_opclass_channel *channel;

	channel = wifi_opclass_find_channel(entry, new->channel);
	if (!channel)
		channel = wifi_opclass_new_channel(entry);
	if (!channel)
		return -1;

	memcpy(channel, new, sizeof(*channel));
	return 0;
}

int wifi_opclass_add_entry(struct wifi_radio_opclass *opclass, struct wifi_radio_opclass_entry *new)
{
	struct wifi_radio_opclass_entry *entry;
	int ret = 0;
	int i;

	entry = wifi_opclass_find_entry(opclass, new->id);
	if (!entry)
		entry = wifi_opclass_new_entry(opclass);
	if (!entry)
		return -1;

	entry->id = new->id;
	entry->bandwidth = new->bandwidth;
	entry->max_txpower = new->max_txpower;

	for (i = 0; i < new->channel_num; i++)
		ret |= wifi_opclass_add_channel(entry, &new->channel[i]);

	return ret;
}

bool wifi_opclass_expired(struct wifi_radio_opclass *opclass, uint32_t seconds)
{
	if (timestamp_expired(&opclass->entry_time, seconds * 1000))
		return true;

	return false;
}

void wifi_opclass_reset(struct wifi_radio_opclass *opclass)
{
	opclass->entry_num = 0;
	memset(opclass->entry, 0, sizeof(opclass->entry));
}

void wifi_opclass_dump(struct wifi_radio_opclass *opclass)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	int i, j, k;

	dbg(">>> opclass num: %d\n", opclass->entry_num);
	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];
		dbg("opclass: %u\n", entry->id);
		for (j = 0; j < entry->channel_num; j++) {
			channel = &entry->channel[j];
			dbg("\tchan %u pref %u reason %u\n",
			    channel->channel,
			    (channel->preference & CHANNEL_PREF_MASK) >> 4,
			    channel->preference & CHANNEL_PREF_REASON);
			for (k =0; k < ARRAY_SIZE(channel->ctrl_channels); k++) {
				if (channel->ctrl_channels[k])
					dbg("\t\t ctrl: %u\n", channel->ctrl_channels[k]);
			}
		}
	}
	dbg("<<<\n");
}

uint8_t wifi_opclass_get_id(struct wifi_radio_opclass *opclass, uint8_t channel, int bandwidth)
{
	struct wifi_radio_opclass_entry *entry;
	int i, j;

	if (!opclass) {
		dbg("%s: opclass parameter missing\n", __func__);
		return 0;
	}

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];

		if (entry->bandwidth != bandwidth)
			continue;

		for (j = 0; j < entry->channel_num; j++) {
			if (entry->channel[j].channel == channel)
				return entry->id;
		}
	}

	return 0; /* Not found */
}

bool wifi_opclass_supported(struct wifi_radio_opclass *opclass, uint8_t id)
{
	struct wifi_radio_opclass_entry *entry;
	uint8_t pref;
	int i;

	entry = wifi_opclass_find_entry(opclass, id);
	if (!entry)
		return false;

	for (i = 0; i < entry->channel_num; i++) {
		pref = (entry->channel[i].preference & CHANNEL_PREF_MASK) >> 4;
		if (pref)
			return true;
	}

	return false;
}

void wifi_opclass_set_preferences(struct wifi_radio_opclass *opclass, uint8_t preference)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	int i, j;

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];

		for (j = 0; j < entry->channel_num; j++) {
			channel = &entry->channel[j];
			channel->preference = preference;
		}
	}
}

static struct wifi_radio_opclass_channel *
_wifi_opclass_get_higest_preference(struct wifi_radio_opclass *opclass,
				    int req_bandwidth,
				    uint8_t *opclass_id,
				    uint8_t *channel,
				    uint8_t *bandwidth)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *chan;
	struct wifi_radio_opclass_channel *best;
	uint8_t preference = 0;
	uint8_t pref;
	int i, j;

	*opclass_id = 0;
	*channel = 0;
	*bandwidth = 0;
	best = NULL;

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];

		if (req_bandwidth && entry->bandwidth != req_bandwidth)
			continue;

		for (j = 0; j < entry->channel_num; j++) {
			chan = &entry->channel[j];
			pref = (chan->preference & CHANNEL_PREF_MASK) >> 4;

			if (pref > preference) {
				preference = pref;
				*opclass_id = entry->id;
				*bandwidth = entry->bandwidth;
				*channel = chan->channel;
				best = chan;
			}
		}
	}

	if (preference == 0)
		return NULL;
	if (*opclass_id == 0)
		return NULL;
	if (*channel == 0)
		return NULL;
	if (*bandwidth == 0)
		return NULL;

	return best;
}

static uint8_t wifi_get_best_ctrl_channel(struct wifi_radio_opclass *opclass, const uint8_t *channels, int channels_num)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *chan;
	struct wifi_radio_opclass_channel *best = NULL;
	uint8_t preference = 0;
	uint8_t pref;
	int i, j, k;

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];

		if (entry->bandwidth != 20)
			continue;

		for (j = 0; j < entry->channel_num; j++) {
			chan = &entry->channel[j];
			pref = (chan->preference & CHANNEL_PREF_MASK) >> 4;

			for (k = 0; k < channels_num; k++) {
				if (channels[k] != chan->channel)
					continue;

				if (pref > preference) {
					preference = pref;
					best = chan;
				}
			}
		}
	}

	if (WARN_ON(!best))
		return channels[0];

	return best->channel;
}

int wifi_opclass_get_higest_preference(struct wifi_radio_opclass *opclass, int bandwidth,
				       uint8_t *opclass_id, uint8_t *channel)
{
	struct wifi_radio_opclass_channel *best;
	uint8_t bw;

	best = _wifi_opclass_get_higest_preference(opclass, bandwidth, opclass_id, channel, &bw);
	if (!best)
		return -1;

	switch (bw) {
	case 160:
	case 80:
		*channel = wifi_get_best_ctrl_channel(opclass, best->ctrl_channels, ARRAY_SIZE(best->ctrl_channels));
		break;
	case 20:
	case 40:
	default:
		break;
	}

	return 0;
}

bool wifi_opclass_id_supported(struct wifi_radio_opclass *opclass, uint8_t id)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	uint8_t pref;
	int i;

	entry = wifi_opclass_find_entry(opclass, id);
	if (!entry)
		return false;

	for (i = 0; i < entry->channel_num; i++) {
		channel = &entry->channel[i];
		pref = (channel->preference & CHANNEL_PREF_MASK) >> 4;

		if (pref)
			return true;
	}

	return false;
}

bool wifi_opclass_id_same_preference(struct wifi_radio_opclass *opclass, uint8_t id, uint8_t *preference)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	uint8_t pref;
	int i;

	entry = wifi_opclass_find_entry(opclass, id);
	if (!entry)
		return false;

	if (!entry->channel_num)
		return false;

	channel = &entry->channel[0];
	pref = channel->preference;

	for (i = 0; i < entry->channel_num; i++) {
		channel = &entry->channel[i];
		if (pref != channel->preference)
			return false;
	}

	*preference = pref;
	return true;
}

bool wifi_opclass_max_preference(uint8_t preference)
{
	uint8_t pref;

	pref = (preference & CHANNEL_PREF_MASK) >> 4;

	if (pref == 0xf)
		return true;

	return false;
}

uint8_t wifi_opclass_num_supported(struct wifi_radio_opclass *opclass)
{
	struct wifi_radio_opclass_entry *entry;
	int opclass_num = 0;
	int i;

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];

		if (wifi_opclass_id_supported(opclass, entry->id))
			opclass_num++;
	}

	return opclass_num;
}

static struct wifi_radio_opclass_channel *
wifi_opclass_find_opclass_channel(struct wifi_radio_opclass *opclass,
				  int ctrl_channel,
				  int bandwidth)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	int i, j, k;

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];

		/* First check bandwidth */
		if (entry->bandwidth != bandwidth)
			continue;

		/* Next check control channel */
		for (j = 0; j < entry->channel_num; j++) {
			channel = &entry->channel[j];

			for (k = 0; k < ARRAY_SIZE(channel->ctrl_channels); k++) {
				if (!channel->ctrl_channels[k])
					continue;
				if (channel->ctrl_channels[k] != ctrl_channel)
					continue;

				return channel;
			}
		}
	}

	return NULL;
}

bool wifi_opclass_cac_required(struct wifi_radio_opclass *opclass,
			       int ctrl_channel,
			       int bandwidth,
			       uint32_t *cac_time)
{
	struct wifi_radio_opclass_channel *channel;

	channel = wifi_opclass_find_opclass_channel(opclass, ctrl_channel, bandwidth);
	if (WARN_ON(!channel))
		return false;

	if (channel->cac_time)
		*cac_time = channel->cac_time;

	switch (channel->dfs) {
	case WIFI_RADIO_OPCLASS_CHANNEL_DFS_AVAILABLE:
	case WIFI_RADIO_OPCLASS_CHANNEL_DFS_NONE:
		return false;
	case WIFI_RADIO_OPCLASS_CHANNEL_DFS_CAC:
	case WIFI_RADIO_OPCLASS_CHANNEL_DFS_NOP:
	case WIFI_RADIO_OPCLASS_CHANNEL_DFS_USABLE:
		return true;
	default:
		break;
	}

	return false;
}

bool wifi_opclass_id_all_channels_supported(struct wifi_radio_opclass *opclass, uint8_t id)
{
	struct wifi_radio_opclass_entry *entry;
	uint8_t pref;
	int i;

	entry = wifi_opclass_find_entry(opclass, id);
	if (!entry)
		return false;

	for (i = 0; i < entry->channel_num; i++) {
		pref = (entry->channel[i].preference & CHANNEL_PREF_MASK) >> 4;

		if (!pref)
			return false;
	}

	return true;
}

int wifi_opclass_id_num_channels_supported(struct wifi_radio_opclass *opclass, uint8_t id)
{
	struct wifi_radio_opclass_entry *entry;
	int supported = 0;
	uint8_t pref;
	int i;

	entry = wifi_opclass_find_entry(opclass, id);
	if (!entry)
		return false;

	for (i = 0; i < entry->channel_num; i++) {
		pref = (entry->channel[i].preference & CHANNEL_PREF_MASK) >> 4;

		if (!pref)
			continue;
		supported++;
	}

	return supported;
}

bool wifi_opclass_id_channel_supported(struct wifi_radio_opclass *opclass, uint8_t id, uint8_t channel)
{
	struct wifi_radio_opclass_entry *entry;
        struct wifi_radio_opclass_channel *chan;
	uint8_t pref;

	entry = wifi_opclass_find_entry(opclass, id);
	if (!entry)
		return false;

	chan = wifi_opclass_find_ctrl_channel(entry, channel);
	if (!chan)
		return false;

	pref = (chan->preference & CHANNEL_PREF_MASK) >> 4;
	if (!pref)
		return false;

	return true;
}

bool wifi_opclass_id_channel_available(struct wifi_radio_opclass *opclass, uint8_t id, uint8_t channel)
{
	struct wifi_radio_opclass_entry *entry;
        struct wifi_radio_opclass_channel *chan;
	uint8_t pref;

	entry = wifi_opclass_find_entry(opclass, id);
	if (!entry)
		return false;

	chan = wifi_opclass_find_ctrl_channel(entry, channel);
	if (!chan)
		return false;

	pref = (chan->preference & CHANNEL_PREF_MASK) >> 4;
	if (!pref)
		return false;

	switch (chan->dfs) {
	case WIFI_RADIO_OPCLASS_CHANNEL_DFS_USABLE:
	case WIFI_RADIO_OPCLASS_CHANNEL_DFS_NOP:
	case WIFI_RADIO_OPCLASS_CHANNEL_DFS_CAC:
		return false;
	default:
		break;
	}

	return true;
}

int wifi_opclass_id_num_channels_unsupported(struct wifi_radio_opclass *opclass, uint8_t id)
{
	struct wifi_radio_opclass_entry *entry;
	int unsupported = 0;
	uint8_t pref;
	int i;

	entry = wifi_opclass_find_entry(opclass, id);
	if (!entry)
		return false;

	for (i = 0; i < entry->channel_num; i++) {
		pref = (entry->channel[i].preference & CHANNEL_PREF_MASK) >> 4;

		if (pref)
			continue;
		unsupported++;
	}

	return unsupported;
}

void wifi_opclass_id_set_preferences(struct wifi_radio_opclass *opclass, uint8_t id, uint8_t preference)
{
	struct wifi_radio_opclass_entry *entry;
	int i;

	entry = wifi_opclass_find_entry(opclass, id);
	if (WARN_ON(!entry))
		return;

	for (i = 0; i < entry->channel_num; i++)
		entry->channel[i].preference = preference;
}

bool wifi_opclass_is_channel_supported(struct wifi_radio_opclass_channel *chan)
{
	uint8_t pref;

	pref = (chan->preference & CHANNEL_PREF_MASK) >> 4;

	if (!pref)
		return false;

	return true;
}

int wifi_opclass_get_supported_ctrl_channels(struct wifi_radio_opclass *opclass,
			       uint8_t id,
			       uint8_t ctrl_channels[],
			       int *num_channels)
{
	struct wifi_radio_opclass_entry *entry;
	int i;

	if (WARN_ON(!opclass))
		return -1;

	entry = wifi_opclass_find_entry(opclass, id);
	if (WARN_ON(!entry))
		return -1;

	if (WARN_ON(entry->channel_num > *num_channels))
		return -1;

	*num_channels = 0;

	for (i = 0; i < entry->channel_num; i++) {
		if (!wifi_opclass_id_channel_supported(
				opclass,
				id,
				entry->channel[i].channel))
			continue; /* channel unsuported */
		ctrl_channels[*num_channels] = entry->channel[i].channel;
		(*num_channels)++;
	}

	return 0;
}

bool wifi_opclass_is_dfs_channel(struct wifi_radio_opclass_channel *chan)
{
	if (chan->dfs != WIFI_RADIO_OPCLASS_CHANNEL_DFS_NONE)
		return true;

	return false;
}

bool wifi_opclass_is_channel_dfs_available(struct wifi_radio_opclass_channel *chan)
{
	if (chan->dfs == WIFI_RADIO_OPCLASS_CHANNEL_DFS_AVAILABLE)
		return true;

	return false;
}

bool wifi_opclass_is_channel_dfs_nop(struct wifi_radio_opclass_channel *chan)
{
	if (chan->dfs == WIFI_RADIO_OPCLASS_CHANNEL_DFS_NOP)
		return true;

	return false;
}

bool wifi_opclass_is_channel_dfs_cac(struct wifi_radio_opclass_channel *chan)
{
	if (chan->dfs == WIFI_RADIO_OPCLASS_CHANNEL_DFS_CAC)
		return true;

	return false;
}

uint32_t wifi_opclass_channel_dfs_cac_time(struct wifi_radio_opclass_channel *chan)
{
	return chan->cac_time;
}

uint32_t wifi_opclass_channel_dfs_nop_time(struct wifi_radio_opclass_channel *chan)
{
	return chan->nop_time;
}

bool wifi_opclass_dfs_supported(struct wifi_radio_opclass *opclass)
{
	struct wifi_radio_opclass_entry *entry;
        struct wifi_radio_opclass_channel *chan;
	int i, j;

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];

		for (j = 0; j < entry->channel_num; j++) {
			chan = &entry->channel[j];

			if (!wifi_opclass_is_channel_supported(chan))
				continue;

			if (wifi_opclass_is_dfs_channel(chan))
				return true;
		}
	}

	return false;
}

bool wifi_opclass_id_dfs_supported(struct wifi_radio_opclass *opclass, uint8_t id)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *chan;
	int i;

	entry = wifi_opclass_find_entry(opclass, id);
	if (WARN_ON(!entry))
		return false;

	for (i = 0; i < entry->channel_num; i++) {
		chan = &entry->channel[i];

		if (!wifi_opclass_is_channel_supported(chan))
			continue;

		if (wifi_opclass_is_dfs_channel(chan))
			return true;
	}

	return false;
}

uint8_t wifi_opclass_dfs_num(struct wifi_radio_opclass *opclass)
{
	struct wifi_radio_opclass_entry *entry;
	uint8_t num = 0;
	int i;

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];

		if (wifi_opclass_id_dfs_supported(opclass, entry->id))
			num++;
	}

	return num;
}

uint8_t wifi_opclass_id_dfs_num(struct wifi_radio_opclass *opclass, uint8_t id)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *chan;
	uint8_t num = 0;
	int i;

	entry = wifi_opclass_find_entry(opclass, id);
	if (WARN_ON(!entry))
		return 0;

	for (i = 0; i < entry->channel_num; i++) {
		chan = &entry->channel[i];

		if (!wifi_opclass_is_channel_supported(chan))
			continue;

		if (wifi_opclass_is_dfs_channel(chan))
			num++;
	}

	return num;
}

uint8_t wifi_opclass_find_id_from_channel(struct wifi_radio_opclass *opclass,
					  int ctrl_channel,
					  int bandwidth)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	int i, j, k;

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];

		/* First check bandwidth */
		if (entry->bandwidth != bandwidth)
			continue;

		/* Next check control channel */
		for (j = 0; j < entry->channel_num; j++) {
			channel = &entry->channel[j];

			for (k = 0; k < ARRAY_SIZE(channel->ctrl_channels); k++) {
				if (!channel->ctrl_channels[k])
					continue;
				if (channel->ctrl_channels[k] != ctrl_channel)
					continue;

				return entry->id;
			}
		}
	}

	return 0;
}

void wifi_opclass_mark_unsupported(struct wifi_radio_opclass *out, struct wifi_radio_opclass *in)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	int i, j;

	for (i = 0; i < out->entry_num; i++) {
		entry = &out->entry[i];

		if (!wifi_opclass_id_supported(in, entry->id)) {
			wifi_opclass_id_set_preferences(out, entry->id, 0x00);
			continue;
		}

		for (j = 0; j < entry->channel_num; j++) {
			channel = &entry->channel[j];

			if (!wifi_opclass_id_channel_supported(in, entry->id, channel->channel))
				channel->preference = 0x0;
		}
	}
}

void wifi_opclass_mark_unavailable(struct wifi_radio_opclass *out, struct wifi_radio_opclass *in)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	int i, j;

	for (i = 0; i < out->entry_num; i++) {
		entry = &out->entry[i];

		for (j = 0; j < entry->channel_num; j++) {
			channel = &entry->channel[j];

			if (!wifi_opclass_id_channel_available(in, entry->id, channel->channel))
				channel->preference = 0x0;
		}
	}
}

int wifi_opclass_channels_operable(struct wifi_radio_opclass *opclass, int bandwidth)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel *channel;
	int count = 0;
	int i, j;

	for (i = 0; i < opclass->entry_num; i++) {
		entry = &opclass->entry[i];

		/* First check bandwidth */
		if (entry->bandwidth != bandwidth)
			continue;

		for (j = 0; j < entry->channel_num; j++) {
			channel = &entry->channel[j];
			uint8_t preference;

			preference = (channel->preference & 0xf0) >> 4;
			if (preference == 0)
				continue;

			count++;
		}
	}

	return count;
}
