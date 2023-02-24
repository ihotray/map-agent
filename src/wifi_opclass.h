#ifndef _WIFI_RADIO_OPCLASS_H_
#define _WIFI_RADIO_OPCLASS_H_

enum wifi_radio_opclass_dfs {
	WIFI_RADIO_OPCLASS_CHANNEL_DFS_NONE,
	WIFI_RADIO_OPCLASS_CHANNEL_DFS_USABLE,
	WIFI_RADIO_OPCLASS_CHANNEL_DFS_AVAILABLE,
	WIFI_RADIO_OPCLASS_CHANNEL_DFS_NOP,
	WIFI_RADIO_OPCLASS_CHANNEL_DFS_CAC,
};

struct wifi_radio_opclass_channel {
	uint8_t channel;
	/* preference and reason */
	uint8_t preference;

	enum wifi_radio_opclass_dfs dfs;
	uint32_t cac_time;
	uint32_t nop_time;

	uint8_t ctrl_channels[32];
};

struct wifi_radio_opclass_entry {
	uint8_t id;
	int bandwidth;
	int max_txpower;

	int channel_num;
	struct wifi_radio_opclass_channel channel[64];
};

struct wifi_radio_opclass {
	struct timespec entry_time;

	int entry_num;
	struct wifi_radio_opclass_entry entry[64];
};

const struct wifi_radio_opclass *wifi_opclass_e4(struct wifi_radio_opclass *dst);

struct wifi_radio_opclass_entry *wifi_opclass_find_entry(struct wifi_radio_opclass *opclass, uint8_t id);
struct wifi_radio_opclass_entry *wifi_opclass_new_entry(struct wifi_radio_opclass *opclass);

struct wifi_radio_opclass_channel *wifi_opclass_find_channel(struct wifi_radio_opclass_entry *entry, uint8_t chan);
struct wifi_radio_opclass_channel *wifi_opclass_new_channel(struct wifi_radio_opclass_entry *entry);

int wifi_opclass_add_channel(struct wifi_radio_opclass_entry *entry, struct wifi_radio_opclass_channel *new);
int wifi_opclass_add_entry(struct wifi_radio_opclass *opclass, struct wifi_radio_opclass_entry *new);

bool wifi_opclass_expired(struct wifi_radio_opclass *opclass, uint32_t seconds);
void wifi_opclass_reset(struct wifi_radio_opclass *opclass);
void wifi_opclass_dump(struct wifi_radio_opclass *opclass);

uint8_t wifi_opclass_get_id(struct wifi_radio_opclass *opclass, uint8_t channel, int bandwidth);
bool wifi_opclass_supported(struct wifi_radio_opclass *opclass, uint8_t id);
void wifi_opclass_set_preferences(struct wifi_radio_opclass *opclass, uint8_t preference);
int wifi_opclass_get_higest_preference(struct wifi_radio_opclass *opclass, int bandwith,
				       uint8_t *opclass_id, uint8_t *channel);
bool wifi_opclass_id_supported(struct wifi_radio_opclass *opclass, uint8_t id);
uint8_t wifi_opclass_num_supported(struct wifi_radio_opclass *opclass);
bool wifi_opclass_cac_required(struct wifi_radio_opclass *opclass,
			       int ctrl_channel,
			       int bandwidth,
			       uint32_t *cac_time);
bool wifi_opclass_id_all_channels_supported(struct wifi_radio_opclass *opclass, uint8_t id);
int wifi_opclass_id_num_channels_supported(struct wifi_radio_opclass *opclass, uint8_t id);
int wifi_opclass_id_num_channels_unsupported(struct wifi_radio_opclass *opclass, uint8_t id);
bool wifi_opclass_id_channel_supported(struct wifi_radio_opclass *opclass, uint8_t id, uint8_t channel);
void wifi_opclass_id_set_preferences(struct wifi_radio_opclass *opclass, uint8_t id, uint8_t preference);
bool wifi_opclass_is_channel_supported(struct wifi_radio_opclass_channel *chan);
int wifi_opclass_get_supported_ctrl_channels(struct wifi_radio_opclass *opclass,
			       uint8_t id,
			       uint8_t ctrl_channels[],
			       int *num_channels);
bool wifi_opclass_is_dfs_channel(struct wifi_radio_opclass_channel *chan);
bool wifi_opclass_dfs_supported(struct wifi_radio_opclass *opclass);
bool wifi_opclass_id_dfs_supported(struct wifi_radio_opclass *opclass, uint8_t id);
uint8_t wifi_opclass_dfs_num(struct wifi_radio_opclass *opclass);
uint8_t wifi_opclass_id_dfs_num(struct wifi_radio_opclass *opclass, uint8_t id);
uint8_t wifi_opclass_find_id_from_channel(struct wifi_radio_opclass *opclass,
					  int ctrl_channel,
					  int bandwidth);
bool wifi_opclass_id_same_preference(struct wifi_radio_opclass *opclass, uint8_t id, uint8_t *pref);
bool wifi_opclass_max_preference(uint8_t preference);
bool wifi_opclass_is_channel_dfs_available(struct wifi_radio_opclass_channel *chan);
bool wifi_opclass_is_channel_dfs_nop(struct wifi_radio_opclass_channel *chan);
bool wifi_opclass_is_channel_dfs_cac(struct wifi_radio_opclass_channel *chan);
uint32_t wifi_opclass_channel_dfs_cac_time(struct wifi_radio_opclass_channel *chan);
uint32_t wifi_opclass_channel_dfs_nop_time(struct wifi_radio_opclass_channel *chan);
void wifi_opclass_mark_unsupported(struct wifi_radio_opclass *out, struct wifi_radio_opclass *in);
void wifi_opclass_mark_unavailable(struct wifi_radio_opclass *out, struct wifi_radio_opclass *in);
int wifi_opclass_channels_operable(struct wifi_radio_opclass *opclass, int bandwidth);
#endif /* _WIFI_RADIO_OPCLASS_H_ */
