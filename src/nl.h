#ifndef MAPAGENT_NL_H
#define MAPAGENT_NL_H

#define TS_IFACE_MAX_NUM (2 * WIFI_IFACE_MAX_NUM)
#define MAX_VIDS (WIFI_IFACE_MAX_NUM - 4)

struct agent;

struct ts_iface {
	char name[IFNAMSIZ];
	uint16_t vid;
	int ifi_index;
	struct bridge_vlan_info cur_vinfo[MAX_VIDS];
	bool is_bsta;
};

/* netlink vlan handling context */
struct ts_context {
	struct nl_sock *nl_main_sk;
	struct uloop_fd nl_sk;

	uint16_t primary_vid;
	bool check_tags;

	struct ts_iface iface_array[TS_IFACE_MAX_NUM];

	unsigned int num_vids;
	uint16_t all_vids[MAX_VIDS];
};

struct nl_sock *nl_init_main_sock(struct agent *a);
void nl_free_main_sock(struct nl_sock *sk);
void nl_check_vlan(struct agent *a, bool reconf);
void nl_event_uloop_cb(struct uloop_fd *fd, unsigned int events);
int nl_loop(void);

#endif /* MAPAGENT_NL_H */
