#ifndef DYNBH_H
#define DYNBH_H

#define MAP_UPLINK_PATH 	"/var/run/multiap/multiap.backhaul"

struct ethport {
	bool connected;
	bool loop;
	bool active_uplink;
	char ifname[16];
	uint8_t backhaul_mac[6];
	uint8_t backhaul_device_id[6];
	uint8_t num_mid;
	uint16_t mid[32];
	atimer_t bridge_add;
	atimer_t send_query;
	int retries;
	struct list_head list;
	struct mapclient_private *ctx;
};

struct mapclient_private {
	char alidstr[16]; /* 6 octet macaddr without separators */
	char al_bridge[16];
	uint16_t cmdu_mask;
	struct ubus_context *ctx;
	uint32_t oid;
	uint32_t map_oid;
	void *subscriber;
	struct ubus_event_handler evh;
	int queued_searches;
	//struct list_head searches; /* currently active autoconfig search queries */
	//struct list_head loops;
	struct list_head ethportlist; /*  */
	atimer_t heartbeat;
	struct ubus_object obj;
};

void delif(struct ethport *ap);
void addif(struct ethport *ap);


struct ethport *ethport_by_ifname(struct mapclient_private *p,
		const char *ifname);
struct ethport *loop_by_ifname(struct mapclient_private *p, char *ifname);
struct ethport *ethport_by_mid(struct mapclient_private *p, uint16_t mid);


void free_ethport_search(struct ethport *ap);

#endif
