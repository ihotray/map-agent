
#include <stdio.h>
#include <stdlib.h>

//#include "map_module.h"

int agent_cmdu_handler(uint16_t cmdu_type, void *msg, size_t msglen)
{
	return 0;
}

int cntlr_cmdu_handler(uint16_t cmdu_type, void *msg, size_t msglen)
{
	return 0;
}

int agentcntlr_cmdu_handler(uint16_t cmdu_type, void *msg, size_t msglen)
{
	return 0;
}


static struct map_module agent = {
	.role = MAP_ROLE_AGENT,
	.profile = MAP_PROFILE_2,
	.map_cmdu_rx = agent_cmdu_handler,
};

static struct map_module cntlr = {
	.role = MAP_ROLE_CONTROLLER,
	.profile = MAP_PROFILE_2,
	.map_cmdu_rx = cntlr_cmdu_handler,
};

static struct map_module agentcntlr = {
	.role = MAP_ROLE_AGENT | MAP_ROLE_CONTROLLER,
	.profile = MAP_PROFILE_2,
	.map_cmdu_rx = agentcntlr_cmdu_handler,
};


int main(int argc, char **argv)
{
	int ret;

	/* register and start */
	ret = register_multiap_module(&agent);
	if (ret) {
		fprintf(stderr, "Failed to register map_module 'agent'\n");
		return -1;
	}

	fprintf(stderr, "Sucessfully registered 'agent'\n");

	ret = start_multiap_module(&agent);
	if (ret) {
		fprintf(stderr, "Failed to start map_module 'agent'\n");
		return -1;
	}
	fprintf(stderr, "Sucessfully started 'agent'\n");


	ret = register_multiap_module(&cntlr);
	if (ret) {
		fprintf(stderr, "Failed to register map_module 'cntlr'\n");
		return -1;
	}

	fprintf(stderr, "Sucessfully registered 'cntlr'\n");


	ret = start_multiap_module(&cntlr);
	if (ret) {
		fprintf(stderr, "Failed to start map_module 'cntlr'\n");
		return -1;
	}
	fprintf(stderr, "Sucessfully started 'cntlr'\n");

	fprintf(stderr, "\n");

	/* stop and unregister */
	ret = stop_multiap_module(&agent);
	if (ret) {
		fprintf(stderr, "Failed to stop map_module 'agent'\n");
		return -1;
	}
	fprintf(stderr, "Sucessfully paused 'agent'\n");

	ret = unregister_multiap_module(&agent);
	if (ret) {
		fprintf(stderr, "Failed to unregister map_module 'agent'\n");
		return -1;
	}

	fprintf(stderr, "Sucessfully unregistered 'agent'\n");

	ret = stop_multiap_module(&cntlr);
	if (ret) {
		fprintf(stderr, "Failed to stop map_module 'cntlr'\n");
		return -1;
	}
	fprintf(stderr, "Sucessfully paused 'cntlr'\n");

	ret = unregister_multiap_module(&cntlr);
	if (ret) {
		fprintf(stderr, "Failed to unregister map_module 'cntlr'\n");
		return -1;
	}

	fprintf(stderr, "Sucessfully unregistered 'cntlr'\n");

	fprintf(stderr, "\n");

	/* agent+cntlr combined module */
	ret = register_multiap_module(&agentcntlr);
	if (ret) {
		fprintf(stderr, "Failed to register map_module 'agent+cntlr'\n");
		return -1;
	}

	fprintf(stderr, "Sucessfully registered 'agent+cntlr'\n");

	ret = start_multiap_module(&agentcntlr);
	if (ret) {
		fprintf(stderr, "Failed to start map_module 'agent+cntlr'\n");
		return -1;
	}
	fprintf(stderr, "Sucessfully started 'agent+cntlr'\n");

	ret = stop_multiap_module(&agentcntlr);
	if (ret) {
		fprintf(stderr, "Failed to stop map_module 'agent+cntlr'\n");
		return -1;
	}
	fprintf(stderr, "Sucessfully paused 'agent+cntlr'\n");

	ret = unregister_multiap_module(&agentcntlr);
	if (ret) {
		fprintf(stderr, "Failed to unregister map_module 'agent+cntlr'\n");
		return -1;
	}

	fprintf(stderr, "Sucessfully unregistered 'agent+cntlr'\n");

	return ret;
}
