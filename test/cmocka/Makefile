#CC = gcc
#AGENT_DIR ?= $(shell dirname $(PWD))
#AGENT = -l:agent_test.so -L$(AGENT_DIR)
#CMOCKA_LIB = -lcmocka
#LIBS = $(AGENT) $(CMOCKA_LIB) -luci -lubus -lubox -ljson-c -lblobmsg_json
#CFLAGS = -g -ggdb -Wall -I../.. -I../../src
#LDFLAGS = $(LIBS) -Wl,-rpath=$(AGENT_DIR) -I$(AGENT_DIR)
#UNIT_TESTS = unit_test_agent
#
#VALGRIND = valgrind --leak-check=full --show-reachable=no \
#           --show-leak-kinds=all --errors-for-leak-kinds=all \
#           --error-exitcode=1 --track-origins=yes
#
#unit_test_agent:  unit_test_agent.o
#	$(CC) -o $@ $^ $(LDFLAGS)
#
#unit-test: $(UNIT_TESTS)
#	$(foreach testprog, $(UNIT_TESTS), sudo $(VALGRIND) ./$(testprog);)
#
#.PHONY: clean
#clean:
#	rm *.o unit_test_agent -fv

CC		= gcc
MAPAGENT_LIB_DIR	?= $(shell dirname $(PWD))
MAPAGENT_LIB	= -lmapagent -L$(MAPAGENT_LIB_DIR)
CMOCKA_LIB	= -l cmocka
LIBS		= $(MAPAGENT_LIB) $(CMOCKA_LIB) -lwifi-7 -luci -lubus -lubox -ljson-c -lblobmsg_json -lnl-genl-3 -lnl-3 -ljson-validator -ljson-schema-validator -ljson-editor
CFLAGS		= -g -Wall -I../..
LDFLAGS		= $(LIBS) -Wl,-rpath=$(MAPAGENT_LIB_DIR) -I$(MAPAGENT_LIB_DIR)
UNIT_TESTS	= unit_test_agent
FUNCTIONAL_TESTS	= functional_test_agent
#UTILS 		= test_utils.o

VALGRIND	= valgrind --leak-check=full --show-reachable=no \
	--show-leak-kinds=all --errors-for-leak-kinds=all \
	--error-exitcode=1 --track-origins=yes

unit_test_agent: $(UTILS) unit_test_agent.o
	$(CC) -o $@ $^ $(LDFLAGS)

functional_test_agent: $(UTILS) functional_test_agent.o
	$(CC) -o $@ $^ $(LDFLAGS)

unit-test: $(UNIT_TESTS)
	$(foreach testprog, $(UNIT_TESTS), sudo $(VALGRIND) ./$(testprog);)

functional-test: $(FUNCTIONAL_TESTS)
	$(foreach testprog, $(FUNCTIONAL_TESTS), sudo $(VALGRIND) ./$(testprog);)

.PHONY: clean
clean:
	rm $(UNIT_TESTS) $(FUNCTIONAL_TESTS) *.o -fv
