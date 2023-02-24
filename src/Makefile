EXECS = mapagent dynbh/dynbhd
CFLAGS+=-I. -Iutils -D_GNU_SOURCE #DEBUG=1
CFLAGS+= -ggdb3 -Wall -Werror
CFLAGS += -I/usr/include/libnl3

OBJS = \
	utils/debug.o \
	utils/liblist.o \
	utils/utils.o \
	utils/1905_ubus.o \

AGENT_OBJS = \
	timer.o \
	wifi_ubus.o \
	wifi_opclass.o \
	wifi_scanresults.o \
	wifi.o \
	steer_rules.o \
	agent_ubus.o \
	agent_ubus_dbg.o \
	agent.o \
	agent_map.o \
	agent_tlv.o \
	agent_cmdu.o \
	backhaul.o \
	cmdu_validate.o \
	config.o \
	main.o \
	plugin.o \
	nl.o

LIBS = -lubus -lubox -ljson-c -lblobmsg_json -luci -leasy
LIBS += -I/usr/include/libnl3 -lnl-3 -lnl-route-3
LIBS += -rdynamic -ldl
LIBS += -lieee1905 -lmaputil -lm

plugin_subdirs ?= $(wildcard plugins/*)
plugin_sofile = $(wildcard $(d)/*.so)
plugin_files = $(foreach d, $(plugin_subdirs), $(plugin_sofile))


.PHONY: all check clean plugins FORCE

all: $(EXECS) plugins

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

mapagent: $(OBJS) $(AGENT_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

dynbh/dynbhd: dynbh/dynbh.o dynbh/dbh_nl.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

plugins:
	@echo "$(plugin_subdirs)"
	for i in $(plugin_subdirs); do [ -d $$i ] && $(MAKE) -C $$i all; done


check: FORCE
	@cppcheck --quiet --enable=all --inconclusive --std=c99 \
		--suppress=variableScope \
		--suppress=unusedVariable \
		--suppress=unreadVariable \
		--suppress=funcArgNamesDifferent \
		--suppress=unusedFunction \
		--suppress=wrongPrintfScanfArgNum \
		-I. -Iutils -Iagent -Icomm -Icontroller \
		. 2> cppcheck.out

test: CFLAGS += -fPIC
test: ${OBJS}
	${CC} ${LDFLAGS} -shared -o libmapagent.so ${OBJS} ${LIBS}

unit-test: coverage
	make -C ../test/cmocka unit-test MAPAGENT_LIB_DIR=$(PWD)

coverage: CFLAGS  += -g -O0 -fprofile-arcs -ftest-coverage -fPIC
coverage: LDFLAGS += --coverage
coverage: test mapagent
	$(foreach testprog, $(CODECOVERAGE_SRC), $(GCOV) $(testprog);)

clean:
	rm -f *.o *.so utils/*.o utils/*.so ipc/*.o $(EXECS)
	for i in $(plugin_subdirs); do [ -d $$i ] && $(MAKE) -C $$i clean; done

FORCE:
