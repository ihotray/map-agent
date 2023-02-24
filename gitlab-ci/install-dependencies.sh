#!/bin/bash

echo "install dependencies"

home=$(pwd)

function exec_cmd()
{
	echo "executing $@"
	$@ >/dev/null 2>&1
	local ret=$?

	if [ "${ret}" -ne 0 ]; then
		echo "Failed to execute $@ ret (${ret})"
		exit 1
	fi
}

exec_cmd apt update
exec_cmd apt install -y iproute2

# libwifi-*.so + libeasy.so
cd /opt/dev
rm -fr easy-soc-libs
mkdir -p /usr/include/easy
exec_cmd git clone -b devel https://dev.iopsys.eu/iopsys/easy-soc-libs.git
cd easy-soc-libs/libeasy
exec_cmd make CFLAGS+="-I/usr/include/libnl3"
exec_cmd cp -a libeasy*.so* /usr/lib
exec_cmd cp -a easy.h event.h utils.h if_utils.h debug.h hlist.h /usr/include/easy/
cd ../libwifi
exec_cmd make WIFI_TYPE=TEST
exec_cmd cp wifidefs.h wifiutils.h wifiops.h wifi.h /usr/include
exec_cmd cp -a libwifi*.so* /usr/lib

# wifimngr
cd /opt/dev
rm -fr wifimngr
exec_cmd git clone -b devel https://dev.iopsys.eu/iopsys/wifimngr.git
cd wifimngr
exec_cmd ./gitlab-ci/install-dependencies.sh
exec_cmd ./gitlab-ci/setup.sh
exec_cmd make
exec_cmd cp wifimngr /usr/sbin/

# ieee1905 + map.so
cd /opt/dev
export CFLAGS="${CFLAGS} -g -Wall -g -O0 -DHAS_WIFI -DDYNAMIC_CNTLR_SYNC_CONFIG"
rm -fr ieee1905
exec_cmd git clone --depth 1 -b devel https://dev.iopsys.eu/iopsys/ieee1905.git
cd ieee1905
exec_cmd ./gitlab-ci/install-dependencies.sh
exec_cmd ./gitlab-ci/setup.sh
cd src
exec_cmd make
mkdir -p /usr/include /usr/lib/ieee1905
exec_cmd cp -a cmdu.h /usr/include/
exec_cmd cp -a cmdu_ackq.h /usr/include/
exec_cmd cp -a 1905_tlvs.h /usr/include/
exec_cmd cp -a i1905_wsc.h /usr/include/
exec_cmd cp -a bufutil.h /usr/include/
exec_cmd cp -a timer_impl.h /usr/include/
exec_cmd cp -a libmidgen.so /usr/lib
exec_cmd cp -a libieee1905.so /usr/lib
exec_cmd cp -a ieee1905d /usr/sbin/
exec_cmd cp -a extensions/map/libmaputil.so /usr/lib
exec_cmd cp -a extensions/map/map.so /usr/lib
exec_cmd cp -a extensions/map/map_module.h /usr/include/
exec_cmd cp -a extensions/map/cntlrsync.h /usr/include/
exec_cmd cp -a extensions/map/easymesh.h /usr/include/

ldconfig

## mapagent
#cd /opt/dev
#rm -fr map-agent
#exec_cmd git clone -b devel https://dev.iopsys.eu/iopsys/map-agent.git
#cd map-agent/src
#exec_cmd make
#exec_cmd cp mapagent /usr/sbin/
#
## tap.sh library
#cd /opt/dev
#rm -fr tap
#exec_cmd git clone https://github.com/andrewgregory/tap.sh.git tap
#cd tap
#exec_cmd cp tap.sh /usr/bin/
#
## default mapagent config
#cat <<'EOF' > /etc/config/mapagent
#config agent 'agent'
#	option enabled '1'
#	option debug '0'
#	option profile '2'
#	option brcm_setup '1'
#	option al_bridge 'br-lan'
#	#option netdev 'wl'
#	option discovery_proto 'static'
#
#config controller_select
#	option local '1'
#	option id 'auto'
#	option probe_int '20'
#	option retry_int '3'
#	option autostart '0'
#
#config wifi-radio
#	option device 'test5'
#	option band '5'
#	option steer_policy '2'
#	option util_threshold '200'
#	option rcpi_threshold '30'
#	option report_rcpi_threshold '0'
#	option rcpi_hysteresis_margin '0'
#	option report_util_threshold '0'
#	option include_sta_stats '0'
#	option include_sta_metric '0'
#
#config wifi-radio
#	option device 'test2'
#	option band '2'
#	option steer_policy '2'
#	option util_threshold '200'
#	option rcpi_threshold '30'
#	option report_rcpi_threshold '0'
#	option rcpi_hysteresis_margin '0'
#	option report_util_threshold '0'
#	option include_sta_stats '0'
#	option include_sta_metric '0'
#EOF
