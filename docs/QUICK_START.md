# Multi-AP Environment

## Introduction

This will be a short version of how to setup a Multi-AP environment.

For more detailed information on UCI options and overgrasping READMEs, see
individual repositories at:

* [Map-agent](https://dev.iopsys.eu/iopsys/map-agent)
* [Map-controller](https://dev.iopsys.eu/iopsys/map-controller)
* [Ieee1905](https://dev.iopsys.eu/iopsys/ieee1905)

## Overview

The first chapter will show how to setup a singular device to be the 'master'
device in the network and prepare it for AP-Autoconfiguration and onboarding.

The second chapter will setup a repeater device which wil connect to it.

## Setting up Controller device

In this example, I will be setting up a device with wl0 (5GHz) and wl1 (2.4GHz)

### Prerequisites

* Map-controller, map-agent and ieee1905 package installed
* IEEE1905 must be loaded with MAP extension, preferably set via config.
```
config ieee1905 'ieee1905'
	option enabled '1'
	option extension '1'
	list extmodule 'map'
```
* Mapcontroller has to have `registrar` set for bands it should configure
* Mapagent expects there to be one 'main' bridge in the network, which is
also used as an ieee1905 interface, set by uci option `al_bridge`.

#### Notes
* Only mapagent is expected to modify interfaces specified in mapagent config

### Setting up Mapagent

* Align wireless and mapagent default configuration

In this default setup we have one fronthaul on each radio, named wl0 and wl1 respectively

UCI Wireless excerpt:
```
config wifi-iface 'default_wl0'
	option device 'wl0'
	option network 'lan'
	option ifname 'wl0'
	option mode 'ap'
	option ssid 'iopsysWrt-TEST5'
	option encryption 'psk2'
	option key '1234567890'
	option wps '1'
	option wps_pushbutton '1'
	option ieee80211k '1'
	option bss_transition '1'
	option multi_ap '2'

config wifi-iface 'default_wl1'
	option device 'wl1'
	option network 'lan'
	option ifname 'wl1'
	option mode 'ap'
	option ssid 'iopsysWrt-TEST2'
	option encryption 'psk2'
	option key '1234567890'
	option wps '1'
	option wps_pushbutton '1'
	option ieee80211k '1'
	option bss_transition '1'
	option multi_ap '2'
```

Align mapagent:
```
config agent 'agent'
	option enabled '1'
	option debug '0'
	option profile '2'
	option brcm_setup '1'
	option al_bridge 'br-lan'
	option netdev 'wl'
	option island_prevention '0'

config dynamic_backhaul
	option missing_bh_timer '60'

config controller_select
	option local '1'
	option id 'auto'
	option probe_int '20'
	option retry_int '15'
	option autostart '1'

config ap
	option ifname 'wl0'
	option band '5'
	option device 'wl0'

config ap
	option ifname 'wl1'
	option band '2'
	option device 'wl1'
```

#### Notes
* `multi_ap` should be set in wireless config on map-agent managed interfaces
	* If correspodning `ap` section is missing in map-agent config, it will
	be generated automatically based on `multi_ap` flag in wireless config
* `brcm_setup` must be used for broadcom platform
* This default config will not support backhaul connections
* `radio` sections will be generated automatically by map-agent if absent

### Setting up Mapcontroller

* Setup credentials
In this use case mapcontroller will be setup to provide one dedicated fronthaul
and one backhaul for every 2.4GHz radio and 5GHz radio on the configured device.

```
config controller 'controller'
	option enabled '1'
	option registrar '5 2'	    #bands on which wps registrar supported
	option debug '0'
	option primary_vid '1'
	option primary_pcp '0'

config ap
	option type 'fronthaul'
	option band '5'
	option ssid 'MAP-TEST-5GHz'
	option encryption 'psk2'
	option key '1234567890'
	option vid '1'

config ap
	option type 'fronthaul'
	option band '2'
	option ssid 'MAP-TEST-2.4GHz'
	option encryption 'psk2'
	option key '1234567890'
	option vid '1'

config ap
	option type 'backhaul'
	option band '5'
	option ssid 'MAP-TEST-BH-5GHz'
	option encryption 'psk2'
	option key '1234567890'
	option vid '1'

config ap
	option type 'backhaul'
	option band '2'
	option ssid 'MAP-TEST-BH-2.4GHz'
	option encryption 'psk2'
	option key '1234567890'
	option vid '1'
```

### AP-Autoconfiguration

With these configurations at boot, AP-Autoconfig should automatically trigger.

1. ieee1905d &
2. mapcontroller -d &
3. mapagent -d &

Or via procd:

1. /etc/init.d/ieee1905 start
2. /etc/init.d/mapagent start
3. /etc/init.d/mapcontroller start

Start order is not important, but by starting mapcontroller before map-agent we
will immediately trigger AP-Autoconfig Search and Response upon mapagent start.

Config files after AP-Autoconfig:
```
root@iopsys:~# cat /etc/config/mapagent

config agent 'agent'
	option enabled '1'
	option debug '0'
	option profile '2'
	option brcm_setup '1'
	option al_bridge 'br-lan'
	option netdev 'wl'
	option controller_mac 'ee:6c:9a:52:b0:27'

config dynamic_backhaul
	option missing_bh_timer '60'

config controller_select
	option local '1'
	option id 'auto'
	option probe_int '20'
	option retry_int '3'
	option autostart '1'

config radio
	option device 'wl0'
	option band '5'

config radio
	option device 'wl1'
	option band '2'

config ap
	option ifname 'wl0'
	option band '5'
	option device 'wl0'
	option ssid 'MAP-TEST-5GHz'
	option key '1234567890'
	option encryption 'psk2+aes'
	option type 'fronthaul'
	option vid '1'

config ap
	option ifname 'wl0.1'
	option band '5'
	option device 'wl0'
	option ssid 'MAP-TEST-BH-5GHz'
	option key '1234567890'
	option encryption 'psk2+aes'
	option type 'backhaul'
	option disallow_bsta '0'
	option vid '1'

config ap
	option ifname 'wl1'
	option band '2'
	option device 'wl1'
	option ssid 'MAP-TEST-2.4GHz'
	option key '1234567890'
	option encryption 'psk2+aes'
	option type 'fronthaul'
	option vid '1'

config ap
	option ifname 'wl1.1'
	option band '2'
	option device 'wl1'
	option ssid 'MAP-TEST-BH-2.4GHz'
	option key '1234567890'
	option encryption 'psk2+aes'
	option type 'backhaul'
	option disallow_bsta '0'
	option vid '1'

root@iopsys:~# cat /etc/config/wireless

config wifi-iface 'wl1_ap'
	option ifname 'wl1'
	option network 'lan'
	option ssid 'MAP-TEST-2.4GHz'
	option key '1234567890'
	option encryption 'psk2+aes'
	option mode 'ap'
	option device 'wl1'
	option multi_ap '2'
	option ieee80211k '1'
	option uuid 'cfa7df87-06a3-5daf-911f-ec6c9a52b027'
	option wps '1'
	option wps_pushbutton '1'
	option multi_ap_backhaul_ssid 'MAP-TEST-BH-2.4GHz'
	option multi_ap_backhaul_key '1234567890'

config wifi-iface 'wl1_1_ap'
	option ifname 'wl1.1'
	option network 'lan'
	option ssid 'MAP-TEST-BH-2.4GHz'
	option key '1234567890'
	option encryption 'psk2+aes'
	option mode 'ap'
	option device 'wl1'
	option multi_ap '1'
	option ieee80211k '1'
	option uuid 'cfa7df87-06a3-5daf-911f-ec6c9a52b027'
	option hidden '1'

config wifi-iface 'wl0_ap'
	option ifname 'wl0'
	option network 'lan'
	option ssid 'MAP-TEST-5GHz'
	option key '1234567890'
	option encryption 'psk2+aes'
	option mode 'ap'
	option device 'wl0'
	option multi_ap '2'
	option ieee80211k '1'
	option uuid 'cfa7df87-06a3-5daf-911f-ec6c9a52b027'
	option wps '1'
	option wps_pushbutton '1'
	option multi_ap_backhaul_ssid 'MAP-TEST-BH-5GHz'
	option multi_ap_backhaul_key '1234567890'

config wifi-iface 'wl0_1_ap'
	option ifname 'wl0.1'
	option network 'lan'
	option ssid 'MAP-TEST-BH-5GHz'
	option key '1234567890'
	option encryption 'psk2+aes'
	option mode 'ap'
	option device 'wl0'
	option multi_ap '1'
	option ieee80211k '1'
	option uuid 'cfa7df87-06a3-5daf-911f-ec6c9a52b027'
	option hidden '1'

config wifi-device 'wl0'
	option type 'mac80211'
	option channel '36'
	option hwmode '11a'
	option country 'DE'
	option htmode 'HE80'
	option apsta '0'
	option phy 'phy0'

config wifi-device 'wl1'
	option type 'mac80211'
	option channel '11'
	option hwmode '11g'
	option country 'DE'
	option htmode 'HE20'
	option apsta '0'
	option phy 'phy1'
```

#### Notes
* For extra debug:
	* provide `-dd` to ieee1905
	* provide `-vvvv` to mapagent and/or mapcontroller
* To re-trigger a *FRESH* AP-Autoconfig, mapagent can be restarted at any given
time. However, multiple triggers are available at runtime by mapagent, see
map-agent README for more info.

### AP-Autoconfig Renew

To trigger AP-Autoconfig Renew, credentials in /etc/config/mapcontroller must
differ from the config loaded in memory by mapcontroller *AND* mapcontroller
must receive a `SIGHUP`.

A `SIGUHP` can be triggered via preferred method, i.e.:
* `kill -1 \`pidof mapcontroller\``
* `ubus call uci commit '{"config":"mapcontroller"}'` which will trigger an
init.d hook.

Some example steps:
```
root@iopsys:~# uci set mapcontroller.@ap[3].ssid="MAP-NEW-BH-2.4GHz"
root@iopsys:~# uci commit mapcontroller
root@iopsys:~# ubus call uci commit '{"config":"mapcontroller"}'
root@iopsys:~# sleep 10
root@iopsys:~# wlctl -i wl1.1 status | grep SSID
SSID: "MAP-NEW-BH-2.4GHz"
BSSID: 0E:10:00:00:00:04	Capability: ESS ShortPre ShortSlot RRM
```

## Setting up Repeater Device

In this example, I will be adding another device to the mesh with wl0 (5GHz High
Power), wl1 (2.4GHz) and wl2 (5GHz Low Power).

### Prerequisites

* Map-agent and ieee1905 package installed
* IEEE1905 must be loaded with MAP extension, preferably set via config.
```
config ieee1905 'ieee1905'
	option enabled '1'
	option extension '1'
	list extmodule 'map'
```
* Mapagent expects there to be one 'main' bridge in the network, set by uci
option `al_bridge`.
* If wireless connection is to be used, a backhaul STA interface *MUST* be
present on a radio with the same band and channel range as the controller device.
* **** Any backhaul STA interface *MUST* be the first interface on the radio. ****
* For the backhaul STA radio `apsta` option should be set in the wireless
configuration for the radio.

```
config wifi-device 'wl2'
	option type 'mac80211'
	option channel '36'
	option hwmode '11a'
	option country 'DE'
	option htmode 'HE80'
	option apsta '1'
	option phy 'phy2'
```

#### Notes
* Only mapagent is expected to modify interfaces specified in mapagent config

### Setting up Mapagent

* Align wireless and mapagent default configuration

In this default setup we have one fronthaul on each radio, named wl0 and wl1
respectively and one backhaul STA on wl2.

UCI Wireless excerpt:
```
config wifi-iface 'default_wl0'
	option device 'wl0'
	option network 'lan'
	option ifname 'wl0'
	option mode 'ap'
	option ssid 'iopsysWrt-TEST5'
	option encryption 'psk2'
	option key '1234567890'
	option wps '1'
	option wps_pushbutton '1'
	option ieee80211k '1'
	option bss_transition '1'
	option multi_ap '2'

config wifi-iface 'default_wl1'
	option device 'wl1'
	option network 'lan'
	option ifname 'wl1'
	option mode 'ap'
	option ssid 'iopsysWrt-TEST2'
	option encryption 'psk2'
	option key '1234567890'
	option wps '1'
	option wps_pushbutton '1'
	option ieee80211k '1'
	option bss_transition '1'
	option multi_ap '2'

config wifi-iface 'default_sta_wl2'
	option device 'wl2'
	option mode 'sta'
	option ifname 'wl2'
	option multi_ap '1'
	option disabled '0'
```

Align mapagent:
```
config agent 'agent'
	option enabled '1'
	option debug '0'
	option profile '2'
	option brcm_setup '1'
	option al_bridge 'br-lan'
	option netdev 'wl'

config dynamic_backhaul
	option missing_bh_timer '60'

config controller_select
	option local '0'
	option id 'auto'
	option probe_int '20'
	option retry_int '15'
	option autostart '0'

config ap
	option ifname 'wl0'
	option band '5'
	option device 'wl0'

config ap
	option ifname 'wl1'
	option band '2'
	option device 'wl1'

config radio
	option device 'wl2'
	option band '5'
	option dedicated_backhaul '1'

config bsta
	option ifname 'wl2'
	option band '5'
	option device 'wl2'
```

#### Notes

* Mapagent will never overwrite bsta interfaces during AP-Autoconfig
* With `dedicated_backhaul` set on the radio, AP-Autoconfiguration will not
take place on this radio (optional).

### Onboarding

To trigger onboarding, WPS must be triggered with registrar role (default) on
controller node (device 1), on the autoconfigured fronthaul:

* `ubus call wifi.wps start '{"ifname":"wl0"}'`

On the repeater (device 2), WPS must be started on the bsta interface, with the
enrollee role, as well as providing the multiap IE, this is done by using the
`bsta role`.

* `ubus call wifi.wps start '{"ifname":"wl2", "role":"bsta"}'`

Once the credential exchange is complete you will see a ubus event published
on the repeater side:

```
{ "wps_credentials": {"ifname":"wl0","encryption":"psk2", "ssid":"MAP-TEST-BH-5GHz","key":"1234567890" }}
```

After some time you should see wl2 added to the main bridge and receive an IP.

### AP-Autoconfig

AP-Autoconfig will take place within, usually 30 seconds, after receiving the WPS
credentials, but this may depend on probe_int.

### AP-Autoconfig Renew

Works the same way as a singular device, as AP-Autoconfig Renew is relayed multicast.

### Dynamic Backhaul/Loop Detection

Only one backhaul should be active at any given time, on a device that is already
onboarded, plugging an ethernet cable will dynamically swap to that link. Similarily,
unplugging it will automatically enable the wireless backhaul again.

To observe which connection is the active backhaul either the map-agent UBUS API
may be used:

```
root@iopsys-44d43771bd50:~# ubus call map.agent backhaul_info
{
	"type": "wifi",
	"ifname": "wl1",
	"macaddr": "44:d4:37:71:bd:5e",
	"backhaul_device_id": "46:d4:37:71:b7:30",
	"backhaul_macddr": "fa:d4:37:71:b7:3f"
}
```

or the multiap.backhaul file directly:

```
root@iopsys-44d43771bd50:~# cat /var/run/multiap/multiap.backhaul
{ "type": "wifi", "ifname": "wl1", "macaddr": "44:d4:37:71:bd:5e", "backhaul_device_id": "46:d4:37:71:b7:30", "backhaul_macddr": "fa:d4:37:71:b7:3f" }
```

### Controller Discovery

For controller discovery, see map-agent [README](https://dev.iopsys.eu/iopsys/map-agent#controller-discovery).

### Traffic Separation

To enable Guest WiFi and Easymesh Traffic Segregation, the option 'primary_vid'
and 'enable_ts' must be set to a non-zero value in the map-controller config's
global section.

NOTE: Currently, only primary_vid = '1' is supported:

```
config controller 'controller'
	option enabled '1'
	option registrar '5 2'
	option primary_vid '1'
	option primary_pcp '0'
	option enable_ts '1'
```

To create a Guest WiFi network, a new 'ap' configuration section must be added
to the map-controller configuration, with a VID different from the primary.
Alternatively, an existing section may have its VID changed.

```
config ap
	option band '5'
	option ssid 'iopsysWrt-GUEST-5'
	option encryption 'sae-mixed'
	option key '1234567890'
	option vid '10'
	option type 'fronthaul'
```

After changing as above, issue a `SIGHUP` to map-controller in order to reload
the new configuration and propagate them to the map-agents in the Multi-AP
network.