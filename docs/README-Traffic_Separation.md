# Traffic Separation

## Overview

This README documents important aspects regarding the Traffic Separation feature
in a Multi-AP system. When Traffic Separation is in effect, traffic from
different VLANs are isolated from each other. Multiple SSIDs may belong to the
same VLAN. The functionality for this is specified in Multi-AP Spec 2.0 chapter
19, which this implementation is based on. To achieve separation at layer 2
network, bridge VLAN filtering feature is used and must be compiled into the
kernel.

## Configuration

The configuration governing the Traffic Separation (per AP VLAN tag numbering)
comes from the map-controller.

### Enabling Traffic Separation

To enable traffic separation there are two requirements for map-controller to
pass the necessary Traffic Separation and Default 802.1Q Settings TLVs:
* Traffic separation must be enabled via configuration (option enable_ts)
* Primary VID must be set to a non-zero value (Today only '1' is supported)

```
config controller 'controller'
	option enabled '1'
	option registrar '5 2'
	option primary_vid '1'
	option primary_pcp '0'
        option enable_ts '1'
```

### Per AP VLAN Tagging

Each *ap* section specifies which VLAN ID it belongs to by the *vid* option:

```
config ap
        option band '5'
        option ssid 'MAP-EC6C9A79FC4E-5GHz'
        option encryption 'sae-mixed'
        option vid '1'          # Primary VID
        option type 'fronthaul'
        option key 'FPaY-7teN-hTHa-pgdT'

config ap
        option band '2'
        option ssid 'MAP-EC6C9A79FC4E-2.4GHz'
        option encryption 'sae-mixed'
        option vid '1'          # Primary VID
        option type 'fronthaul'
        option key 'FPaY-7teN-hTHa-pgdT'

config ap
        option band '5'
        option ssid 'My-Guest-Network'
        option encryption 'sae-mixed'
        option vid '50'         # Example guest VID 50
        option type 'fronthaul'
        option key 'FPaY-7teN-hTHa-pgdT'

config ap
        option band '2'
        option ssid 'Another-Guest-Network'
        option encryption 'sae-mixed'
        option vid '20'         # Example guest VID 20
        option type 'fronthaul'
        option key 'FPaY-7teN-hTHa-pgdT'
```

These VIDs will be passed in the Policy Config Request CMDU and during
AP-Autoconfiguration along with AP-Autoconfiguration WSC (M2) CMDU and
configured by map-agent.

## Implementation

In order for map-agent to apply VLAN tagging on the *Primary Network*, it must
receive a **Default 802.1Q Settings TLV** containing the Primary VLAN ID. This
can be received in any of three ways:
- in a **AP-Autoconfiguration WSC** message from the map-controller
- in a **Multi-AP Policy Config Request** message from the map-controller
- as a Multi-AP IE subelement in **(Re-)Association Response** frames

To apply tagging on *Secondary Networks*, it must receive a
**Traffic Separation Policy TLV** containing at least one SSID to VLAN ID
mapping. This can be received in either of the following CMDUs from
map-controller:
- a **AP-Autoconfiguration WSC** message
- a **Multi-AP Policy Config Request** message

When Map Agent receive proper Traffic Separation policy config it will
reconfigure */etc/config/network* to enable VLAN filtering on *al_bridge*
(default br-lan) and configure VLAN for Ethernet ports that were already bridged
to *al_bridge*.

Individual VLAN IDs for ports are configured using *bridge-vlan* network config
entries. A bridge-vlan section allows a configuration of how a VLAN ID should
be appended or untagged at the bridge and each specified port.

| Option | type    | Description |
|--------|---------|-------------|
| name   | string  | Unique section identifier |
| device | string  | Map to a device section with the same name |
| vlan   | integer | VLAN ID for which this section dictates tagging rules |
| flags  | string  | List of egress and ingress rules for the bridge.<br /> 'untagged' = Packets egress untagged for specified VID<br /> 'pvid' = Add VID tag for ingressing untagged frames |
| local  | boolean | Whether any tagging rules should be applied at bridge level for this VLAN ID |
| ports  | list  | List of ports and port desired VLAN ID handling at port level<br /> '*port*:t' = Keep VID tag intact for ingressing and egressing traffic<br /> '*port*:*' = Add VID tag for ingress and remove tag on egress<br /> '*port*' = Add VID tag for ingress and remove tag on egress |

Map-agent will create these sections for each passed VLAN ID within the Traffic
Separation TLV. At the Ethernet port level map-agent will add egress and ingress
tagging rules for the primary VLAN ID and keep tags as-is for secondary VLAN
IDs. At the bridge level all VLAN IDs will be handled and egress untagged,
whereas ingressing packets will receive a Primary VLAN ID tag.

```
config bridge-vlan 'vlan1'
	option name 'vlan1'
	option device 'br-lan'
	option vlan '1'
	option flags 'untagged pvid'
	option local '1'
	list ports 'eth1:*'
	list ports 'eth2:*'
	list ports 'eth3:*'
	list ports 'eth4:*'

config bridge-vlan 'vlan50'
	option name 'vlan50'
	option device 'br-lan'
	option vlan '50'
	option flags 'untagged'
	option local '1'
	list ports 'eth1:t'
	list ports 'eth2:t'
	list ports 'eth3:t'
	list ports 'eth4:t'

config bridge-vlan 'vlan20'
	option name 'vlan20'
	option device 'br-lan'
	option vlan '20'
	option flags 'untagged'
	option local '1'
	list ports 'eth1:t'
	list ports 'eth2:t'
	list ports 'eth3:t'
	list ports 'eth4:t'
```

Bridge VLAN filtering configuration can be seen by *bridge vlan* command and
an example output can look like:

```
root@iopsys-021000000001:~# bridge vlan
port              vlan-id  
eth1              1 PVID Egress Untagged
                  20
                  50
eth2              1 PVID Egress Untagged
                  20
                  50
eth3              1 PVID Egress Untagged
                  20
                  50
eth4              1 PVID Egress Untagged
                  20
                  50
wl0               1 PVID Egress Untagged
wl1               1 PVID Egress Untagged
br-lan            1 PVID Egress Untagged
                  20 Egress Untagged
                  50 Egress Untagged
wl1.1             1 PVID Egress Untagged
wl0.1             1 PVID Egress Untagged
wl0.2             1 Egress Untagged
                  50 PVID Egress Untagged
wl1.2             1 Egress Untagged
                  20 PVID Egress Untagged
```

PVID Egress Untagged entries will add/remove VLAN ID tag on for
incoming/outgoing frames on that port. VLAN IDs listed without PVID Egress
Untagged mean that particular VLAN tag is accepted on the port, non listed VLAN
tags are dropped. In example above *eth2* will:
* Accept 802.1q frames with VIDs 20 and 50
* Change untagged incoming ethernet frames to 802.1q with vid 1
* Remove tags for outgoing frames

For wireless port *wl0.2*:
* Transfer untagged traffic to vid 50.


## Wi-Fi Guest-to-Guest Isolation

With Wi-Fi guest-to-guest isolation enabled, clients within the same guest VLAN
ID may not send or receive traffic from one another.

Guest-to-guest isolation will set the wireless configuration option `isolate` to
1 to prevent intra-BSS traffic between STAs. Additionally, `ebtables` filter
rules are added to prevent communication between WiFi guest STAs connected to
different devices.

This feature does not affect Wi-Fi clients on the primary VLAN.

### Configuration

This can be enabled with the map-agent UCI configuration's (global section)
option name 'guest_isolation'.

```
config agent 'agent'
        option enabled '1'
        option brcm_setup '1'
        option al_bridge 'br-lan'
        option netdev 'wl'
        option island_prevention '0'
        option eth_onboards_wifi_bhs '1'
        option guest_isolation '1'
```

### Implementation

When traffic separation is enabled as provided by **Default 802.1Q Settings TLV**
and **Traffic Separation Policy TLV** and the option `guest_isolation` is set
map-agent will create ebtables rules as follows:

```
root@iopsys-44d43771b730:~# ebtables -L
Bridge table: filter

Bridge chain: INPUT, entries: 0, policy: ACCEPT

Bridge chain: FORWARD, entries: 4, policy: ACCEPT
-p 802_1Q -i wl0.2 -o wds+ --vlan-id ! 1 -j DROP
-p 802_1Q -i wds+ -o wl0.2 --vlan-id ! 1 -j DROP
-p 802_1Q -i wl1.2 -o wds+ --vlan-id ! 1 -j DROP
-p 802_1Q -i wds+ -o wl1.2 --vlan-id ! 1 -j DROP

Bridge chain: OUTPUT, entries: 0, policy: ACCEPT
```

These rules are applied for any fronthaul interface with a guest VLAN ID. The
ebtable rules will drop any traffic with a VLAN ID tag that differs from the
primary that is egressing over a 4address mode link. And vice versa, any traffic
with a VLAN ID tag that differs from the primary ingressing over a 4address mode
link and egressing over a fronthaul interface with a guest VLAN ID will be
dropped. This prevents any traffic from flowing over the guest network between
clients connected at different nodes.

To prevent intra-BSS traffic, hostapd `isolate` option is set over the
guest fronthaul interfaces to prevent client to client traffic.

```
config wifi-iface 'wl1_2_ap'
	option ifname 'wl1.2'
	option ieee80211k '1'
	option bss_transition '1'
	option wps '1'
	option wps_pushbutton '1'
	option uuid 'c96f5e29-9c4a-4abf-942d-44D43771B730'
	option network 'lan'
	option ssid 'iopsys-vid20'
	option key '1234567890'
	option encryption 'sae-mixed+aes'
	option mode 'ap'
	option device 'wl1'
	option multi_ap '2'
	option ieee80211w '1'
	option disabled '0'
	option mbo '1'
	option wps_device_type '6-0050f204-1'
	option multicast_to_unicast '1'
	option isolate '1'                                     # isolate traffic
	option multi_ap_backhaul_ssid 'MAP-44D43771B730-BH-2.4GHz'
	option multi_ap_backhaul_key '626fb1949a0f05a0643c067f91c66582fe7f20a2531cdd933b2627b3b9c610b'

```
