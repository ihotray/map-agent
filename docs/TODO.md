## TODO

This section describes remaining issues found in 6.3RC2.
These tests are based on a sh3 <-> disc setup with vlan_segregation enabled.

### First time bringup

When enabling vlan_segregation for the first time, bridges are not filled out properly.
- br-map remains empty (all devices are created but end up outside of bridge) - likely netifd recreates bridge and clears out unmanaged devices (such as veth and tag devices).
  - can be fixed manually by running **wifi**
- *disc* is brought up with tagging active, even when not connected to *sh3* - tagging should only be enabled once trigger is received from *controller* (see TS readme)

### Sink setup incomplete

- sink devices missing from lan bridge - only the sink side of the veth link is in place - similar as above
  - can be added manually with __brctl addif br-lan sink1_vlanX__

### Auto setup on repeaters

- the autostart implementation does not take into account which device it is run on
  - sets up sink devices on DISC as well - not needed
  - sets up DHCP config for sinks on DISC - not desired
  - sets up WAN access for sinks on DISC - not desired

### Incorrect VID passed to tagging rules

It would seem there is a bug with the VID input. A VID of 0 is invalid and is never supposed to be used.

```
[ 9287.132124] [ERROR vlan] registerVlanDeviceByName,435: Failed to REGISTER VLAN Device lei_vlan1
[ 9287.142087] [ERROR vlan] vlanIoctl ,684: Failed to create VLAN device (lei, lei_vlan1)
[ 9287.168427] [ERROR vlan] tagRulePreProcessor,1322: Invalid filter: VLAN Tag #0
[ 9287.168432] [ERROR vlan] vlanIoctl ,815: Failed to Insert Tag Rule in lei (tags=1, dir=0)
[ 9287.187879] [ERROR vlan] tagRulePreProcessor,1322: Invalid filter: VLAN Tag #0
[ 9287.187884] [ERROR vlan] vlanIoctl ,815: Failed to Insert Tag Rule in lei (tags=1, dir=1)
```
Seems rx rule for Secondary network on LEI is not set up as a result of this (set with eth_populate() in the script).
```
root@iopsys:~# echo 7 > /proc/sys/kernel/printk
root@iopsys:~# vlanctl --if lei --rx --tags 1 --show-table
root@iopsys:~# dmesg | tail -n5
[  174.363349] 
[  174.363349] VLAN Rule Table : lei, Rx, nbrOfTags 1, default DROP  
[  174.363351] No entries found
[  174.363352] 
[  174.363352] --------------------------------------------------------------------------------
```
Sometimes rule comus up with incorrect VID (10 => 16)
```
root@iopsys:~# vlanctl --if lei --rx --tags 1 --show-table
root@iopsys:~# dmesg | tail -n19
[  809.214858] 
[  809.214858] VLAN Rule Table : lei, Rx, nbrOfTags 1, default DROP  
[  809.214862] 
[  809.214862] --------------------------------------------------------------------------------
[  809.214864] ===> lei (RG) : RX, 1 tag(s)
[  809.214865] Tag Rule ID : 0
[  809.214867] Rx VLAN Device : lei_vlan1
[  809.214867] 
[  809.214867] Filters
[  809.214868]  VlanDev MacAddr : No
[  809.214870]  VLAN Tag 0      : pbits -, cfi -, vid 16, (tci 0x0FFF/0x0010), ether -
[  809.214877] 
[  809.214877] Commands
[  809.214877]  00:[NOP, 0x00000000, 0x00000000] 
[  809.214877] 
[  809.214882] Rule Type  : Flow
[  809.214883] Hit Count   : 0
[  809.214884] 
[  809.214884] --------------------------------------------------------------------------------
```

This rule can be manually set with
```
root@iopsys:~# vlanctl --if lei --rx --tags 1 --rule-remove 0
root@iopsys:~# vlanctl --if lei --rx --tags 1 --filter-vid <VID> 0 --set-rxif lei_vlan1 --rule-append
```

### Sporadic kernel crashes

When the vlan_segregation feature is active, *sh3* seems to sporadically crash and reboot. (This issue has not been seen on *disc*).

```
[  344.549713] Call trace:
[  344.549738]  dhd_pktfwd_lut_hit+0x27c/0x2a0 [dhd]
[  344.549742]  bcm_br_wl_query_bridgefdb+0x94/0xb0 [wlshared]
[  344.549746]  bcm_br_fdb_cleanup+0x58/0x90
[  344.549749]  br_fdb_cleanup+0x74/0x110
[  344.549755]  process_one_work+0x194/0x2e0
[  344.549758]  worker_thread+0x48/0x400
[  344.549761]  kthread+0x128/0x160
[  344.549766]  ret_from_fork+0x10/0x24
[  344.549770] Code: 17ffffac 121e7400 f9000a9f 39006e80 (79406720)
[  346.644634] ---[ end trace b03917b556e6be8e ]---
[  346.644637] Kernel panic - not syncing: Fatal exception in interrupt
```
This is indicative of a loop issue and *may* be related to test setup, or *may* be a result of incorrect tag device bringup.

Setting the system up without tagging devices does not result in the sporadic crash, indicating it could be relating to tag device setup.

A way of creating an untagged setup is to disable **ts_sub** calls in **/lib/wifi/multiap** (preferably replacing the call with a logger entry for debugging purposes):
```
#       ts) ts_sub $@;;
        ts) logger -t vlan $@;;
```
Also, the ebtables rules need to be added manually in this case. A simple ebtables setup is:
```
ebtables -t broute -D BROUTING -p 0x893a -i wl+ -j ACCEPT
ebtables -t broute -I BROUTING -p 0x893a -i wl+ -j ACCEPT
ebtables -t broute -D BROUTING -p 0x893a -i lei -j ACCEPT
ebtables -t broute -I BROUTING -p 0x893a -i lei -j ACCEPT
ebtables -t broute -D BROUTING -p 0x893a -i lei_vlan -j ACCEPT
ebtables -t broute -I BROUTING -p 0x893a -i lei_vlan -j ACCEPT
```

### vlan errors

```
root@iopsys:~# dmesg | grep "ERROR vlan"
[   44.490788] [ERROR vlan] registerVlanDeviceByName,435: Failed to REGISTER VLAN Device sink3_vlan1
[   44.490802] [ERROR vlan] vlanIoctl ,684: Failed to create VLAN device (sink2_vlan1, sink3_vlan1)
[  293.001110] [ERROR vlan] registerVlanDeviceByName,435: Failed to REGISTER VLAN Device lei_vlan1
[  293.001123] [ERROR vlan] vlanIoctl ,684: Failed to create VLAN device (lei, lei_vlan1)
[  393.049025] [ERROR vlan] registerVlanDeviceByName,435: Failed to REGISTER VLAN Device lei_vlan1
[  393.059035] [ERROR vlan] vlanIoctl ,684: Failed to create VLAN device (lei, lei_vlan1)
```

### auto setup repetition (including incorrect secondary VID setup on LEI)
```
root@iopsys:~# logread -e vlan
Fri Oct  1 15:30:53 2021 user.notice : Added device handler type: macvlan
Fri Oct  1 15:30:54 2021 user.notice vlanconf: creating eth0.1, type: untagged, parent: eth0
Fri Oct  1 15:30:59 2021 user.notice vlan: multicast eth1
Fri Oct  1 15:30:59 2021 user.notice vlan: multicast eth2
Fri Oct  1 15:30:59 2021 user.notice vlan: multicast eth3
Fri Oct  1 15:30:59 2021 user.notice vlan: multicast eth4
Fri Oct  1 15:30:59 2021 user.notice vlan: multicast wl1
Fri Oct  1 15:30:59 2021 user.notice vlan: multicast wl0
Fri Oct  1 15:30:59 2021 user.notice vlan: multicast wl0.1
Fri Oct  1 15:30:59 2021 user.notice vlan: multicast wl1.1
Fri Oct  1 15:30:59 2021 user.notice vlan: multicast lei_lan
Fri Oct  1 15:31:00 2021 user.notice vlan: multicast lei_lan
Fri Oct  1 15:31:06 2021 user.notice vlan: create fh wl0 1
Fri Oct  1 15:31:06 2021 user.notice vlan: create dhcp 1
Fri Oct  1 15:31:06 2021 user.notice vlan: create fh wl1 1
Fri Oct  1 15:31:06 2021 user.notice vlan: create dhcp 1
Fri Oct  1 15:31:06 2021 user.notice vlan: create bh wl0.1 1 2
Fri Oct  1 15:31:06 2021 user.notice vlan: create bh wl1.1 1 2
Fri Oct  1 15:31:06 2021 user.notice vlan: create eth lei 1 0 br-map br-lan
Fri Oct  1 15:31:06 2021 user.notice vlan: populate eth lei 4155247100
Fri Oct  1 15:31:08 2021 user.notice vlan: delete wl0
Fri Oct  1 15:31:08 2021 user.notice vlan: delete wl0.1
Fri Oct  1 15:31:08 2021 user.notice vlan: delete wl1
Fri Oct  1 15:31:08 2021 user.notice vlan: delete wl1.1
Fri Oct  1 15:31:08 2021 user.notice vlan: delete lei
Fri Oct  1 15:31:13 2021 user.notice vlan: multicast eth1
Fri Oct  1 15:31:13 2021 user.notice vlan: multicast eth2
Fri Oct  1 15:31:13 2021 user.notice vlan: multicast eth3
Fri Oct  1 15:31:13 2021 user.notice vlan: multicast eth4
Fri Oct  1 15:31:13 2021 user.notice vlan: multicast wl1.1
Fri Oct  1 15:31:13 2021 user.notice vlan: multicast lei_lan
Fri Oct  1 15:31:13 2021 user.notice vlan: create fh wl0 1
Fri Oct  1 15:31:13 2021 user.notice vlan: create dhcp 1
Fri Oct  1 15:31:13 2021 user.notice vlan: create fh wl1 1
Fri Oct  1 15:31:13 2021 user.notice vlan: create dhcp 1
Fri Oct  1 15:31:13 2021 user.notice vlan: create bh wl0.1 1 2
Fri Oct  1 15:31:13 2021 user.notice vlan: create bh wl1.1 1 2
Fri Oct  1 15:31:13 2021 user.notice vlan: create eth lei 1 0 br-map br-lan
Fri Oct  1 15:31:13 2021 user.notice vlan: populate eth lei 4155247100
Fri Oct  1 15:31:13 2021 user.notice vlan: multicast eth1
Fri Oct  1 15:31:13 2021 user.notice vlan: multicast eth2
Fri Oct  1 15:31:13 2021 user.notice vlan: multicast eth3
Fri Oct  1 15:31:13 2021 user.notice vlan: multicast eth4
Fri Oct  1 15:31:13 2021 user.notice vlan: multicast wl1.1
Fri Oct  1 15:31:13 2021 user.notice vlan: multicast lei_lan
Fri Oct  1 15:31:13 2021 user.notice vlan: create fh wl0 1
Fri Oct  1 15:31:13 2021 user.notice vlan: create dhcp 1
Fri Oct  1 15:31:14 2021 user.notice vlan: create fh wl1 1
Fri Oct  1 15:31:14 2021 user.notice vlan: create dhcp 1
Fri Oct  1 15:31:14 2021 user.notice vlan: create bh wl0.1 1 2
Fri Oct  1 15:31:14 2021 user.notice vlan: create bh wl1.1 1 2
Fri Oct  1 15:31:14 2021 user.notice vlan: create eth lei 1 0 br-map br-lan
Fri Oct  1 15:31:14 2021 user.notice vlan: populate eth lei 4155247100
```
