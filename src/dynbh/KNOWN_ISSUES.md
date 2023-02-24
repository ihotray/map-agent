# KNOWN ISSUES

## 1. Ethernet Loops
Two known issues where traffic is unable to be sent and received between DISC
and SH3 upon forming a network loop have been observed.
The root cause for the lack of traffic is currently unknown.

### 1.1 Loop Formation
Occassionally when an ethernet loop is formed, traffic stops being sent
and received between the SH3 and DISC. This will cause loop avoidance to fail
and lack of uplink.

#### 1.1.1 Notes:
* Dynbhd will not be able to detect loop due to lack of traffic
* Both ports will be found in bridge
* Will not cause SH3 or DISC to crash
* To recover, both ports of the loop have to be disconnected, then
	one port connected. If DISC does not recover connection quick
	enough and send traffic upon reconnection, loop avoidance will
	fail due to the 10 second detection window. To mitigate, allow
	for longer disconnection time during disconnection of ports.
	- This delayed recovery effect may be mitigated in the future by
		periodic probes, over connected eth interfaces that have not
		been marked by dynbhd.

### 1.2 Network Restart
When network is restarted, and bridge is recreated (i.e.
`/etc/init.d/network restart`) and loop is present (and properly identified
and avoided by dynbhd). Traffic may stop being sent and received between SH3 and
DISC. See point 1.1 for additional notes.

## 2. Generic

As implementation is largely dependent on ethport events and ieee1905, missing
events or CMDUs will be detrimental. All listed issues may be avoided or
mitigated by implementing a periodic probe.

### 2.1 Missing Autoconfig Responses
If device is connected to an upstream device, and that upstream device does
not, for whatever reason, answer the autoconfig search, the link will work, but
if later on a loop is formed, it will not be able to be identified due to the
missing `/var/run/multiap/map.agent.bsta_global_disable` file.

### 2.2 Missing ethport events
If an ethport event is missed, or does not come, there will be unexpected
behavior in form of i.e. loops not being identified or WAN missing from bridge.
