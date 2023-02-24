# Layer 3 Traffic Separation

The EasyMesh R2 specification only specifies behavior for layer 2 traffic
separation, which IOPSYS Multi-AP components support and will automatically
setup necessary configuration for when it is enabled.

However, using the same solution layer 3 traffic separation is supported but
must be configured manually. This primarily refers to the creation of **bridge-vlan** sections,
which dictates bridge and Ethernet port tagging rules. If a Traffic Separation
TLV is received for which the necessary **bridge-vlan** sections are already
present, map-agent will not setup any additional configuration or modify the
existing rules. Map-agent will still be responsible for setting up tagging
rules on the wireless interfaces as dictated by the EasyMesh specification and
passed map-controller configuration.

This leaves users with flexibility to setup layer 3 traffic separation
or any other configuration as they require.

## How to Configure

To enable layer 3 traffic separation, it is necessary to manually setup the
**network**, **firewall** and **dhcp** configuration as per any custom
requirements.

In this how to guide an example it will be shown how to setup a basic use-case
where guest clients will receive an IPv4 address from a DHCP server running on a
separate bridge, with all traffic egressing and ingressing over said bridge.

### Network Configuration

#### Guest Bridges

First, the bridges must be created. The bridges can have any IP address,
netmask etc. In this example we will create two additional guest bridges, one
for VID 50 and one for VID 20.

```
config interface 'guest50'
	option device 'br-guest50'
	option is_lan '1'
	option proto 'static'
	option ipaddr '192.168.50.1'
	option netmask '255.255.255.0'

config device 'br_guest50'
	option name 'br-guest50'
	option type 'bridge'

config interface 'guest20'
	option device 'br-guest20'
	option is_lan '1'
	option proto 'static'
	option ipaddr '192.168.20.1'
	option netmask '255.255.255.0'

config device 'br_guest20'
	option name 'br-guest20'
	option type 'bridge'
```


#### Veth Pair

As incoming Wi-Fi client traffic will be ingressing over the wireless interfaces
which reside in the **al_bridge**, we must create a veth pair so this traffic
can ingress to the guest bridges.

```
config device 'guest_dev20'
	option type 'veth'
	option name 'guest_dev20'
	option peer_name 'guest_peer20'

config device 'guest_dev50'
	option type 'veth'
	option name 'guest_dev50'
	option peer_name 'guest_peer50'
```

These veth pairs must now have their peers attached to the port list of the
respective bridge and the source interface to the **al_bridge**.

```
config device 'br_lan'
	option name 'br-lan'
	option type 'bridge'
	list ports 'eth1'
	list ports 'eth2'
	list ports 'eth3'
	list ports 'eth4'
	list ports 'guest_dev20'
	list ports 'guest_dev50'

config device 'br_guest50'
	option name 'br-guest50'
	option type 'bridge'
	list ports 'guest_peer50'

config device 'br_guest20'
	option name 'br-guest20'
	option type 'bridge'
	list ports 'guest_peer20'
```

We will now find traffic ingressing over the **al_bridge** on the guest bridges
as well.

#### VLAN ID Tagging Rules

Finally, we must setup the **bridge-vlan** sections providing netifd with
information on the bridge filtering rules. These rules are in a layer 2 use-case
automatically setup by map-agent.

The **al_bridge** must not untag anything that is not the Primary VLAN ID
(unless it is desired that it managed _some_ secondary VLAN IDs), and the guest
bridges untag according to the VLAN IDs that they are supposed to manage.

```
# Ethernet ports and br-lan tag and untaged Primary VLAN ID
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

# Ethernet ports (as many as desired) and br-lan allow VID 50 to be passed
# guest_dev50 tags and untags VID 50
config bridge-vlan 'vlan50'
	option name 'vlan50'
	option device 'br-lan'
	option vlan '50'
	option flags 'untagged'
	option local '0'
	list ports 'eth1:t'
	list ports 'eth2:t'
	list ports 'eth3:t'
	list ports 'eth4:t'
	list ports 'guest_dev50:*'

# Ethernet ports (as many as desired) and br-lan allow VID 20 to be passed
# guest_dev50 tags and untags VID 20
config bridge-vlan 'vlan20'
	option name 'vlan20'
	option device 'br-lan'
	option vlan '20'
	option flags 'untagged'
	option local '0'
	list ports 'eth1:t'
	list ports 'eth2:t'
	list ports 'eth3:t'
	list ports 'eth4:t'
	list ports 'guest_dev20:*'
```

#### Bridge Filtering Configuration

With the network configuration setup and loaded (recommended to be done via
`/etc/init.d/network restart` as `reload` will not always apply the necessary
tagging rules), **bridge vlan** configuration output should look as follows:

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
guest_peer20      1 PVID Egress Untagged
guest_dev20       20 PVID Egress Untagged
guest_peer50      1 PVID Egress Untagged
guest_dev50       50 PVID Egress Untagged
br-guest20        1 PVID Egress Untagged
br-guest50        1 PVID Egress Untagged
wl1.1             1 PVID Egress Untagged
wl0.1             1 PVID Egress Untagged
```

An example **brctl show** output would look as:

```
root@iopsys-021000000001:~# brctl show
bridge name	bridge id		STP enabled	interfaces
br-guest20		7fff.922f1251b15b	no		guest_peer20
br-guest50		7fff.ec6c9a52b02b	no		guest_peer50
br-lan		7fff.ec6c9a52b027	no		eth1
							eth2
							eth3
							eth4
							guest_dev20
							guest_dev50
							wl0
							wl0.1
							wl1
							wl1.1
```

### Firewall Configuration

In the firewall configuration, each network must be given input, output and
forwarding rules by being attached to a firewall **zone**. In this example we
create a zone for each network that accepts all traffic.

```
config zone 'guest20'
	option name 'guest20'
	list network 'guest20'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'

config zone 'guest50'
	option name 'guest50'
	list network 'guest50'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
```
Next we create the forwarding rules for these zones, forwarding traffic through
the wan zone.

```
config forwarding
	option src 'guest20'
	option dest 'wan'

config forwarding
	option src 'guest50'
	option dest 'wan'

```

With the configuration setup, we must now reload the firewall rules via i.e.
`/etc/init.d/firewall reload`.

### DHCP Configuration

In the DHCP configuration, we create a DHCP server for each network, specifying
the desired DHCP ranges.

```
config dhcp 'guest20'
	option interface 'guest20'
	option start '100'
	option limit '150'
	option leasetime '1h'
	option dhcpv4 'server'
	option dhcpv6 'server'
	option ra 'server'
	option ra_slaac '1'
	list ra_flags 'managed-config'
	list ra_flags 'other-config'

config dhcp 'guest50'
	option interface 'guest50'
	option start '100'
	option limit '150'
	option leasetime '1h'
	option dhcpv4 'server'
	option dhcpv6 'server'
	option ra 'server'
	option ra_slaac '1'
	list ra_flags 'managed-config'
	list ra_flags 'other-config'
```

We can now restart dnsmasq via i.e. `/etc/init.d/dnsmasq restart`.

### Map-Controller Configuration

In map-controller we may now enable Traffic Separation and append two guest
networks for VID 20 and VID 50.

```
config controller 'controller'
	option enabled '1'
	option registrar '5 2'
	option debug '0'
	option primary_vid '1'
	option primary_pcp '0'
	option enable_ts '1'
```

```
config ap
	option ssid 'iopsys-vid50'
	option band '5'
	option encryption 'sae-mixed'
	option key '1234567890'
	option vid '50'
	option type 'fronthaul'

config ap
	option ssid 'iopsys-vid20'
	option band '2'
	option encryption 'sae-mixed'
	option key '1234567890'
	option vid '20'
	option type 'fronthaul'
```

A SIGHUP can then be sent to map-controller as i.e.
`kill -1 $(pidof mapcontroller)`.

## Verification

### Bridge VLAN Filtering

The **bridge vlan** configuration should now look as such:

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
guest_peer20      1 PVID Egress Untagged
guest_dev20       20 PVID Egress Untagged
guest_peer50      1 PVID Egress Untagged
guest_dev50       50 PVID Egress Untagged
br-guest20        1 PVID Egress Untagged
br-guest50        1 PVID Egress Untagged
wl1.1             1 PVID Egress Untagged
wl0.1             1 PVID Egress Untagged
wl1.2             1 Egress Untagged
                  20 PVID Egress Untagged
wl0.2             1 Egress Untagged
                  50 PVID Egress Untagged
```
### Connecting a Wi-Fi Client

Connecting a client to i.e. **wl1.2** we can see that it will receive a DHCP
address from the 192.168.20.0/24 subnet:

```
root@iopsys-021000000001:~# ubus call wifi.ap.wl1.2 assoclist
{
	"assoclist": [
		{
			"wdev": "wl1.2",
			"macaddr": "4a:93:6d:3c:48:21"
		}
	]
}
root@iopsys-021000000001:~# cat /tmp/dhcp.leases
1670580192 4a:93:6d:3c:48:21 192.168.20.139 jakobs-S21 01:4a:93:6d:3c:48:21
```

### Tags on Bridge

By using tcpdump, we can now observe that this clients traffic will now have its
VLAN ID 20 tag intact over **br-lan**, which means it will not egress through from
**br-lan** as no egress rules are set for VID 20 on **br-lan**.

```
root@iopsys-021000000001:~# tcpdump -nei br-lan icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on br-lan, link-type EN10MB (Ethernet), capture size 262144 bytes
10:08:08.357498 b2:f3:b5:c1:ca:54 > 4a:93:6d:3c:48:21, ethertype 802.1Q (0x8100), length 106: vlan 20, p 0, ethertype IPv4, 192.168.20.1 > 192.168.20.139: ICMP net 20.50.80.209 unreachable, length 68
10:08:10.524492 b2:f3:b5:c1:ca:54 > 4a:93:6d:3c:48:21, ethertype 802.1Q (0x8100), length 106: vlan 20, p 0, ethertype IPv4, 192.168.20.1 > 192.168.20.139: ICMP net 52.114.74.223 unreachable, length 68
10:08:10.993687 4a:93:6d:3c:48:21 > b2:f3:b5:c1:ca:54, ethertype 802.1Q (0x8100), length 102: vlan 20, p 0, ethertype IPv4, 192.168.20.139 > 123.123.123.123: ICMP echo request, id 2136, seq 1, length 64
10:08:10.993886 b2:f3:b5:c1:ca:54 > 4a:93:6d:3c:48:21, ethertype 802.1Q (0x8100), length 102: vlan 20, p 0, ethertype IPv4, 123.123.123.123 > 192.168.20.139: ICMP echo reply, id 2136, seq 1, length 64
```

However, on **br-guest20** we can see the same traffic is untagged and can egress:
```
root@iopsys-021000000001:~# tcpdump -nei br-guest20 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on br-guest20, link-type EN10MB (Ethernet), capture size 262144 bytes
10:09:29.127415 b2:f3:b5:c1:ca:54 > 4a:93:6d:3c:48:21, ethertype IPv4 (0x0800), length 590: 192.168.20.1 > 192.168.20.139: ICMP net 31.13.72.53 unreachable, length 556
10:09:29.709500 b2:f3:b5:c1:ca:54 > 4a:93:6d:3c:48:21, ethertype IPv4 (0x0800), length 102: 192.168.20.1 > 192.168.20.139: ICMP net 52.114.74.223 unreachable, length 68
10:09:32.640145 4a:93:6d:3c:48:21 > b2:f3:b5:c1:ca:54, ethertype IPv4 (0x0800), length 98: 192.168.20.139 > 123.123.123.123: ICMP echo request, id 2395, seq 1, length 64
10:09:32.640227 b2:f3:b5:c1:ca:54 > 4a:93:6d:3c:48:21, ethertype IPv4 (0x0800), length 98: 123.123.123.123 > 192.168.20.139: ICMP echo reply, id 2395, seq 1, length 64
```


