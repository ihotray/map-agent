# DYNBHD

Dynbhd is a daemon that will automatically detect LAN and WAN ports
based on autoconfig search, autoconfig response and supportedRole=controller.
Additionally, dynbhd will find looped WAN interfaces and remove any excess WAN
interfaces from the bridge.

Ethwan will always take priority over wireless. Ethwan priority is based upon
ethport event receival time and autoconfig response time.

## Support Scenarios
* Multiple ethwan connections
* Swapping between ethwan and bsta
* LAN clients

## Implementation Limitations

* Currently a 10 second timer is allowed to figure out of a connection is WAN or
LAN. This means LAN clients will experience 10 seconds after connection to
recieve DHCP.

## Known Issues

* Upon forming a loop traffic may be dropped completely. Causing dynbhd to
not function properly.

## Fixes, Mitigation and Future Work
The known limitations will be able to be reduced or mitigated once periodic WAN
probing is implemented.


