#NAT Implementation using DPDK.

[![BSD license](https://img.shields.io/badge/License-BSD-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

In nowadays high speed virtualized nerwork, tranditional network mechanism has no longer satisfied our requirement. In home network virtualization many data plane features, e.g.: NAT and PPPoE, will be de-coupled to cloud NFV infrastructure. However, the perfoemance of data plane is always the main point of our concern. Therefore, we design a system that make NAT can be used in virtualization and high speed network.

System required: Intel DPDK, Linux kernel > 3.10, at least 4G ram, 7 cpu cores(We suggest to use 8 cpu cores).

------------------------------------How to Use------------------------------------

Git clone this repository and change branch to "timer"

	$ git clone https://github.com/w180112/DPDK_NAT.git

Type 
	```
	$ make 
	```
to compile

Then 
	```
	$ ./build/nat <LAN gw IP> <WAN gw IP> <dpdk eal options>
	```
e.g. 
	```
	$ ./build/nat 192.168.1.102 192.168.2.112 -l 0-6 -n 2
	```

In this project we need 2 DPDK ethernet ports, the first is used to receive packets from/send packets to LAN port and the second is used to receive packets from/send packets to WAN port.

To remove the binary file 
	```
	$ make clean 
	```

##Test environment : 

	1.CentOS 7.5 KVM with Mellanox CX3, CX4 Lx
	2.AMD Ryzen 2700, 32GB ram
	4.Intel DPDK 18.11

##TODO : 

	1.VLAN support
	2.Multiple users/devices support
