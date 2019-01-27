libatsc3
==========
ATSC 3.0 NGBP Open Source Library - Parse LMT, LLS and other signaling, object delivery via ROUTE, video playback of MMT and DASH 

Updates:

## 2019-01-27 - src/

Refactored out POC VLC plugin into standalone mmt sample listener.

* To build, run make
* To run, ./atsc3_mmt_listener_test vnic1
** where vnic1 is the mulitcast interface of your choice

* the listener test driver will write out mpu fragments in the mpu/ directory from all flows.  dst ip and port flows can be restricted by invoking the driver with these on the command line.  the listener will write out the packet fragments as received on the wire, and proper re-sequencing and re-assembly can be obtained by inspecting the mmtp_sub_flow_vector.  
**KNOWN ISSUES:** this code is very leaky, as the driver does not free the vector yet.

## 2019-01-21 - support_scripts/  

For ATSC 3.0 receiption with the Airwavz Redzone receiver, including RF scanning, reflection, capturing and replaying of IP multicast streams with tcpdump, tcprewrite and bittwist.  


jjustman@ngbp.org
###