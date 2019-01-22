Tools for the Airwavz Redzone ATSC 3.0 receiver for ethernet mulicast reflection, field scanning, tuning and collection.

2019-01-21
jjustman@ngbp.org

I run my airwavz receiver on a linux virtual machine, use my mac as my development host.  There are two folders with scripts for each envrionment:

linux/

./startEnMulticast 

Streamlines the redzone turn-up process from cold boot.  This script will provision 
enp0s6 ethernet interface for multicast reflection (instead of lo) and adds mcast routes.  
Update ./loopback-en.sh accordingy if you want to map to a virtual nic or wifi adapter. 
It will also launch the redzone userspace driver (2x to work-around first power-on bug), and
launch Firefox with the RF status page.

./tuneFreq 737

Perform a one-shot tune to the specified center frequency (will append 000000 to be in the MHz range)

./kill

Kill the redzone userspace driver (via -9)

./tuneWalkUhf

Perform a 473-800Mhz scan, incrementing by 6Mhz every 10 seconds (in an infinite loop) for ATSC 3.0 transmission detection in the field.
RF techincal data will be captured in a folder labeled "scans/YYYY-MM-DD" and each file will contain the frequency, UTC, and the 
last RF/Tuner status before chainging frequency.

Please note, as repack'd 4G/LTE stations begin lighting up in the 710-716MHz, 740-758MHz, and 776-788Mhz, you may see phantom bootstraps 
in the results.  If you observe BOOTSTRAP EASINFO:1, BOOTSTRAP PREAMBLE STRUCTURE and BOOTSTRAP BSR COEFFICIENT values with a super strong RSSI but no SNR/LOCK, along with the BW range incrementing from 6Mhz to 7Mhz, keep scanning.  It's not ATSC 3.0.

    "OPERATING MODE": "2",
    "FREQUENCY (HZ)": "737000000",
    "BANDWIDTH (HZ)": "6000000",
    "INTERMEDIATE FREQUENCY (HZ)": "6000000",
    "RSSI (dBm)": "-41",
    "MASTER LOCK": "0",
    "SNR (dB * 100)": "-1000",
    "SIGNAL QUALITY (%)": "0",
    "BOOTSTRAP DONE": "0",
    "BOOTSTRAP EASINFO": "1",
    "BOOTSTRAP MAJOR": "0",
    "BOOTSTRAP MINOR": "0",
    "BOOTSTRAP PREAMBLE STRUCTURE": "25",
    "BOOTSTRAP BSR COEFFICIENT": "2",
    "LLS VALID BITMASK": "0",
    "PLP VALID BITMASK": "0",
    "L1B LOCK": "0",

For more information about UFH blocks, see the following link:

    http://otadtv.com/frequency/index.html

osx/

./deleteMulticastRoute

OSX doesn't have traditional multicast support via ifconfig or setsockopt, you'll have to manage it by removing lo routes and adding them to your corresponding nic.  This script will delete the 224/4 route (and some other selective ones that have shown up on my mac).  Use the next script to join:

./addVnic1MulitcastRoute

Join the 224/4 mulicast via vnic1

./capture

Begin a pcap capture from vnic1 and write out to utc.pcap

./fixchksum

Most NIC's do checksum offloading, and you may need to recalculate proper values before attempting to replay your .pcap.  Run tcprewrite --fixcsum on the completed pcap file and then run replay:

./replay

run bittwist to replay the pcap file in an infinte loop

Good luck!
- Jason

###


