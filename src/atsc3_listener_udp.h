/*
 * atsc3_listener_udp.h
 *
 *  Created on: Feb 6, 2019
 *      Author: jjustman
 */
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

#ifndef ATSC3_LISTENER_UDP_H_
#define ATSC3_LISTENER_UDP_H_

typedef struct udp_packet {
	uint32_t		src_ip_addr;
	uint32_t		dst_ip_addr;
	uint16_t		src_port;
	uint16_t		dst_port;

	//inherit from libpcap type usage
	int 			data_length;
	u_char* 		data;

} udp_packet_t;


#endif /* ATSC3_LISTENER_UDP_H_ */
