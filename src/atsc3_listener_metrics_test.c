/*
 * atsc3_listener_metrics_test.c
 *
 *  Created on: Jan 19, 2019
 *      Author: jjustman
 *
 * global listener driver for LLS, MMT and ROUTE / DASH (coming soon)
 *
 *
 * borrowed from https://stackoverflow.com/questions/26275019/how-to-read-and-send-udp-packets-on-mac-os-x
 * uses libpacp for udp mulicast packet listening
 *
 * opt flags:
  export LDFLAGS="-L/usr/local/opt/libpcap/lib"
  export CPPFLAGS="-I/usr/local/opt/libpcap/include"

  to invoke test driver, run ala:

  ./atsc3_listener_metrics_test vnic1


  TODO: A/331 - Section 8.1.2.1.3 - Constraints on MMTP
  	  PacketId
*/


#define MMT_DST_ADDR 4026468866
#define MMT_DST_PORT 51002


//#define _ENABLE_TRACE 1
//#define _SHOW_PACKET_FLOW 1
int PACKET_COUNTER=0;

#define LLS_DST_ADDR 3758102332
#define LLS_DST_PORT 4937

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/stat.h>
#include "atsc3_mmtp_types.h"
#include "atsc3_lls.h"
#include "atsc3_mmtp_parser.h"
#include "atsc3_mmtp_ntp32_to_pts.h"

extern int _MPU_DEBUG_ENABLED;
extern int _MMTP_DEBUG_ENABLED;
extern int _LLS_DEBUG_ENABLED;


#define println(...) printf(__VA_ARGS__);printf("\n")

#define __PRINTLN(...) printf(__VA_ARGS__);printf("\n")
#define __PRINTF(...)  printf(__VA_ARGS__);

#define __ERROR(...)   printf("%s:%d:ERROR:",__FILE__,__LINE__);__PRINTLN(__VA_ARGS__);
#define __WARN(...)    printf("%s:%d:WARN:",__FILE__,__LINE__);__PRINTLN(__VA_ARGS__);
#define __INFO(...)    printf("%s:%d:INFO:",__FILE__,__LINE__);__PRINTLN(__VA_ARGS__);

#ifdef _ENABLE_DEBUG
#define __DEBUG(...)   printf("%s:%d:DEBUG:",__FILE__,__LINE__);__PRINTLN(__VA_ARGS__);
#define __DEBUGF(...)  printf("%s:%d:DEBUG:",__FILE__,__LINE__);__PRINTF(__VA_ARGS__);
#define __DEBUGA(...) 	__PRINTF(__VA_ARGS__);
#define __DEBUGN(...)  __PRINTLN(__VA_ARGS__);
#else
#define __DEBUG(...)
#define __DEBUGF(...)
#define __DEBUGA(...)
#define __DEBUGN(...)
#endif

#ifdef _ENABLE_TRACE
#define __TRACE(...)   printf("%s:%d:TRACE:",__FILE__,__LINE__);__PRINTLN(__VA_ARGS__);

void __trace_dump_ip_header_info(u_char* ip_header) {
    __TRACE("Version\t\t\t\t\t%d", (ip_header[0] >> 4));
    __TRACE("IHL\t\t\t\t\t\t%d", (ip_header[0] & 0x0F));
    __TRACE("Type of Service\t\t\t%d", ip_header[1]);
    __TRACE("Total Length\t\t\t%d", ip_header[2]);
    __TRACE("Identification\t\t\t0x%02x 0x%02x", ip_header[3], ip_header[4]);
    __TRACE("Flags\t\t\t\t\t%d", ip_header[5] >> 5);
    __TRACE("Fragment Offset\t\t\t%d", (((ip_header[5] & 0x1F) << 8) + ip_header[6]));
    __TRACE("Time To Live\t\t\t%d", ip_header[7]);
    __TRACE("Header Checksum\t\t\t0x%02x 0x%02x", ip_header[10], ip_header[11]);
}

#else
#define __TRACE(...)
#endif


typedef struct udp_packet {
	uint32_t		src_ip_addr;
	uint32_t		dst_ip_addr;
	uint16_t		src_port;
	uint16_t		dst_port;

	//inherit from libpcap type usage
	int 			data_length;
	u_char* 		data;

} udp_packet_t;


//239.255.10.2:51002
uint32_t  dst_ip = MMT_DST_ADDR;
uint16_t  dst_port = MMT_DST_PORT;
uint32_t* dst_ip_addr_filter = &dst_ip;
uint16_t* dst_ip_port_filter = &dst_port;

typedef struct packet_id_mpu_stats {
	uint32_t mpu_sequence_number;
	uint8_t  mpu_fragementation_counter;

	uint32_t mpu_sequence_number_last;
	uint8_t  mpu_fragementation_counter_last;

} packet_id_mpu_stats_timed_t;

typedef struct packet_id_mpu_stats_nontimed {
	uint32_t mpu_nontimed_total;

} packet_id_mpu_stats_nontimed_t;

typedef struct packet_id_signalling_stats {

	uint32_t signalling_messages_total;

	uint32_t mmt_atsc3_message_count;
	uint16_t mmt_atsc3_message_id;
	uint16_t mmt_atsc3_message_content_type;

} packet_id_signalling_stats_t;

typedef struct packet_id_mmt_stats {
	uint32_t packet_id;
	uint32_t packet_sequence_number;
	uint32_t timestamp;

	uint32_t packet_sequence_number_last;
	uint32_t timestamp_last;

	packet_id_mpu_stats_timed_t* 		mpu_stats_timed;
	packet_id_mpu_stats_nontimed_t* 	mpu_stats_nontimed;
	packet_id_signalling_stats_t* 		signalling_stats;

} packet_id_mmt_stats_t;

typedef struct global_mmt_stats {

	uint32_t packet_counter_recv;
	uint32_t packet_counter_last_value;
	uint32_t packet_counter_parse_error;
	uint32_t packet_counter_last_gap_gap;
	uint32_t packet_counter_missing;

	uint32_t packet_counter_mpu;
	uint32_t packet_counter_signaling;

	uint32_t lls_parsed_success_counter;
	uint32_t lls_parsed_failed_counter;

	int	packet_id_n;
	packet_id_mmt_stats_t** packet_id_vector;

	packet_id_mmt_stats_t* packet_id_delta;

} global_mmt_stats_t;

global_mmt_stats_t* global_mmt_stats;

packet_id_mmt_stats_t* find_packet_id(uint32_t packet_id) {
	for(int i=0; i < global_mmt_stats->packet_id_n; i++ ) {
		packet_id_mmt_stats_t* packet_mmt_stats = global_mmt_stats->packet_id_vector[i];
		__TRACE("  find_packet_id with %u from %u", packet_id, packet_id_mmt_stats->packet_id);

		if(packet_mmt_stats->packet_id == packet_id) {
			__TRACE("  find_packet_id returning with %p", packet_id_mmt_stats);

			return packet_mmt_stats;
		}
	}

	return NULL;
}

packet_id_mmt_stats_t* find_or_get_packet_id(uint32_t packet_id) {
	packet_id_mmt_stats_t* packet_mmt_stats = find_packet_id(packet_id);
	if(!packet_mmt_stats) {
		if(global_mmt_stats->packet_id_n && global_mmt_stats->packet_id_vector) {

			__INFO("*before realloc to %p, %i, adding %u", global_mmt_stats->packet_id_vector, global_mmt_stats->packet_id_n, packet_id);

			global_mmt_stats->packet_id_vector = realloc(global_mmt_stats->packet_id_vector, (global_mmt_stats->packet_id_n + 1) * sizeof(packet_id_mmt_stats_t*));
			if(!global_mmt_stats->packet_id_vector) {
				abort();
			}

			//global_mmt_stats->packet_id_vector[global_mmt_stats->packet_id_n++]
			packet_mmt_stats = global_mmt_stats->packet_id_vector[global_mmt_stats->packet_id_n++] = calloc(1, sizeof(packet_id_mmt_stats_t));

			if(!packet_mmt_stats) {
				abort();
			}


			__INFO("*after realloc to %p, %i, adding %u", packet_mmt_stats, global_mmt_stats->packet_id_n, packet_id);

		} else {
			global_mmt_stats->packet_id_n = 1;
			global_mmt_stats->packet_id_vector = calloc(1, sizeof(packet_id_mmt_stats_t*));
			global_mmt_stats->packet_id_vector[0] = calloc(1, sizeof(packet_id_mmt_stats_t));

			if(!global_mmt_stats->packet_id_vector) {
				abort();
			}

			packet_mmt_stats = global_mmt_stats->packet_id_vector[0];
			__INFO("*calloc %p for %u", packet_mmt_stats, packet_id);
		}
		packet_mmt_stats->packet_id = packet_id;
		packet_mmt_stats->mpu_stats_timed = 	calloc(1, sizeof(packet_id_mpu_stats_timed_t));
		packet_mmt_stats->mpu_stats_nontimed = 	calloc(1, sizeof(packet_id_mpu_stats_nontimed_t));
		packet_mmt_stats->signalling_stats = 	calloc(1, sizeof(packet_id_signalling_stats_t));

	}

	return packet_mmt_stats;
}

void packet_mmt_stats_populate(packet_id_mmt_stats_t* packet_mmt_stats, mmtp_payload_fragments_union_t* mmtp_payload) {
	if(packet_mmt_stats->packet_sequence_number) {
		packet_mmt_stats->packet_sequence_number_last = packet_mmt_stats->packet_sequence_number;
	}

	if(packet_mmt_stats->timestamp) {
		packet_mmt_stats->timestamp_last = packet_mmt_stats->timestamp;
	}

	packet_mmt_stats->packet_sequence_number = mmtp_payload->mmtp_packet_header.packet_sequence_number;
	packet_mmt_stats->timestamp = mmtp_payload->mmtp_packet_header.mmtp_timestamp;

	if(mmtp_payload->mmtp_packet_header.mmtp_payload_type == 0x0) {
		//assign our timed mpu stats
		if(mmtp_payload->mmtp_mpu_type_packet_header.mpu_timed_flag == 1) {
			if(packet_mmt_stats->mpu_stats_timed->mpu_sequence_number) {
				packet_mmt_stats->mpu_stats_timed->mpu_sequence_number_last = packet_mmt_stats->mpu_stats_timed->mpu_sequence_number;
			} else {
				packet_mmt_stats->mpu_stats_timed->mpu_sequence_number_last = 0;
			}
			packet_mmt_stats->mpu_stats_timed->mpu_sequence_number = mmtp_payload->mmtp_mpu_type_packet_header.mpu_sequence_number;

			if(packet_mmt_stats->mpu_stats_timed->mpu_fragementation_counter) {
				packet_mmt_stats->mpu_stats_timed->mpu_fragementation_counter_last = packet_mmt_stats->mpu_stats_timed->mpu_fragementation_counter;
			} else {
				packet_mmt_stats->mpu_stats_timed->mpu_fragementation_counter_last = 0;
			}
			packet_mmt_stats->mpu_stats_timed->mpu_fragementation_counter = mmtp_payload->mmtp_mpu_type_packet_header.mpu_fragmentation_counter;

		} else {
			//assign our non-timed stats here
			packet_mmt_stats->mpu_stats_nontimed->mpu_nontimed_total++;
		}
	} else if(mmtp_payload->mmtp_packet_header.mmtp_payload_type == 0x1) {
		//assign our signalling stats here
		packet_mmt_stats->signalling_stats->signalling_messages_total++;
	}
	global_mmt_stats->packet_id_delta = packet_mmt_stats;
}


int DUMP_COUNTER=0;

void dump_global_mmt_stats(){
	if(DUMP_COUNTER++%1000 == 0) {
		__INFO("global mmt stats:");
		__INFO("-----------------");
		__INFO("packet_counter_recv: %u", 				global_mmt_stats->packet_counter_recv);

		__INFO("packet_counter_last_value: %u", 		global_mmt_stats->packet_counter_last_value);
		__INFO("packet_counter_parse_error: %u", 		global_mmt_stats->packet_counter_parse_error);
		__INFO("packet_counter_last_gap_gap: %u", 		global_mmt_stats->packet_counter_last_gap_gap);
		__INFO("packet_counter_missing: %u", 			global_mmt_stats->packet_counter_missing);

		__INFO("packet_counter_mpu: %u", 				global_mmt_stats->packet_counter_mpu);
		__INFO("packet_counter_signaling: %u",			global_mmt_stats->packet_counter_signaling);

		__INFO("lls_parsed_success_counter: %u", 		global_mmt_stats->lls_parsed_success_counter);
		__INFO("lls_parsed_failed_counter: %u",			global_mmt_stats->lls_parsed_failed_counter);
		__INFO("-----------------");

		for(int i=0; i < global_mmt_stats->packet_id_n; i++ ) {
			packet_id_mmt_stats_t* packet_mmt_stats = global_mmt_stats->packet_id_vector[i];
			__INFO(" mmt packet_id: %u", packet_mmt_stats->packet_id);
			__INFO(" --------------");
			__INFO("  current packet_sequence_number: %u", packet_mmt_stats->packet_sequence_number);
			//print out ntp sample
			uint16_t seconds;
			uint16_t microseconds;
			compute_ntp32_to_seconds_microseconds(packet_mmt_stats->timestamp, &seconds, &microseconds);

			__INFO("  current timestamp: packet_id: %u, ntp: %u (s: %u, uS: %u)", packet_mmt_stats->packet_id, packet_mmt_stats->timestamp, seconds, microseconds);
			__INFO("  mpu_sequence_number: %u", packet_mmt_stats->mpu_stats_timed->mpu_sequence_number);
			__INFO(" --------------");

		}
	}

	if(global_mmt_stats->packet_id_delta) {
		packet_id_mmt_stats_t* packet_mmt_stats = global_mmt_stats->packet_id_delta;
		if(packet_mmt_stats->mpu_stats_timed->mpu_sequence_number_last &&
				(packet_mmt_stats->mpu_stats_timed->mpu_sequence_number_last != packet_mmt_stats->mpu_stats_timed->mpu_sequence_number && packet_mmt_stats->mpu_stats_timed->mpu_fragementation_counter_last != 0)) {

			__WARN(" **mpu sequence gap, packet_id: %u, FROM mpu_sequence:%u, packet_seq_num_last:%u, mpu_frag_counter_last: %d TO mpu_sequence:%u, packet_seq_num:%u, mpu_frag_counter: %u",
					packet_mmt_stats->packet_id,
					packet_mmt_stats->mpu_stats_timed->mpu_sequence_number_last,
					packet_mmt_stats->packet_sequence_number_last,
					packet_mmt_stats->mpu_stats_timed->mpu_fragementation_counter_last,
					packet_mmt_stats->mpu_stats_timed->mpu_sequence_number,
					packet_mmt_stats->packet_sequence_number,
					packet_mmt_stats->mpu_stats_timed->mpu_fragementation_counter);
		}
	}
	//process any gaps or deltas

	global_mmt_stats->packet_id_delta = NULL;
}

//make sure to invoke     mmtp_sub_flow_vector_init(&p_sys->mmtp_sub_flow_vector);
mmtp_sub_flow_vector_t* mmtp_sub_flow_vector;
void dump_mpu(mmtp_payload_fragments_union_t* mmtp_payload) {

	__DEBUG("------------------");

	if(mmtp_payload->mmtp_mpu_type_packet_header.mpu_timed_flag) {
		__DEBUG("MFU Packet (Timed)");
		__DEBUG("-----------------");
		__DEBUG(" mpu_fragmentation_indicator: %d", mmtp_payload->mpu_data_unit_payload_fragments_timed.mpu_fragment_type);
		__DEBUG(" movie_fragment_seq_num: %u", mmtp_payload->mpu_data_unit_payload_fragments_timed.movie_fragment_sequence_number);
		__DEBUG(" sample_num: %u", mmtp_payload->mpu_data_unit_payload_fragments_timed.sample_number);
		__DEBUG(" offset: %u", mmtp_payload->mpu_data_unit_payload_fragments_timed.offset);
		__DEBUG(" pri: %d", mmtp_payload->mpu_data_unit_payload_fragments_timed.priority);
		__DEBUG(" mpu_sequence_number: %u",mmtp_payload->mpu_data_unit_payload_fragments_timed.mpu_sequence_number);

	} else {
		__DEBUG("MFU Packet (Non-timed)");
		__DEBUG("---------------------");
		__DEBUG(" mpu_fragmentation_indicator: %d", mmtp_payload->mpu_data_unit_payload_fragments_nontimed.mpu_fragment_type);
		__DEBUG(" non_timed_mfu_item_id: %u", mmtp_payload->mpu_data_unit_payload_fragments_nontimed.non_timed_mfu_item_id);

	}

	__DEBUG("-----------------");
}

void mpu_dump_flow(uint32_t dst_ip, uint16_t dst_port, mmtp_payload_fragments_union_t* mmtp_payload) {
	//sub_flow_vector is a global
	dump_mpu(mmtp_payload);

	__DEBUG("::dumpMfu ******* file dump file: %d.%d.%d.%d:%d-p:%d.s:%d.ft:%d",
			(dst_ip>>24)&0xFF,(dst_ip>>16)&0xFF,(dst_ip>>8)&0xFF,(dst_ip)&0xFF,
			dst_port,
			mmtp_payload->mmtp_mpu_type_packet_header.mmtp_packet_id,
			mmtp_payload->mpu_data_unit_payload_fragments_timed.mpu_sequence_number,

			mmtp_payload->mmtp_mpu_type_packet_header.mpu_fragment_type);

	char *myFilePathName = calloc(64, sizeof(char*));
	snprintf(myFilePathName, 64, "mpu/%d.%d.%d.%d,%d-p.%d.s,%d.ft,%d",
			(dst_ip>>24)&0xFF,(dst_ip>>16)&0xFF,(dst_ip>>8)&0xFF,(dst_ip)&0xFF,
			dst_port,
			mmtp_payload->mmtp_mpu_type_packet_header.mmtp_packet_id,
			mmtp_payload->mpu_data_unit_payload_fragments_timed.mpu_sequence_number,

			mmtp_payload->mmtp_mpu_type_packet_header.mpu_fragment_type);


	__DEBUG("::dumpMfu ******* file dump file: %s", myFilePathName);

	FILE *f = fopen(myFilePathName, "a");
	if(!f) {
		__INFO("::dumpMpu ******* UNABLE TO OPEN FILE %s", myFilePathName);
			return;
	}


	for(int i=0; i <  mmtp_payload->mmtp_mpu_type_packet_header.mpu_data_unit_payload->i_buffer; i++) {
		fputc(mmtp_payload->mmtp_mpu_type_packet_header.mpu_data_unit_payload->p_buffer[i], f);
	}
	fclose(f);
}

//assumes in-order delivery
void mpu_dump_reconstitued(uint32_t dst_ip, uint16_t dst_port, mmtp_payload_fragments_union_t* mmtp_payload) {
	//sub_flow_vector is a global
	dump_mpu(mmtp_payload);

	__DEBUG("::dump_mpu_reconstitued ******* file dump file: %d.%d.%d.%d:%d-p:%d.s:%d.ft:%d",
			(dst_ip>>24)&0xFF,(dst_ip>>16)&0xFF,(dst_ip>>8)&0xFF,(dst_ip)&0xFF,
			dst_port,
			mmtp_payload->mmtp_mpu_type_packet_header.mmtp_packet_id,
			mmtp_payload->mpu_data_unit_payload_fragments_timed.mpu_sequence_number,

			mmtp_payload->mmtp_mpu_type_packet_header.mpu_fragment_type);

	char *myFilePathName = calloc(64, sizeof(char*));
	snprintf(myFilePathName, 64, "mpu/%d.%d.%d.%d,%d-p.%d.s,%d.ft",
			(dst_ip>>24)&0xFF,(dst_ip>>16)&0xFF,(dst_ip>>8)&0xFF,(dst_ip)&0xFF,
			dst_port,
			mmtp_payload->mmtp_mpu_type_packet_header.mmtp_packet_id,
			mmtp_payload->mpu_data_unit_payload_fragments_timed.mpu_sequence_number);


	__DEBUG("::dumpMfu ******* file dump file: %s", myFilePathName);

	FILE *f = fopen(myFilePathName, "a");
	if(!f) {
		__ERROR("::dumpMpu ******* UNABLE TO OPEN FILE %s", myFilePathName);
			return;
	}


	for(int i=0; i <  mmtp_payload->mmtp_mpu_type_packet_header.mpu_data_unit_payload->i_buffer; i++) {
		fputc(mmtp_payload->mmtp_mpu_type_packet_header.mpu_data_unit_payload->p_buffer[i], f);
	}
	fclose(f);
}


void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

  int i = 0;
  int k = 0;
  u_char ethernet_packet[14];
  u_char ip_header[24];
  u_char udp_header[8];
  int udp_header_start = 34;
  udp_packet_t* udp_packet = NULL;

//dump full packet if needed
#ifdef _ENABLE_TRACE
    for (i = 0; i < pkthdr->len; i++) {
        if ((i % 16) == 0) {
            __TRACE("%03x0\t", k);
            k++;
        }
        __TRACE("%02x ", packet[i]);
    }
#endif
    __TRACE("*******************************************************");

    for (i = 0; i < 14; i++) {
        ethernet_packet[i] = packet[0 + i];
    }

    if (!(ethernet_packet[12] == 0x08 && ethernet_packet[13] == 0x00)) {
        __TRACE("Source MAC Address\t\t\t%02X:%02X:%02X:%02X:%02X:%02X", ethernet_packet[6], ethernet_packet[7], ethernet_packet[8], ethernet_packet[9], ethernet_packet[10], ethernet_packet[11]);
        __TRACE("Destination MAC Address\t\t%02X:%02X:%02X:%02X:%02X:%02X", ethernet_packet[0], ethernet_packet[1], ethernet_packet[2], ethernet_packet[3], ethernet_packet[4], ethernet_packet[5]);
    	__TRACE("Discarding packet with Ethertype unknown");
    	return;
    }

    for (i = 0; i < 20; i++) {
		ip_header[i] = packet[14 + i];
	}

	//check if we are a UDP packet, otherwise bail
	if (ip_header[9] != 0x11) {
		__TRACE("Protocol not UDP, dropping");
		return;
	}

	#ifdef _ENABLE_TRACE
        __trace_dump_ip_header_info(ip_header);
	#endif

	if ((ip_header[0] & 0x0F) > 5) {
		udp_header_start = 48;
		__TRACE("Options\t\t\t\t\t0x%02x 0x%02x 0x%02x 0x%02x", ip_header[20], ip_header[21], ip_header[22], ip_header[23]);
	}

	//malloc our udp_packet_header:
	udp_packet = calloc(1, sizeof(udp_packet_t));
	udp_packet->src_ip_addr = ((ip_header[12] & 0xFF) << 24) | ((ip_header[13]  & 0xFF) << 16) | ((ip_header[14]  & 0xFF) << 8) | (ip_header[15] & 0xFF);
	udp_packet->dst_ip_addr = ((ip_header[16] & 0xFF) << 24) | ((ip_header[17]  & 0xFF) << 16) | ((ip_header[18]  & 0xFF) << 8) | (ip_header[19] & 0xFF);

	for (i = 0; i < 8; i++) {
		udp_header[i] = packet[udp_header_start + i];
	}

	udp_packet->src_port = (udp_header[0] << 8) + udp_header[1];
	udp_packet->dst_port = (udp_header[2] << 8) + udp_header[3];

	//4294967295
	//1234567890
	__DEBUGF("Src. Addr  : %d.%d.%d.%d\t(%-10u)\t", ip_header[12], ip_header[13], ip_header[14], ip_header[15], udp_packet->src_ip_addr);
	__DEBUGN("Src. Port  : %-5hu ", (udp_header[0] << 8) + udp_header[1]);
	__DEBUGF("Dst. Addr  : %d.%d.%d.%d\t(%-10u)\t", ip_header[16], ip_header[17], ip_header[18], ip_header[19], udp_packet->dst_ip_addr);
	__DEBUGA("Dst. Port  : %-5hu \t", (udp_header[2] << 8) + udp_header[3]);

	__TRACE("Length\t\t\t\t\t%d", (udp_header[4] << 8) + udp_header[5]);
	__TRACE("Checksum\t\t\t\t0x%02x 0x%02x", udp_header[6], udp_header[7]);

	udp_packet->data_length = pkthdr->len - (udp_header_start + 8);
	if(udp_packet->data_length <=0 || udp_packet->data_length > 1514) {
		__ERROR("invalid data length of udp packet: %d", udp_packet->data_length);
		return;
	}
	__DEBUG("Data length: %d", udp_packet->data_length);
	udp_packet->data = malloc(udp_packet->data_length * sizeof(udp_packet->data));
	memcpy(udp_packet->data, &packet[udp_header_start + 8], udp_packet->data_length);

	//inefficient as hell for 1 byte at a time, but oh well...
	#ifdef __ENABLE_TRACE
		for (i = 0; i < udp_packet->data_length; i++) {
			__TRACE("%02x ", packet[udp_header_start + 8 + i]);
		}
	#endif


	//dispatch for LLS extraction and dump


	#ifdef _SHOW_PACKET_FLOW
		__INFO("--- Packet size : %-10d | Counter: %-8d", udp_packet->data_length, PACKET_COUNTER++);
		__INFO("    Src. Addr   : %d.%d.%d.%d\t(%-10u)\t", ip_header[12], ip_header[13], ip_header[14], ip_header[15], udp_packet->src_ip_addr);
		__INFO("    Src. Port   : %-5hu ", (uint16_t)((udp_header[0] << 8) + udp_header[1]));
		__INFO("    Dst. Addr   : %d.%d.%d.%d\t(%-10u)\t", ip_header[16], ip_header[17], ip_header[18], ip_header[19], udp_packet->dst_ip_addr);
		__INFO("    Dst. Port   : %-5hu \t", (uint16_t)((udp_header[2] << 8) + udp_header[3]));
	#endif

	if(udp_packet->dst_ip_addr == LLS_DST_ADDR && udp_packet->dst_port == LLS_DST_PORT) {
		global_mmt_stats->packet_counter_recv++;
		//process as lls
		lls_table_t* lls = lls_table_create(udp_packet->data, udp_packet->data_length);
		if(lls) {
			global_mmt_stats->lls_parsed_success_counter++;
			lls_dump_instance_table(lls);
			lls_table_free(lls);
		} else {
			global_mmt_stats->lls_parsed_failed_counter++;
			__ERROR("unable to parse LLS table");
		}

		dump_global_mmt_stats();

	} else 	if((dst_ip_addr_filter == NULL && dst_ip_port_filter == NULL) || (udp_packet->dst_ip_addr == *dst_ip_addr_filter && udp_packet->dst_port == *dst_ip_port_filter)) {
		global_mmt_stats->packet_counter_recv++;

		__DEBUG("data len: %d", udp_packet->data_length)
		mmtp_payload_fragments_union_t* mmtp_payload = mmtp_packet_parse(mmtp_sub_flow_vector, udp_packet->data, udp_packet->data_length);

		if(!mmtp_payload) {
			global_mmt_stats->packet_counter_parse_error++;
			__ERROR("mmtp_packet_parse: raw packet ptr is null, parsing failed for flow: %d.%d.%d.%d:(%-10u):%-5hu \t ->  %d.%d.%d.%d\t(%-10u)\t:%-5hu",
					ip_header[12], ip_header[13], ip_header[14], ip_header[15], udp_packet->src_ip_addr,
					(uint16_t)((udp_header[0] << 8) + udp_header[1]),
					ip_header[16], ip_header[17], ip_header[18], ip_header[19], udp_packet->dst_ip_addr,
					(uint16_t)((udp_header[2] << 8) + udp_header[3])
					);
			goto cleanup;
		}

		//dump header, then dump applicable packet type
		mmtp_packet_header_dump(mmtp_payload);

		if(mmtp_payload->mmtp_packet_header.packet_counter != global_mmt_stats->packet_counter_last_value + 1 && global_mmt_stats->packet_counter_last_value) {

			global_mmt_stats->packet_counter_last_gap_gap = mmtp_payload->mmtp_packet_header.packet_counter - global_mmt_stats->packet_counter_last_value;
			__WARN("---Missing packets from %u to %u (total: %u)  ", global_mmt_stats->packet_counter_last_value, mmtp_payload->mmtp_packet_header.packet_counter, global_mmt_stats->packet_counter_last_gap_gap);

			global_mmt_stats->packet_counter_missing += global_mmt_stats->packet_counter_last_gap_gap;
		}

		global_mmt_stats->packet_counter_last_value = mmtp_payload->mmtp_packet_header.packet_counter;
		packet_id_mmt_stats_t* packet_mmt_stats = find_or_get_packet_id(mmtp_payload->mmtp_packet_header.mmtp_packet_id);

		packet_mmt_stats_populate(packet_mmt_stats, mmtp_payload);

		if(mmtp_payload->mmtp_packet_header.mmtp_payload_type == 0x0) {
			global_mmt_stats->packet_counter_mpu++;

			if(mmtp_payload->mmtp_mpu_type_packet_header.mpu_timed_flag == 1) {
				//timed
				//mpu_dump_flow(udp_packet->dst_ip_addr, udp_packet->dst_port, mmtp_payload);
				mpu_dump_reconstitued(udp_packet->dst_ip_addr, udp_packet->dst_port, mmtp_payload);

			} else {
				//non-timed
			}
		} else if(mmtp_payload->mmtp_packet_header.mmtp_payload_type == 0x2) {

			signaling_message_dump(mmtp_payload);
			global_mmt_stats->packet_counter_signaling++;

		} else {
			_MMTP_WARN("mmtp_packet_parse: unknown payload type of 0x%x", mmtp_payload->mmtp_packet_header.mmtp_payload_type);
			goto cleanup;
		}

		dump_global_mmt_stats();

	}

cleanup:

	if(udp_packet->data) {
		free(udp_packet->data);
		udp_packet->data = NULL;
	}

	if(udp_packet) {
		free(udp_packet);
		udp_packet = NULL;
	}
}


#define MAX_PCAP_LEN 1514
/**
 *
 * atsc3_mmt_listener_test interface (dst_ip) (dst_port)
 *
 * arguments:
 */
int main(int argc,char **argv) {

	_MPU_DEBUG_ENABLED = 0;
	_MMTP_DEBUG_ENABLED = 0;
	_LLS_DEBUG_ENABLED = 0;

    char *dev;

    char *dst_ip = NULL;
    char *dst_port = NULL;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;

    //listen to all flows
    if(argc == 2) {
    	dev = argv[1];
	    __DEBUG("listening on dev: %s", dev);
    } else if(argc==4) {
    	//listen
    	dev = argv[1];

    	//todo
    	__DEBUG("listening on dev: %s, dst_ip: %s, dst_port: %s", dev, dst_ip, dst_port);

    } else {
    	println("%s - a udp mulitcast listener test harness for atsc3 mmt messages", argv[0]);
    	println("---");
    	println("args: dev (dst_ip) (dst_port)");
    	println(" dev: device to listen for udp multicast, default listen to 0.0.0.0:0");
    	println(" (dst_ip): optional, filter to specific ip address");
    	println(" (dst_port): optional, filter to specific port");
    	println("");
    	exit(1);
    }
    mmtp_sub_flow_vector = calloc(1, sizeof(mmtp_sub_flow_vector_t));
    mmtp_sub_flow_vector_init(mmtp_sub_flow_vector);

    global_mmt_stats = calloc(1, sizeof(*global_mmt_stats));

    mkdir("mpu", 0777);

    pcap_lookupnet(dev, &netp, &maskp, errbuf);
    descr = pcap_open_live(dev, MAX_PCAP_LEN, 1, 0, errbuf);

    if(descr == NULL) {
        printf("pcap_open_live(): %s",errbuf);
        exit(1);
    }

    char filter[] = "udp";
    if(pcap_compile(descr,&fp, filter,0,netp) == -1) {
        fprintf(stderr,"Error calling pcap_compile");
        exit(1);
    }

    if(pcap_setfilter(descr,&fp) == -1) {
        fprintf(stderr,"Error setting filter");
        exit(1);

    }

    pcap_loop(descr,-1,process_packet,NULL);

    return 0;
}



/* write a packet
//define a new packet and for each position set its values
u_char packet[86];


// Send down the packet
if (pcap_sendpacket(descr, packet, 86) != 0) {

    fprintf(stderr,"Error sending the packet: %s", pcap_geterr(descr));
    return 2;
}
*/
