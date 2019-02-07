/*
 * atsc3_mmt_packet_statistics.h
 *
 *  Created on: Feb 6, 2019
 *      Author: jjustman
 */

#include <time.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <stdbool.h>
#include <unistd.h>
#include <locale.h>
#include "output_statistics_ncurses.h"

#include "atsc3_utils.h"
#include "atsc3_lls.h"
#include "atsc3_mmtp_types.h"

#ifndef ATSC3_MMT_PACKET_STATISTICS_H_
#define ATSC3_MMT_PACKET_STATISTICS_H_



#ifndef __PKT_STATS_NCURSES
#define __PS_REFRESH()
#define __PS_CLEAR()
#define __PS_STATS(...)   printf("%s:%d: ","pkt_stats",__LINE__);__PRINTLN(__VA_ARGS__);
#define __PS_STATS_G(...) __PS_STATS(__VA_ARGS__);
#define __PS_STATS_F(...) __PS_STATS(__VA_ARGS__);
#define __PS_STATS_L(...) fprintf( stderr, __VA_ARGS__);fprintf( stderr, "\n");
//__PS_STATS(__VA_ARGS__);
#define	__PS_REFRESH_L();

#define __PS_STATSL(...)  printf("%s:%d: ","pkt_stats",__LINE__);printf(__VA_ARGS__);
#define __PS_STATSC(...)  printf(__VA_ARGS__);
#define __PS_STATSN(...)  __PRINTLN(__VA_ARGS__);

#define __PS_ERROR(...)   printf("%s:%d:ERROR :","pkt_stats",__LINE__);__PRINTLN(__VA_ARGS__);
#define __PS_WARN(...)    printf("%s:%d:WARN: ","pkt_stats",__LINE__);__PRINTLN(__VA_ARGS__);
#define __PS_INFO(...)    printf("%s:%d: ",__FILE__,__LINE__);__PRINTLN(__VA_ARGS__);
#endif

#ifdef _ENABLE_DEBUG
#define __PS_DEBUG(...)   printf("%s:%d:DEBUG: ",__FILE__,__LINE__);__PRINTLN(__VA_ARGS__);
#define __PS_DEBUGF(...)  printf("%s:%d:DEBUG: ",__FILE__,__LINE__);__PRINTF(__VA_ARGS__);
#define __PS_DEBUGA(...) 	__PRINTF(__VA_ARGS__);
#define __PS_DEBUGN(...)  __PRINTLN(__VA_ARGS__);
#else
#define __PS_DEBUG(...)
#define __PS_DEBUGF(...)
#define __PS_DEBUGA(...)
#define __PS_DEBUGN(...)
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
#define __PS_TRACE(...)
#endif
typedef struct packet_id_mpu_stats {
	uint32_t mpu_sequence_number;
	uint8_t  mpu_fragementation_counter;

	uint32_t mpu_sequence_number_last;
	uint8_t  mpu_fragementation_counter_last;

	uint32_t mpu_sequence_number_first;
	uint8_t  mpu_fragementation_counter_first;


	uint32_t mpu_timed_total;

} packet_id_mmt_timed_mpu_stats_t;

typedef struct packet_id_mpu_stats_nontimed {
	uint32_t mpu_nontimed_total;

} packet_id_mmt_nontimed_mpu_stats_t;

typedef struct packet_id_signalling_stats {

	uint32_t signalling_messages_total;

	uint32_t mmt_atsc3_message_count;
	uint16_t mmt_atsc3_message_id;
	uint16_t mmt_atsc3_message_content_type;

} packet_id_signalling_stats_t;

typedef struct packet_id_missing {
	uint32_t packet_sequence_number_present_oldest;
	uint32_t timestamp_oldest;
	uint32_t packet_sequence_number_missing_oldest;
	uint32_t packet_sequence_number_missing_newest;
	uint32_t packet_sequence_number_present_newest;
	uint32_t timestamp_newest;
	uint32_t missing_count;
} packet_id_missing_t;

//remember, many of these values can roll over
//needed: uint33_t for nullables :)
typedef struct packet_id_mmt_stats {
	uint32_t ip;
	uint16_t port;
	uint32_t packet_id;

	bool	 has_timestamp;
	uint32_t timestamp;

	bool	 has_timestamp_sample_interval_start;
	uint32_t timestamp_sample_interval_start;
	uint16_t timestamp_sample_interval_start_s;
	uint16_t timestamp_sample_interval_start_us;

	bool	 has_timestamp_lifetime_start;
	uint32_t timestamp_lifetime_start;
	uint16_t timestamp_lifetime_start_s;
	uint16_t timestamp_lifetime_start_us;

	bool	 has_timestamp_last;
	uint32_t timestamp_last;	//compute packet variance here

	bool	 has_packet_sequence_number;
	uint32_t packet_sequence_number;

	bool	 has_packet_sequence_number_last_value;
	uint32_t packet_sequence_number_last_value;

	bool	 has_packet_sequence_number_sample_interval_start;
	uint32_t packet_sequence_number_sample_interval_start;

	bool	 has_packet_sequence_number_lifetime_start;
	uint32_t packet_sequence_number_lifetime_start;

	uint32_t packet_sequence_number_last_gap;		//the gap intra packet_id
	uint32_t packet_sequence_number_sample_interval_gap;	//the gap between dump_stats flows
	uint32_t packet_sequence_number_max_gap;

	uint32_t packet_sequence_number_sample_interval_processed;
	uint32_t packet_sequence_number_sample_interval_missing;

	uint32_t packet_sequence_number_lifetime_processed;
	uint32_t packet_sequence_number_lifetime_missing;

	packet_id_mmt_timed_mpu_stats_t* 		mpu_stats_timed_sample_interval;
	packet_id_mmt_nontimed_mpu_stats_t* 	mpu_stats_nontimed_sample_interval;
	packet_id_signalling_stats_t* 			signalling_stats_sample_interval;

	packet_id_mmt_timed_mpu_stats_t* 		mpu_stats_timed_lifetime;
	packet_id_mmt_nontimed_mpu_stats_t* 	mpu_stats_nontimed_lifetime;
	packet_id_signalling_stats_t* 			signalling_stats_lifetime;

	uint32_t	packet_counter_value;
	int						packet_id_missing_n;
	packet_id_missing_t**	packet_id_missing_vector;

} packet_id_mmt_stats_t;

typedef struct packet_flow {
	uint32_t ip;
	uint16_t port;
	uint32_t packet_counter;

	uint32_t packet_counter_sample_interval_processed;
	uint32_t packet_counter_lifetime_processed;


	int	packet_id_n;
	packet_id_mmt_stats_t* packet_id_vector;
} packet_flow_t;
/*
 *
 * todo: capture these on a mmtp flow
 * uint32_t packet_counter;
	uint32_t packet_counter_last_value;
	uint32_t packet_counter_parse_error;
	uint32_t packet_counter_last_gap_gap;
	uint32_t packet_counter_max_gap_gap;
	uint32_t packet_counter_missing;
	uint32_t packet_counter_totalf
 */

/*
 * also capture ALC flow tsi information
 */
typedef struct global_mmt_stats {

	uint32_t packet_counter_lls_packets_received;
	uint32_t packet_counter_lls_packets_parsed;
	uint32_t packet_counter_lls_packets_parsed_error;
	uint32_t packet_counter_lls_slt_packets_parsed;
	uint32_t packet_counter_lls_slt_update_processed;

	uint32_t packet_counter_mmtp_packets_received;
	uint32_t packet_counter_mmtp_packets_parsed_error;
	sig_atomic_t packet_counter_mmtp_packets_missing;
	uint32_t packet_counter_mmt_mpu;
	uint32_t packet_counter_mmt_timed_mpu;
	uint32_t packet_counter_mmt_nontimed_mpu;
	uint32_t packet_counter_mmt_signaling;
	uint32_t packet_counter_mmt_unknown;

	int packet_flow_n;
	packet_flow_t** packet_flow_vector;

	int	packet_id_n;
	packet_id_mmt_stats_t** packet_id_vector;
	packet_id_mmt_stats_t* packet_id_delta;

	uint32_t packet_counter_alc_recv;
	uint32_t packet_counter_alc_packets_parsed;
	uint32_t packet_counter_alc_packets_parsed_error;

	uint32_t packet_counter_filtered_ipv4;

	uint32_t packet_counter_total_received;

	struct timeval program_timeval_start;
} global_mmt_stats_t;

global_mmt_stats_t* global_stats;

packet_id_mmt_stats_t* find_packet_id(uint32_t ip, uint16_t port, uint32_t packet_id);
packet_id_mmt_stats_t* find_or_get_packet_id(uint32_t ip, uint16_t port, uint32_t packet_id);

void atsc3_packet_statistics_dump_global_stats();
void atsc3_packet_statistics_mmt_stats_populate(udp_packet_t* udp_packet, mmtp_payload_fragments_union_t* mmtp_payload);

#endif /* ATSC3_MMT_PACKET_STATISTICS_H_ */
