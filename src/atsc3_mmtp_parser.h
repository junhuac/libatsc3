/*
 * atsc3_mmtp_parser.h
 *
 *  Created on: Jan 3, 2019
 *      Author: jjustman
 */

#ifndef MODULES_DEMUX_MMT_MMTP_PARSER_H_
#define MODULES_DEMUX_MMT_MMTP_PARSER_H_

#include "atsc3_mmtp_types.h"
#include "atsc3_vector.h"
#include "atsc3_mmtp_ntp32_to_pts.h"
#include "atsc3_mmt_signaling_message.h"

//#include <vlc_common.h>
//#include <vlc_vector.h>

#include <assert.h>
#include <limits.h>

#define MIN_MMTP_SIZE 32
#define MAX_MMTP_SIZE 1514

/**
 *
 * MMTP packet parsing
 *
 *
 * mmtp_packet_parse: parse a full udp datagram into its applicable mmtp_payload_type:
 *
 * 	packet header cast for determining payload type:
 *
 * 		if(mmtp_payload_fragments->mmtp_packet_header.mmtp_payload_type == 0x0) {
 *
 * 	supported types:
 *
 * 		MPU=0x0					mmtp_mpu_type_packet_header
 * 	 	 (mpu_timed_flag==1)	mpu_data_unit_payload_fragments_timed
 * 	 	 (mpu_timed_flag==0)	mpu_data_unit_payload_fragments_nontimed
 *
 * 		signaling message=0x2	mmtp_signalling_message_fragments
 *
 *

 *
 * packet types not supported:
 *
 *		generic_object=0x1 (restricted usage in atsc3 in favor of ROUTE)
 * 		repair_signal=0x3 are not supported
 *
 */


mmtp_payload_fragments_union_t* mmtp_packet_parse(mmtp_sub_flow_vector_t* mmtp_sub_flow_vector, uint8_t* udp_raw_buf, int udp_raw_buf_size);
void mmtp_packet_header_dump(mmtp_payload_fragments_union_t* mmtp_payload_fragments);

/**
 * internal packet handling methods below, you probably don't want to invoke these...
 */


/**
 *
 * calloc our struct
 */

mmtp_payload_fragments_union_t* mmtp_packet_header_allocate_from_raw_packet(block_t *raw_packet);

//returns pointer from udp_raw_buf where we completed header parsing
uint8_t* mmtp_packet_header_parse_from_raw_packet(mmtp_payload_fragments_union_t *mmtp_packet, uint8_t* udp_raw_buf, int udp_raw_buf_size);


//think of this as castable to the base fields as they are the same size layouts
mmtp_payload_fragments_union_t* mmtp_packet_create(block_t * raw_packet,
												uint8_t mmtp_packet_version,
												uint8_t mmtp_payload_type,
												uint16_t mmtp_packet_id,
												uint32_t packet_sequence_number,
												uint32_t packet_counter,
												uint32_t mmtp_timestamp);
/**
 * mmtp sub_flow vector management for re-assembly
 */

void mmtp_sub_flow_vector_init(mmtp_sub_flow_vector_t *mmtp_sub_flow_vector);
//push this to mpu_fragments_vector->all_fragments_vector first,
// 	then re-assign once fragment_type and fragmentation info are parsed
//mpu_sequence_number *SHOULD* only be resolved from the interior all_fragments_vector for tuple lookup
mmtp_sub_flow_t* mmtp_sub_flow_vector_find_packet_id(mmtp_sub_flow_vector_t *vec, uint16_t mmtp_packet_id);
mmtp_sub_flow_t* mmtp_sub_flow_vector_get_or_set_packet_id(mmtp_sub_flow_vector_t *vec, uint16_t mmtp_packet_id);
void mmtp_sub_flow_push_mmtp_packet(mmtp_sub_flow_t *mmtp_sub_flow, mmtp_payload_fragments_union_t *mmtp_packet);


#endif /* MODULES_DEMUX_MMT_MMTP_PARSER_H_ */
