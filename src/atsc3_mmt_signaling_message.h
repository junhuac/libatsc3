/*
 * atsc3_mmt_signaling_message.h
 *
 *  Created on: Jan 21, 2019
 *      Author: jjustman
 */

#ifndef MODULES_DEMUX_MMT_ATSC3_MMT_SIGNALING_MESSAGE_H_
#define MODULES_DEMUX_MMT_ATSC3_MMT_SIGNALING_MESSAGE_H_

#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "atsc3_mmtp_types.h"


#define _MMSM_PRINTLN(...) printf(__VA_ARGS__);printf("\n")
#define _MMSM_ERROR(...)   printf("%s:%d:ERROR:",__FILE__,__LINE__);_MMSM_PRINTLN(__VA_ARGS__);
#define _MMSM_WARN(...)    printf("%s:%d:WARN:",__FILE__,__LINE__);_MMSM_PRINTLN(__VA_ARGS__);
#define _MMSM_INFO(...)    printf("%s:%d:INFO:",__FILE__,__LINE__);_MMSM_PRINTLN(__VA_ARGS__);
#define _MMSM_DEBUG(...)   printf("%s:%d:DEBUG:",__FILE__,__LINE__);_MMSM_PRINTLN(__VA_ARGS__);
#define _MMSM_TRACE(...)   printf("%s:%d:TRACE:",__FILE__,__LINE__);_MMSM_PRINTLN(__VA_ARGS__);

/**
 *
 * MPU_timestamp_descriptor message example
 *
0000   62 02 00 23 af b9 00 00 00 2b 4f 2f 00 35 10 58   b..#¯¹...+O/.5.X
0010   a4 00 00 00 00 12 ce 00 3f 12 ce 00 3b 04 01 00   ¤.....Î.?.Î.;...
0020   00 00 00 00 00 00 00 10 11 11 11 11 11 11 11 11   ................
0030   11 11 11 11 11 11 11 11 68 65 76 31 fd 00 ff 00   ........hev1ý.ÿ.
0040   01 5f 90 01 00 00 23 00 0f 00 01 0c 00 00 16 ce   ._....#........Î
0050   df c2 af b8 d6 45 9f ff                           ßÂ¯¸ÖE.ÿ

raw base64 payload:

62020023afb90000002b4f2f00351058a40000000012ce003f12ce003b04010000000000000000101111111111111111111111111111111168657631fd00ff00015f9001000023000f00010c000016cedfc2afb8d6459fff
 *
 */

//signaling message - message id values:

#define PA_message 			0x0000

#define MPI_message_start 	0x0001
#define MPI_message_end	 	0x0010

#define MPT_message_start	0x0011
#define MPT_message_end		0x0020
//		RESERVED			0x0021 ~ 0x01FF

#define	CRI_message			0x0200
#define	DCI_message			0x0201
#define	SSWR_message		0x0202
#define	AL_FEC_message		0x0203
#define	HRBM_message		0x0204
#define	MC_message			0x0205
#define	AC_message			0x0206
#define	AF_message			0x0207
#define	RQF_message			0x0208
#define	ADC_message			0x0209
#define	HRB_removal_message	0x020A
#define	LS_message			0x020B
#define	LR_message			0x020C
#define	NAMF_message		0x020D
#define	LDC_message			0x020E

//Reserved for private use 0x8000 ~ 0xFFFF


//table 58 - asset id descriptor
typedef struct asset_id {
	uint32_t	asset_id_scheme;
	uint32_t	asset_id_length;
	uint8_t*	asset_id_bytes;
} asset_id_t;



//from table 59 - identifier mapping

typedef struct url_length {
	uint16_t	length;
	uint8_t* 	byte;
} url_length_t;

/**
 * identifer mapping:  table 59
 *
 * identifier_type values:
 *
 * 	0x00	identifier of the content is provided as an asset_id
 * 	0x01	a list of URL's that are related togther and share the same packet_id mapping
 * 	0x02	identifier is provided with a regex string used to match urls
 * 	0x03 	provided as a DASH representation@id
 * 	0x04	reserved for private identifiers
 */

typedef struct identifier_mapping {
	uint8_t		identifier_type;

	//if(identifier_type == 0x00)
	asset_id_t 		asset_id;
	//else if type == 0x01

	uint16_t		url_count;
	url_length_t*	url_length_list;

	//else if type == 0x02
	uint16_t		regex_length;
	uint8_t*		regex_byte;

	//else if identifier_type == 0x03
	uint16_t		representation_id_length;
	uint8_t*		representation_id_byte;

	//else
	uint16_t		private_length;
	uint8_t*		private_byte;

} identifier_mapping_t;

typedef struct mp_table_descriptors {
	uint16_t	mp_table_descriptors_length;
	uint8_t*	mp_table_descriptors_byte;
} mp_table_descriptors_t;

typedef struct mmt_package_id {
	uint8_t		mmt_package_id_length;
	uint8_t*	mmt_package_id_byte;
} mmt_package_id_t;

typedef struct mp_table_asset_row {
	identifier_mapping_t identifier_mapping;

	//identifer_mapping()
	uint32_t	asset_type;
	//6 bits reserved
	uint8_t		default_asset_flag;

	uint8_t		asset_clock_relation_flag;
	uint8_t		asset_clock_relation_id;
	//7bits reserved
	uint8_t		asset_timescale_flag;
	uint32_t	asset_timescale;

	//asset_location (
	uint8_t		location_count;
	//mmt_generation_location_info() //?

	//asset_descriptors (
	uint16_t	asset_descriptors_length;
	uint8_t		asset_descriptors_byte;

} mp_table_asset_row_t;

typedef struct mp_table {
	uint8_t					table_id;
	uint8_t					version;
	uint16_t				length;
	//6 bits are reserved
	uint8_t					mp_table_mode;

	//table_id==0x20 || table_id==0x11 - mmt_package_id
	mmt_package_id_t 		mmt_package_id;
	//mp_table_descriptors
	mp_table_descriptors_t 	mp_table_descriptors;

	uint8_t					number_of_assets;
	mp_table_asset_row_t* 	mp_table_asset_row;

} mp_table_t;


typedef struct mpt_message {
	uint16_t	message_id;
	uint8_t		version;
	uint16_t	length;
	mp_table_t  mp_table;

} mpt_message_t;

typedef struct mmt_signaling_message_mpu_tuple {
	uint32_t mpu_sequence_number;
	uint64_t mpu_presentation_time;
} mmt_signaling_message_mpu_tuple_t;

typedef struct mmt_signaling_message_mpu_timestamp_descriptor {
	uint16_t							descriptor_tag;
	uint8_t								descriptor_length;
	uint8_t								mpu_tuple_n; //mpu_tuple_n = descriptor_length/12 = (32+64)/8
	mmt_signaling_message_mpu_tuple_t*	mpu_tuple;
} mmt_signaling_message_mpu_timestamp_descriptor_t;


uint8_t* signaling_message_parse_payload_header(mmtp_payload_fragments_union_t* si_message, uint8_t* udp_raw_buf, uint8_t udp_raw_buf_size);
uint8_t* signaling_message_parse_payload_table(mmtp_payload_fragments_union_t *si_message, uint8_t* udp_raw_buf, uint8_t buf_size);

uint8_t* pa_message_parse(mmtp_payload_fragments_union_t* si_message, uint8_t* udp_raw_buf, uint8_t udp_raw_buf_size);
uint8_t* mpi_message_parse(mmtp_payload_fragments_union_t* si_message, uint8_t* udp_raw_buf, uint8_t udp_raw_buf_size);
uint8_t* mpt_message_parse(mmtp_payload_fragments_union_t* si_message, uint8_t* udp_raw_buf, uint8_t udp_raw_buf_size);

uint8_t* si_message_not_supported(mmtp_payload_fragments_union_t* si_message, uint8_t* udp_raw_buf, uint8_t udp_raw_buf_size);



void signaling_message_dump(mmtp_payload_fragments_union_t* si_message);
void pa_message_dump(mmtp_payload_fragments_union_t* mmtp_payload_fragments);
void mpi_message_dump(mmtp_payload_fragments_union_t* mmtp_payload_fragments);
void mpt_message_dump(mmtp_payload_fragments_union_t* mmtp_payload_fragments);


#endif /* MODULES_DEMUX_MMT_ATSC3_MMT_SIGNALING_MESSAGE_H_ */
