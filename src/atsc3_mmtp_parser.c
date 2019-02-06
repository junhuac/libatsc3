/*
 * mmtp_types.h
 *
 *  Created on: Jan 3, 2019
 *      Author: jjustman
 *
 *
 * parses the header of the MMTP packet, and invokes specific methods for MPU and signaling messages
 */

#include "atsc3_mmtp_types.h"
#include "atsc3_mmtp_parser.h"
#include "atsc3_mmt_mpu_parser.h"
#include "atsc3_mmt_signaling_message.h"

#include <assert.h>
#include <limits.h>
int _MMTP_DEBUG_ENABLED = 1;
int _MMTP_TRACE_ENABLED = 0;

/*
 * MMTP as specified in Clause 9 of ISO/IEC23008-1 [37] shall be used to deliver MPUs. The following constraints shall be applied to MMTP:
   The value of the version field of MMTP packets shall be '01'.
 */

#define _ISO23008_1_MMTP_VERSION_0x00_SUPPORT_ false

/*
 * The value of the packet_id field of MMTP packets shall be between 0x0010 and 0x1FFE for easy conversion of an MMTP stream to an MPEG-2 TS.
 * The value of the packet_id field of MMTP packets for each content component can be randomly assigned, but the value of the packet_id field of
 * MMTP packets carrying two different components shall not be the same in a single MMTP session.
 *
 * See A/331 Section 7.2.3 for exceptions regarding signaling flow for SLS which shall be 0x0000
 */
#define _ATSC3_MMT_PACKET_ID_MPEGTS_COMPATIBILITY_ true

/*
 * The value of ‘0x01’ for the type field of an MMTP packet header shall not be used, i.e. the Generic File Delivery (GFD) mode specified in
 * subclauses 9.3.3 and 9.4.3 of [37] shall not be used.
 *
 * jjustman-2019-02-05 - I think this was a poor choice for real-time interactive object delivery use cases and experiences.
 */
#define _ISO230081_1_MMTP_GFD_SUPPORT_ false

/*
 * Open items:
 *
 *  The value of the timestamp field of an MMTP packet shall represent the UTC time when the first byte of the MMTP packet is passed to the UDP layer and shall be formatted in the “short format” as specified in Clause 6 of RFC 5905, NTP version 4 [23].
 *  The value of the RAP_flag of MMTP packets shall be set to 0 when the value of the FT field is equal to 0.
 */

/**
 *
 * mmtp packet parsing - parse header for struct instantiation
 */


//returns pointer from udp_raw_buf where we completed header parsing
uint8_t* mmtp_packet_header_parse_from_raw_packet(mmtp_payload_fragments_union_t *mmtp_packet, uint8_t* udp_raw_buf, int udp_raw_buf_size) {

	if(udp_raw_buf_size < 20) {
		//bail, the min header is at least 20 bytes
		_MMTP_ERROR("mmtp_packet_header_parse_from_raw_packet, udp_raw_buf size is: %d, need at least 20 bytes", udp_raw_buf_size);
		return NULL;
	}

	uint8_t *raw_buf = udp_raw_buf;
	uint8_t *buf = udp_raw_buf;

	uint8_t mmtp_packet_preamble[20];

	//msg_Warn( p_demux, "buf pos before extract is: %p", (void *)buf);
	buf = extract(buf, mmtp_packet_preamble, 20);

	//A/331 Section 8.1.2.1.3 Constraints on MMTP
	// The value of the version field of MMTP packets shall be '01'.
#if !_ISO23008_1_MMTP_VERSION_0x00_SUPPORT_
	mmtp_packet->mmtp_packet_header.mmtp_packet_version = (mmtp_packet_preamble[0] & 0xC0) >> 6;
	if(mmtp_packet->mmtp_packet_header.mmtp_packet_version != 0x1) {
		_MMTP_ERROR("MMTP version field != 0x1, value is 0x%x, bailing!", mmtp_packet->mmtp_packet_header.mmtp_packet_version);
		goto error;
	}
#endif

	mmtp_packet->mmtp_packet_header.packet_counter_flag = (mmtp_packet_preamble[0] & 0x20) >> 5;
	mmtp_packet->mmtp_packet_header.fec_type = (mmtp_packet_preamble[0] & 0x18) >> 3;

#if _ISO23008_1_MMTP_VERSION_0x00_SUPPORT_

	if(mmtp_packet->mmtp_packet_header.mmtp_packet_version == 0x00) {
		//after fec_type, with v=0, next bitmask is 0x4 >>2
		//0000 0010
		//V0CF E-XR
		mmtp_packet->mmtp_packet_header.mmtp_header_extension_flag = (mmtp_packet_preamble[0] & 0x2) >> 1;
		mmtp_packet->mmtp_packet_header.mmtp_rap_flag = mmtp_packet_preamble[0] & 0x1;

		//6 bits right aligned
		mmtp_packet->mmtp_packet_header.mmtp_payload_type = mmtp_packet_preamble[1] & 0x3f;
		if(mmtp_packet->mmtp_packet_header.mmtp_header_extension_flag & 0x1) {
			mmtp_packet->mmtp_packet_header.mmtp_header_extension_type = (mmtp_packet_preamble[16]) << 8 | mmtp_packet_preamble[17];
			mmtp_packet->mmtp_packet_header.mmtp_header_extension_length = (mmtp_packet_preamble[18]) << 8 | mmtp_packet_preamble[19];
		} else {
			//walk back by 4 bytes
			buf-=4;
		}
	} else

#endif

	if(mmtp_packet->mmtp_packet_header.mmtp_packet_version == 0x01) {
		//bitmask is 0000 00
		//0000 0100
		//V1CF EXRQ
		mmtp_packet->mmtp_packet_header.mmtp_header_extension_flag = mmtp_packet_preamble[0] & 0x4 >> 2; //X
		mmtp_packet->mmtp_packet_header.mmtp_rap_flag = (mmtp_packet_preamble[0] & 0x2) >> 1;				//RAP
		mmtp_packet->mmtp_packet_header.mmtp_qos_flag = mmtp_packet_preamble[0] & 0x1;					//QOS
		//0000 0000
		//FEBI TYPE
		//4 bits for preamble right aligned

		mmtp_packet->mmtp_packet_header.mmtp_flow_identifer_flag = ((mmtp_packet_preamble[1]) & 0x80) >> 7;			//F
		mmtp_packet->mmtp_packet_header.mmtp_flow_extension_flag = ((mmtp_packet_preamble[1]) & 0x40) >> 6;			//E
		mmtp_packet->mmtp_packet_header.mmtp_header_compression = ((mmtp_packet_preamble[1]) &  0x20) >> 5; 		//B
		mmtp_packet->mmtp_packet_header.mmtp_indicator_ref_header_flag = ((mmtp_packet_preamble[1]) & 0x10) >> 4;	//I

		mmtp_packet->mmtp_packet_header.mmtp_payload_type = mmtp_packet_preamble[1] & 0xF;

		//TB 2 bits
		mmtp_packet->mmtp_packet_header.mmtp_type_of_bitrate = ((mmtp_packet_preamble[16] & 0x40) >> 6) | ((mmtp_packet_preamble[16] & 0x20) >> 5);

		//DS 3 bits
		mmtp_packet->mmtp_packet_header.mmtp_delay_sensitivity = ((mmtp_packet_preamble[16] & 0x10) >> 4) | ((mmtp_packet_preamble[16] & 0x8) >> 3) | ((mmtp_packet_preamble[16] & 0x4) >> 2);

		//TP 3 bits
		mmtp_packet->mmtp_packet_header.mmtp_transmission_priority =(( mmtp_packet_preamble[16] & 0x02) << 2) | ((mmtp_packet_preamble[16] & 0x1) << 1) | ((mmtp_packet_preamble[17] & 0x80) >>7);

		mmtp_packet->mmtp_packet_header.flow_label = mmtp_packet_preamble[17] & 0x7f;

		//header extension is offset by 2 bytes in v=1, so an additional block chain read is needed to get extension length
		if(mmtp_packet->mmtp_packet_header.mmtp_header_extension_flag & 0x1) {
			mmtp_packet->mmtp_packet_header.mmtp_header_extension_type = (mmtp_packet_preamble[18] << 8) | mmtp_packet_preamble[19];

			_MMTP_TRACE("mmtp_demuxer - dping mmtp_header_extension_length_bytes: %d",  mmtp_packet->mmtp_packet_header.mmtp_header_extension_type);

			uint8_t mmtp_header_extension_length_bytes[2];
			buf = extract(buf, mmtp_header_extension_length_bytes, 2);

			mmtp_packet->mmtp_packet_header.mmtp_header_extension_length = mmtp_header_extension_length_bytes[0] << 8 | mmtp_header_extension_length_bytes[1];
		} else {
			//walk us back for mmtp payload type header parsing
			buf-=2;
		}
	} else {
		_MMTP_ERROR("mmtp_demuxer - unknown packet version of 0x%X", mmtp_packet->mmtp_packet_header.mmtp_packet_version);
		goto error;
	}

	mmtp_packet->mmtp_packet_header.mmtp_packet_id			= mmtp_packet_preamble[2]  << 8  | mmtp_packet_preamble[3];

#if _ATSC3_MMT_PACKET_ID_MPEGTS_COMPATIBILITY_
	//exception for MMT signaling, See A/331 7.2.3.

	if(!(mmtp_packet->mmtp_packet_header.mmtp_packet_id == 0x0000 && mmtp_packet->mmtp_packet_header.mmtp_payload_type == 0x2)) {
		if(!(mmtp_packet->mmtp_packet_header.mmtp_packet_id >= 0x0010 && mmtp_packet->mmtp_packet_header.mmtp_packet_id <= 0x1FFE)) {
			_MMTP_ERROR("MMTP packet_id is not compliant with A/331 8.1.2.1.3 - MPEG2 conversion compatibility, packet_id: %-10hu (0x%04x)", mmtp_packet->mmtp_packet_header.mmtp_packet_id, mmtp_packet->mmtp_packet_header.mmtp_packet_id);
			goto error;
		}
	}
#endif
	mmtp_packet->mmtp_packet_header.mmtp_timestamp 			= mmtp_packet_preamble[4]  << 24 | mmtp_packet_preamble[5]  << 16 | mmtp_packet_preamble[6]   << 8 | mmtp_packet_preamble[7];
	compute_ntp32_to_seconds_microseconds(mmtp_packet->mmtp_packet_header.mmtp_timestamp, &mmtp_packet->mmtp_packet_header.mmtp_timestamp_s, &mmtp_packet->mmtp_packet_header.mmtp_timestamp_us);

	mmtp_packet->mmtp_packet_header.packet_sequence_number	= mmtp_packet_preamble[8]  << 24 | mmtp_packet_preamble[9]  << 16 | mmtp_packet_preamble[10]  << 8 | mmtp_packet_preamble[11];
	mmtp_packet->mmtp_packet_header.packet_counter 			= mmtp_packet_preamble[12] << 24 | mmtp_packet_preamble[13] << 16 | mmtp_packet_preamble[14]  << 8 | mmtp_packet_preamble[15];

	return buf;

error:
	return NULL;
}


void mmtp_packet_header_dump(mmtp_payload_fragments_union_t* mmtp_payload_fragments) {
	_MMTP_INFO("------------------");
	_MMTP_INFO("MMTP Packet Header");
	_MMTP_INFO("------------------");
	_MMTP_INFO(" packet version         : %-10d (0x%d%d)", mmtp_payload_fragments->mmtp_packet_header.mmtp_packet_version, ((mmtp_payload_fragments->mmtp_packet_header.mmtp_packet_version >> 1) & 0x1), mmtp_payload_fragments->mmtp_packet_header.mmtp_packet_version & 0x1);
	_MMTP_INFO(" payload_type           : %-10d (0x%d%d)", mmtp_payload_fragments->mmtp_packet_header.mmtp_payload_type, ((mmtp_payload_fragments->mmtp_packet_header.mmtp_payload_type >> 1) & 0x1), mmtp_payload_fragments->mmtp_packet_header.mmtp_payload_type & 0x1);
	_MMTP_INFO(" packet_id              : %-10hu (0x%04x)", mmtp_payload_fragments->mmtp_packet_header.mmtp_packet_id, mmtp_payload_fragments->mmtp_packet_header.mmtp_packet_id);
	_MMTP_INFO(" timestamp              : %-10u (0x%08x)", mmtp_payload_fragments->mmtp_packet_header.mmtp_timestamp, mmtp_payload_fragments->mmtp_packet_header.mmtp_timestamp);
	_MMTP_INFO(" packet_sequence_number : %-10u (0x%08x)", mmtp_payload_fragments->mmtp_packet_header.packet_sequence_number,mmtp_payload_fragments->mmtp_packet_header.packet_sequence_number);
	_MMTP_INFO(" packet counter         : %-10u (0x%04x)", mmtp_payload_fragments->mmtp_packet_header.packet_counter, mmtp_payload_fragments->mmtp_packet_header.packet_counter);
	_MMTP_INFO("------------------");
}

mmtp_payload_fragments_union_t* mmtp_packet_parse(mmtp_sub_flow_vector_t* mmtp_sub_flow_vector, uint8_t* udp_raw_buf, int udp_raw_buf_size) {

	mmtp_sub_flow_t *mmtp_sub_flow = NULL;
	uint8_t* raw_packet_ptr = NULL;

	_MMTP_DEBUG("mmtp_packet_parse: udp raw buf size: %d, raw_packet_ptr: %p, udp_raw_buf: %p", udp_raw_buf_size, raw_packet_ptr, udp_raw_buf);

	int i_status = 0;
	mmtp_payload_fragments_union_t* mmtp_payload_fragments = calloc(1, sizeof(mmtp_payload_fragments_union_t));

	raw_packet_ptr = mmtp_packet_header_parse_from_raw_packet(mmtp_payload_fragments, udp_raw_buf, udp_raw_buf_size);

	if(!raw_packet_ptr) {
		_MMTP_ERROR("mmtp_packet_parse: unable to parse MMTP header");
		goto failed;
	}

	mmtp_sub_flow = mmtp_sub_flow_vector_get_or_set_packet_id(mmtp_sub_flow_vector, mmtp_payload_fragments->mmtp_packet_header.mmtp_packet_id);
	mmtp_sub_flow_push_mmtp_packet(mmtp_sub_flow, mmtp_payload_fragments);

	if(mmtp_payload_fragments->mmtp_packet_header.mmtp_payload_type == 0x0) {
		_MMTP_DEBUG("before: mmt_parse_payload: udp raw buf size: %d, raw_packet_ptr: %p, udp_raw_buf: %p", udp_raw_buf_size, raw_packet_ptr, udp_raw_buf);
		int new_size = udp_raw_buf_size - (raw_packet_ptr - udp_raw_buf);

		mmt_parse_payload(mmtp_sub_flow_vector, mmtp_payload_fragments, raw_packet_ptr, new_size);
	} else
#if _ISO230081_1_MMTP_GFD_SUPPORT_
	if(mmtp_payload_fragments->mmtp_packet_header.mmtp_payload_type == 0x1) {
		_MMTP_WARN("MMTP_GFD: not supported for packet_id: %-10hu (0x%04x)", mmtp_payload_fragments->mmtp_packet_header.mmtp_packet_id, mmtp_payload_fragments->mmtp_packet_header.mmtp_packet_id);
		goto failed;
	} else
#endif
	if(mmtp_payload_fragments->mmtp_packet_header.mmtp_payload_type == 0x2) {
		uint8_t new_size = udp_raw_buf_size - (raw_packet_ptr - udp_raw_buf);
		raw_packet_ptr = signaling_message_parse_payload_header(mmtp_payload_fragments, raw_packet_ptr, new_size);

		new_size = udp_raw_buf_size - (raw_packet_ptr - udp_raw_buf);
		raw_packet_ptr = signaling_message_parse_payload_table(mmtp_payload_fragments, raw_packet_ptr, new_size);

	} else {
		_MMTP_WARN("mmtp_packet_parse: unknown payload type of 0x%x for %-10hu (0x%04x)", mmtp_payload_fragments->mmtp_packet_header.mmtp_payload_type,
				mmtp_payload_fragments->mmtp_packet_header.mmtp_packet_id, mmtp_payload_fragments->mmtp_packet_header.mmtp_packet_id);
		goto failed;
	}

	return mmtp_payload_fragments;

failed:
	if(mmtp_payload_fragments) {
		free(mmtp_payload_fragments);
		mmtp_payload_fragments = NULL;
	}
	return NULL;

}


void mmtp_sub_flow_vector_init(mmtp_sub_flow_vector_t *mmtp_sub_flow_vector) {
	__PRINTF_DEBUG("%d:mmtp_sub_flow_vector_init: %p\n", __LINE__, mmtp_sub_flow_vector);
	atsc3_vector_init(mmtp_sub_flow_vector);
	__PRINTF_DEBUG("%d:mmtp_sub_flow_vector_init: %p\n", __LINE__, mmtp_sub_flow_vector);
}

/**

static struct vlc_player_program *
vlc_player_program_vector_FindById(vlc_player_program_vector *vec, int id,
                                   size_t *idx)
{
    for (size_t i = 0; i < vec->size; ++i)
    {
        struct vlc_player_program *prgm = vec->data[i];
        if (prgm->group_id == id)
        {
            if (idx)
                *idx = i;
            return prgm;
        }
    }
    return NULL;
}
**/




mmtp_sub_flow_t* mmtp_sub_flow_vector_find_packet_id(mmtp_sub_flow_vector_t *vec, uint16_t mmtp_packet_id) {
	for (size_t i = 0; i < vec->size; ++i) {
		mmtp_sub_flow_t *mmtp_sub_flow = vec->data[i];

		if (mmtp_sub_flow->mmtp_packet_id == mmtp_packet_id) {
			return mmtp_sub_flow;
		}
	}
	return NULL;
}


mmtp_sub_flow_t* mmtp_sub_flow_vector_get_or_set_packet_id(mmtp_sub_flow_vector_t *vec, uint16_t mmtp_packet_id) {

	mmtp_sub_flow_t *entry = mmtp_sub_flow_vector_find_packet_id(vec, mmtp_packet_id);

	if(!entry) {
		entry = calloc(1, sizeof(mmtp_sub_flow_t));
		entry->mmtp_packet_id = mmtp_packet_id;
		mmtp_sub_flow_mpu_fragments_allocate(entry);
		atsc3_vector_init(&entry->mmtp_generic_object_fragments_vector);
		atsc3_vector_init(&entry->mmtp_signalling_message_fragements_vector);
		atsc3_vector_init(&entry->mmtp_repair_symbol_vector);

		atsc3_vector_push(vec, entry);
	}

	return entry;
}


mmtp_payload_fragments_union_t* mmtp_packet_header_allocate_from_raw_packet(block_t *raw_packet) {
	mmtp_payload_fragments_union_t *entry = NULL;

	//pick the larger of the timed vs. non-timed fragment struct sizes
	entry = calloc(1, sizeof(mmtp_payload_fragments_union_t));

	if(!entry) {
		abort();
	}
	entry->mmtp_packet_header.raw_packet = raw_packet;

	return entry;
}

//think of this as castable to the base fields as they are the same size layouts
mmtp_payload_fragments_union_t* mmtp_packet_create(block_t * raw_packet,
												uint8_t mmtp_packet_version,
												uint8_t mmtp_payload_type,
												uint16_t mmtp_packet_id,
												uint32_t packet_sequence_number,
												uint32_t packet_counter,
												uint32_t mmtp_timestamp) {
	mmtp_payload_fragments_union_t *entry = NULL;

	//pick the larger of the timed vs. non-timed fragment struct sizes
	entry = calloc(1, sizeof(mmtp_payload_fragments_union_t));

	if(!entry) {
		abort();
	}

	entry->mmtp_packet_header.raw_packet = raw_packet;
	entry->mmtp_packet_header.mmtp_packet_version = mmtp_packet_version;
	entry->mmtp_packet_header.mmtp_payload_type = mmtp_payload_type;
	entry->mmtp_packet_header.mmtp_packet_id = mmtp_packet_id;
	entry->mmtp_packet_header.packet_sequence_number = packet_sequence_number;
	entry->mmtp_packet_header.packet_counter = packet_counter;
	entry->mmtp_packet_header.mmtp_timestamp = mmtp_timestamp;

	return entry;
}

void mmtp_sub_flow_push_mmtp_packet(mmtp_sub_flow_t *mmtp_sub_flow, mmtp_payload_fragments_union_t *mmtp_packet) {
	mmtp_packet->mmtp_packet_header.mmtp_sub_flow = mmtp_sub_flow;

	__PRINTF_DEBUG("%d:mmtp_sub_flow_push_mmtp_packet, mmtp_payload_type: 0x%x\n", __LINE__, mmtp_packet->mmtp_packet_header.mmtp_payload_type);
	if(mmtp_packet->mmtp_packet_header.mmtp_payload_type == 0x00) {
		//(mmtp_mpu_type_packet_header_fields_t*
		//defer, we don;'t know enough about the type
		mpu_fragments_t *mpu_fragments = mpu_fragments_get_or_set_packet_id(mmtp_sub_flow, mmtp_packet->mmtp_packet_header.mmtp_packet_id);
		atsc3_vector_push(&mpu_fragments->all_mpu_fragments_vector, mmtp_packet);

	} else if(mmtp_packet->mmtp_packet_header.mmtp_payload_type == 0x01) {
		atsc3_vector_push(&mmtp_sub_flow->mmtp_generic_object_fragments_vector, mmtp_packet);
	} else if(mmtp_packet->mmtp_packet_header.mmtp_payload_type == 0x02) {
		atsc3_vector_push(&mmtp_sub_flow->mmtp_signalling_message_fragements_vector, mmtp_packet);
	} else if(mmtp_packet->mmtp_packet_header.mmtp_payload_type == 0x03) {
		atsc3_vector_push(&mmtp_sub_flow->mmtp_repair_symbol_vector, mmtp_packet);
	}
}




