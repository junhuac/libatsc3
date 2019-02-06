/*
 * atsc3_mmt_signaling_message.h
 *
 *  Created on: Jan 21, 2019
 *      Author: jjustman
 */

#include "atsc3_mmtp_types.h"
#include "atsc3_mmtp_parser.h"
#include "atsc3_mmt_signaling_message.h"
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


uint8_t* signaling_message_parse_payload_header(mmtp_payload_fragments_union_t *mmtp_packet, uint8_t* udp_raw_buf, uint8_t udp_raw_buf_size) {

	if(mmtp_packet->mmtp_packet_header.mmtp_payload_type != 0x02) {
		_MMSM_ERROR("signaling_message_parse_payload_header: mmtp_payload_type 0x02 != 0x%x", mmtp_packet->mmtp_packet_header.mmtp_payload_type);
		return NULL;
	}

	uint8_t *raw_buf = udp_raw_buf;
	uint8_t *buf = udp_raw_buf;
	//parse the mmtp payload header for signaling message mode
	uint8_t	mmtp_payload_header[2];
	buf = extract(buf, mmtp_payload_header, 2);

	/* TODO:
	 * f_i: bits 0-1 fragmentation indicator:
	 * 0x00 = payload contains one or more complete signaling messages
	 * 0x01 = payload contains the first fragment of a signaling message
	 * 0x10 = payload contains a fragment of a signaling message that is neither first/last
	 * 0x11 = payload contains the last fragment of a signaling message
	 */

	mmtp_packet->mmtp_signalling_message_fragments.si_fragmentation_indiciator = (mmtp_payload_header[0] >> 6) & 0x03;
	//next 4 bits are 0x0000 reserved
	if((mmtp_payload_header[0] >> 2) & 0xF) {
		_MMTP_ERROR("signaling message mmtp header bits 2-5 are not reserved 0");
	}

	//bit 6 is additional Header
	mmtp_packet->mmtp_signalling_message_fragments.si_additional_length_header = ((mmtp_payload_header[0] >> 1) & 0x1);

	//bit 7 is Aggregation
	mmtp_packet->mmtp_signalling_message_fragments.si_aggregation_flag = (mmtp_payload_header[0] & 0x1);
	mmtp_packet->mmtp_signalling_message_fragments.si_fragmentation_counter = mmtp_payload_header[1];

	if(mmtp_packet->mmtp_signalling_message_fragments.si_aggregation_flag) {
		//read additional MSG_length attribute
		uint8_t	mmtp_aggregation_msg_length[2];
		buf = extract(buf, mmtp_aggregation_msg_length, 2);

		mmtp_packet->mmtp_signalling_message_fragments.si_aggregation_message_length = (mmtp_aggregation_msg_length[0] << 8) | mmtp_aggregation_msg_length[1];
	}


	//create general signaling message format
	uint8_t  message_id_t[2];
	buf = extract(buf, message_id_t, 2);
	uint16_t message_id = (message_id_t[0] << 8) | message_id_t[1];
	mmtp_packet->mmtp_signalling_message_fragments.message_id = message_id;

	uint8_t signaling_version;
	buf = extract(buf, &signaling_version, 1);
	mmtp_packet->mmtp_signalling_message_fragments.version = signaling_version;

	if(message_id != PA_message && !(message_id > MPI_message_start && message_id < MPI_message_end)) {
		uint8_t length[2];
		buf = extract(buf, length, 2);
		mmtp_packet->mmtp_signalling_message_fragments.length = (length[0] << 8) | length[1] ;
	} else {
		uint8_t length[4];
		buf = extract(buf, length, 4);
		mmtp_packet->mmtp_signalling_message_fragments.length = (length[0] << 24) | (length[1] << 16) | (length[2] << 8) | length[3];
	}

	return buf;
}

/**
 * create our concrete (void*) extension or (void*) payload instances
 */
uint8_t* signaling_message_parse_payload_table(mmtp_payload_fragments_union_t *si_message, uint8_t* udp_raw_buf, uint8_t buf_size) {

	if(si_message->mmtp_packet_header.mmtp_payload_type != 0x02) {
		_MMSM_ERROR("signaling_message_parse_payload_header: mmtp_payload_type 0x02 != 0x%x", si_message->mmtp_packet_header.mmtp_payload_type);
		return NULL;
	}

	//if msg_id <= 0x0010 MPI_message || PA_message -> 32 bits

	uint8_t *buf = udp_raw_buf;
	if(si_message->mmtp_signalling_message_fragments.message_id == PA_message) {
		buf = pa_message_parse(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id >= MPI_message_start && si_message->mmtp_signalling_message_fragments.message_id < MPI_message_end) {
		buf = mpi_message_parse(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id >= MPT_message_start && si_message->mmtp_signalling_message_fragments.message_id < MPT_message_end) {
		buf = mpt_message_parse(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == CRI_message) {
		//0x200
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == DCI_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == SSWR_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == AL_FEC_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == HRBM_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == MC_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == AC_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == AF_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == RQF_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == ADC_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == HRB_removal_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == LS_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == LR_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == NAMF_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else if(si_message->mmtp_signalling_message_fragments.message_id == LDC_message) {
		buf = si_message_not_supported(si_message, buf, buf_size);
	} else {
		buf = si_message_not_supported(si_message, buf, buf_size);
	}




	return buf;

}
////parse the mmtp payload header for signaling message mode
//uint8_t	mmtp_payload_header[2];
//buf = extract(buf, mmtp_payload_header, 2);



uint8_t* pa_message_parse(mmtp_payload_fragments_union_t* si_message, uint8_t* udp_raw_buf, uint8_t udp_raw_buf_size) {
	_MMSM_WARN("signalling information message id not supported: 0x%04x", si_message->mmtp_signalling_message_fragments.message_id);

	return NULL;
}
uint8_t* mpi_message_parse(mmtp_payload_fragments_union_t* si_message, uint8_t* buf, uint8_t buf_size) {


	return NULL;
}
uint8_t* mpt_message_parse(mmtp_payload_fragments_union_t* si_message, uint8_t* buf, uint8_t buf_size) {

	mpt_message_t* mpt_message = calloc(1, sizeof(mpt_message_t));

	uint8_t scratch[2];
	buf = extract(buf, scratch, 2);
	mpt_message->message_id = (scratch[0] << 8) | (scratch[1]);
	//if message_id==20 - full message, otherwise subset n-1

	uint8_t scratch_single;
	buf = extract(buf, &scratch_single, 1);
	mpt_message->version = scratch_single;

	buf = extract(buf, scratch, 2);
	mpt_message->length = (scratch[0] << 8) | (scratch[1]);

	si_message->mmtp_signalling_message_fragments.payload = (void*) mpt_message;


	buf = extract(buf, &scratch_single, 1);
	mpt_message->mp_table.table_id = scratch_single;

	buf = extract(buf, &scratch_single, 1);
	mpt_message->mp_table.version = scratch_single;

	buf = extract(buf, scratch, 2);
	mpt_message->mp_table.length = (scratch[0] << 8) | scratch[1];

	buf = extract(buf, &scratch_single, 1);
	if((scratch_single >> 2) != 0x3F) {
	//	_MMSM_WARN("mp_table reserved 6 bits are not set - message_id: 0x%04x, table_id: 0x%02x, packet_counter: %u", si_message->mmtp_signalling_message_fragments.message_id, mpt_message->mp_table.table_id, si_message->mmtp_mpu_type_packet_header.packet_counter);

		goto cleanup;
	}

	//set MP_table_mode
	mpt_message->mp_table.mp_table_mode = scratch_single & 0x2;

	if(mpt_message->mp_table.table_id == 0x20 || mpt_message->mp_table.table_id == 0x11) {
		//process packages & descriptors
		_MMSM_WARN("mp_table processing for mmt_package_id not supported yet!");

		//read mmt_package_id here

	}


	buf = extract(buf, &scratch_single, 1);
	scratch_single = (scratch_single > 255) ? 255 : (scratch_single > 0) ? scratch_single : 0;
	mpt_message->mp_table.number_of_assets = scratch_single;
	mpt_message->mp_table.mp_table_asset_row = calloc(scratch_single, sizeof(mp_table_asset_row_t));
	for(int i=0; i < mpt_message->mp_table.number_of_assets; i++ ) {
		mp_table_asset_row_t* row = &mpt_message->mp_table.mp_table_asset_row[i];

		//grab our identifer mapping
		buf = extract(buf, &scratch_single, 1);
		row->identifier_mapping.identifier_type = scratch_single;
		if(row->identifier_mapping.identifier_type == 0x00) {
			uint8_t asset_id_array[4];

			buf = extract(buf, asset_id_array, 4);
			row->identifier_mapping.asset_id.asset_id_scheme = (asset_id_array[0] << 24) | (asset_id_array[1] << 16) | (asset_id_array[2] << 8) | asset_id_array[3];

			buf = extract(buf, asset_id_array, 4);
			row->identifier_mapping.asset_id.asset_id_length = (asset_id_array[0] << 24) | (asset_id_array[1] << 16) | (asset_id_array[2] << 8) | asset_id_array[3];

			//implicit vuln here:
			row->identifier_mapping.asset_id.asset_id_bytes = calloc((row->identifier_mapping.asset_id.asset_id_length), sizeof(uint8_t));

			for(int i=0; i < row->identifier_mapping.asset_id.asset_id_length; i++) {
				//not the most performant...
				buf = extract(buf, &scratch_single, 1);
				row->identifier_mapping.asset_id.asset_id_bytes[i] = scratch_single;

			}

		} else if(row->identifier_mapping.identifier_type == 0x01) {
			//build url

		}
		uint8_t asset_arr[4];
		buf = extract(buf, asset_arr, 4);
		row->asset_type = (asset_arr[0] << 24) & (asset_arr[1] << 16) & (asset_arr[2] << 8) & asset_arr[3];

	}


cleanup:

	return NULL;
}


uint8_t* si_message_not_supported(mmtp_payload_fragments_union_t* si_message, uint8_t* udp_raw_buf, uint8_t udp_raw_buf_size) {
//	_MMSM_WARN("signalling information message id not supported: 0x%04x", si_message->mmtp_signalling_message_fragments.message_id);

	return NULL;
}


void signaling_message_dump(mmtp_payload_fragments_union_t* mmtp_payload_fragments) {
	if(mmtp_payload_fragments->mmtp_packet_header.mmtp_payload_type != 0x02) {
		_MMSM_ERROR("signaling_message_dump, payload_type 0x%x != 0x02", mmtp_payload_fragments->mmtp_packet_header.mmtp_payload_type);
		return;
	}

	//dump mmtp packet header
	mmtp_packet_header_dump(mmtp_payload_fragments);

	_MMSM_INFO("-----------------");
	_MMSM_INFO("Signaling Message");
	_MMSM_INFO("-----------------");
	/**
	 * dump si payload header fields
	 * 	uint8_t		si_fragmentation_indiciator; //2 bits,
		uint8_t		si_additional_length_header; //1 bit
		uint8_t		si_aggregation_flag; 		 //1 bit
		uint8_t		si_fragmentation_counter;    //8 bits
		uint16_t	si_aggregation_message_length;
	 */
	_MMSM_INFO(" fragmentation_indiciator   : %d", 	mmtp_payload_fragments->mmtp_signalling_message_fragments.si_fragmentation_indiciator);
	_MMSM_INFO(" additional_length_header   : %d", 	mmtp_payload_fragments->mmtp_signalling_message_fragments.si_additional_length_header);
	_MMSM_INFO(" aggregation_flag           : %d",	mmtp_payload_fragments->mmtp_signalling_message_fragments.si_aggregation_flag);
	_MMSM_INFO(" fragmentation_counter      : %d",	mmtp_payload_fragments->mmtp_signalling_message_fragments.si_fragmentation_counter);
	_MMSM_INFO(" aggregation_message_length : %hu",	mmtp_payload_fragments->mmtp_signalling_message_fragments.si_aggregation_message_length);

	_MMSM_INFO("-----------------");
	_MMSM_INFO(" Message ID       : %hu (0x%04x)", 	mmtp_payload_fragments->mmtp_signalling_message_fragments.message_id, mmtp_payload_fragments->mmtp_signalling_message_fragments.message_id);
	_MMSM_INFO(" Version          : %d", 			mmtp_payload_fragments->mmtp_signalling_message_fragments.version);
	_MMSM_INFO(" Length           : %u", 			mmtp_payload_fragments->mmtp_signalling_message_fragments.length);
	_MMSM_INFO("------------------");
	_MMSM_INFO(" Extension        : %p", 			mmtp_payload_fragments->mmtp_signalling_message_fragments.extension);
	_MMSM_INFO(" Payload          : %p", 			mmtp_payload_fragments->mmtp_signalling_message_fragments.payload);
	_MMSM_INFO("------------------");
	_MMSM_INFO("");

	//_MMSM_INFO("--------------------------------------");

	if(mmtp_payload_fragments->mmtp_signalling_message_fragments.message_id == PA_message) {
		pa_message_dump(mmtp_payload_fragments);
	} else if(mmtp_payload_fragments->mmtp_signalling_message_fragments.message_id >= MPI_message_start && mmtp_payload_fragments->mmtp_signalling_message_fragments.message_id < MPI_message_end) {
		mpi_message_dump(mmtp_payload_fragments);
	} else if(mmtp_payload_fragments->mmtp_signalling_message_fragments.message_id >= MPT_message_start && mmtp_payload_fragments->mmtp_signalling_message_fragments.message_id < MPT_message_end) {
		mpt_message_dump(mmtp_payload_fragments);
	}
}

void pa_message_dump(mmtp_payload_fragments_union_t* mmtp_payload_fragments) {

}

void mpi_message_dump(mmtp_payload_fragments_union_t* mmtp_payload_fragments) {

}

void mpt_message_dump(mmtp_payload_fragments_union_t* mmtp_payload_fragments) {

}


