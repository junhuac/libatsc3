/*
 * atsc3_mmt_mpu_parser.c
 *
 *  Created on: Jan 26, 2019
 *      Author: jjustman
 *
 *
 *      do the heavy lifting...
 */


#include "atsc3_mmtp_types.h"
#include "atsc3_mmtp_parser.h"
#include "atsc3_mmt_mpu_parser.h"


uint8_t* mmt_parse_payload(mmtp_sub_flow_vector_t* mmtp_sub_flow_vector, mmtp_payload_fragments_union_t* mmtp_packet_header, uint8_t* udp_raw_buf, uint8_t udp_raw_buf_size) {

	mmtp_sub_flow_t *mmtp_sub_flow = NULL;
	block_t *mmtp_raw_packet_block;

	//resync our buf positions
	uint8_t *raw_buf = udp_raw_buf;
	uint8_t *buf = udp_raw_buf;

	//create a sub_flow with this packet_id
	__LOG_DEBUG( p_demux, "%d:mmtp_demuxer, after mmtp_packet_header_parse_from_raw_packet, mmtp_packet_id is: %d, mmtp_payload_type: 0x%x, packet_counter: %d, remaining len: %d, mmtp_raw_packet_size: %d, buf: %p, raw_buf:%p",
			__LINE__,
			mmtp_packet_header->mmtp_packet_header.mmtp_packet_id,
			mmtp_packet_header->mmtp_packet_header.mmtp_payload_type,
			mmtp_packet_header->mmtp_packet_header.packet_counter,
			(mmtp_raw_packet_size - (buf - raw_buf)),
			mmtp_raw_packet_size,
			buf,
			raw_buf);

	mmtp_sub_flow = mmtp_sub_flow_vector_get_or_set_packet_id(mmtp_sub_flow_vector, mmtp_packet_header->mmtp_packet_header.mmtp_packet_id);
	__LOG_DEBUG( p_demux, "%d:mmtp_demuxer - mmtp_sub_flow is: %p, mmtp_sub_flow->mpu_fragments: %p", __LINE__, mmtp_sub_flow, mmtp_sub_flow->mpu_fragments);

	//push this to
	//if our header extension length is set, then block extract the header extension length, adn we should be at our payload data
	uint8_t *mmtp_header_extension_value = NULL;

	if(mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_flag & 0x1) {
		//clamp mmtp_header_extension_length
		mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_length = MIN(mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_length, 2^16);

		__LOG_DEBUG( p_demux, "mmtp_header_extension_flag, header extension size: %d, packet version: %d, payload_type: 0x%X, packet_id 0x%hu, timestamp: 0x%X, packet_sequence_number: 0x%X, packet_counter: 0x%X",
				mmtp_packet_header->mmtp_packet_header.mmtp_packet_version,
				mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_length,
				mmtp_packet_header->mmtp_packet_header.mmtp_payload_type,
				mmtp_packet_header->mmtp_packet_header.mmtp_packet_id,
				mmtp_packet_header->mmtp_packet_header.mmtp_timestamp,
				mmtp_packet_header->mmtp_packet_header.packet_sequence_number,
				mmtp_packet_header->mmtp_packet_header.packet_counter);

		mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_value = malloc(mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_length);
		//read the header extension value up to the extension length field 2^16
		buf = extract(buf, (uint8_t*)&mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_value, mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_length);
	}

	if(mmtp_packet_header->mmtp_packet_header.mmtp_payload_type == 0x0) {
		//VECTOR:  TODO - refactor this into helper method

		//pull the mpu and frag iformation

		uint8_t mpu_payload_length_block[2];
		uint16_t mpu_payload_length = 0;

		//msg_Warn( p_demux, "buf pos before mpu_payload_length extract is: %p", (void *)buf);
		buf = extract(buf, (uint8_t*)&mpu_payload_length_block, 2);
		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_payload_length = (mpu_payload_length_block[0] << 8) | mpu_payload_length_block[1];
		//__LOG_DEBUG( p_demux, "mmtp_demuxer - doing mpu_payload_length: %hu (0x%X 0x%X)",  mpu_payload_length, mpu_payload_length_block[0], mpu_payload_length_block[1]);

		uint8_t mpu_fragmentation_info;
		//msg_Warn( p_demux, "buf pos before extract is: %p", (void *)buf);
		buf = extract(buf, &mpu_fragmentation_info, 1);

		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragment_type = (mpu_fragmentation_info & 0xF0) >> 4;
		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_timed_flag = (mpu_fragmentation_info & 0x8) >> 3;
		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator = (mpu_fragmentation_info & 0x6) >> 1;
		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_aggregation_flag = (mpu_fragmentation_info & 0x1);

		__LOG_DEBUG( p_demux, "%d:mmtp_demuxer - mmtp packet: mpu_fragmentation_info is: 0x%x, mpu_fragment_type: 0x%x, mpu_timed_flag: 0x%x, mpu_fragmentation_indicator: 0x%x, mpu_aggregation_flag: 0x%x",
					__LINE__,
					mpu_fragmentation_info,
					mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragment_type,
					mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_timed_flag,
					mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator,
					mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_aggregation_flag);



		uint8_t mpu_fragmentation_counter;
		//msg_Warn( p_demux, "buf pos before extract is: %p", (void *)buf);
		buf = extract(buf, &mpu_fragmentation_counter, 1);
		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragmentation_counter = mpu_fragmentation_counter;

		//re-fanagle
		uint8_t mpu_sequence_number_block[4];

		buf = extract(buf, (uint8_t*)&mpu_sequence_number_block, 4);
		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_sequence_number = (mpu_sequence_number_block[0] << 24)  | (mpu_sequence_number_block[1] <<16) | (mpu_sequence_number_block[2] << 8) | (mpu_sequence_number_block[3]);
		__LOG_DEBUG( p_demux, "%d:mmtp_demuxer - mmtp packet: mpu_payload_length: %hu (0x%X 0x%X), mpu_fragmentation_counter: %d, mpu_sequence_number: %d",
				__LINE__,
				mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_payload_length,
				mpu_payload_length_block[0],
				mpu_payload_length_block[1],
				mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragmentation_counter,
				mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_sequence_number);


		mpu_fragments_assign_to_payload_vector(mmtp_sub_flow, mmtp_packet_header);

		//VECTOR: assign data unit payload once parsed, eventually replacing processMpuPacket

		int remainingPacketLen = -1;

		//todo - if FEC_type != 0, parse out source_FEC_payload_ID trailing bits...
		do {
			//pull out aggregate packets data unit length
			int to_read_packet_length = -1;
			//mpu_fragment_type

			//only read DU length if mpu_aggregation_flag=1
			if(mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_aggregation_flag) {
				uint8_t data_unit_length_block[2];
				buf = extract(buf, (uint8_t*)&data_unit_length_block, 2);
				mmtp_packet_header->mmtp_mpu_type_packet_header.data_unit_length = (data_unit_length_block[0] << 8) | (data_unit_length_block[1]);
				to_read_packet_length = mmtp_packet_header->mmtp_mpu_type_packet_header.data_unit_length;
				__LOG_DEBUG(p_demux, "%d:mpu data unit size: %d, mpu_aggregation_flag:1, to_read_packet_length: %d",
						__LINE__, mmtp_packet_header->mmtp_mpu_type_packet_header.data_unit_length, to_read_packet_length);

			} else {
				to_read_packet_length = udp_raw_buf_size - (buf-raw_buf);
				__LOG_DEBUG(p_demux, "%d:skipping data_unit_size: mpu_aggregation_flag:0, raw packet size: %d, buf: %p, raw_buf: %p, to_read_packet_length: %d",
						__LINE__, mmtp_raw_packet_size, buf, raw_buf, to_read_packet_length);
			}

			//if we are MPU metadata or movie fragment metadatas
			if(mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragment_type != 0x2) {
				//read our packet length just as a mpu metadata fragment or movie fragment metadata
				//read our packet length without any mfu
				block_t *tmp_mpu_fragment = block_Alloc(to_read_packet_length);
				__LOG_DEBUG(p_demux, "%d::creating tmp_mpu_fragment, setting block_t->i_buffer to: %d", __LINE__, to_read_packet_length);

				buf = extract(buf, tmp_mpu_fragment->p_buffer, to_read_packet_length);
				tmp_mpu_fragment->i_buffer = to_read_packet_length;

				mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_data_unit_payload = block_Duplicate(tmp_mpu_fragment);



			//	processMpuPacket(p_demux, mmtp_sub_flow, mmtp_packet_header);

				remainingPacketLen = udp_raw_buf_size - (buf - raw_buf);
				//this should only be non-zero if mpu_aggregration_flag=1
				//__LOG_INFO(p_demux, "%d::mpu_fragment_type: %hu, remainingPacketLen: %d", __LINE__, mpu_fragment_type, remainingPacketLen);

			} else {
				//mfu's have time and un-timed additional DU headers, so recalc to_read_packet_len after doing extract
				//we use the du_header field
				//parse data unit header here based upon mpu timed flag

				/**
				* MFU mpu_fragmentation_indicator==1's are prefixed by the following box, need to remove
				*
				aligned(8) class MMTHSample {
				   unsigned int(32) sequence_number;
				   if (is_timed) {

					//interior block is 152 bits, or 19 bytes
					  signed int(8) trackrefindex;
					  unsigned int(32) movie_fragment_sequence_number
					  unsigned int(32) samplenumber;
					  unsigned int(8)  priority;
					  unsigned int(8)  dependency_counter;
					  unsigned int(32) offset;
					  unsigned int(32) length;
					//end interior block

					  multiLayerInfo();
				} else {
						//additional 2 bytes to chomp for non timed delivery
					  unsigned int(16) item_ID;
				   }
				}

				aligned(8) class multiLayerInfo extends Box("muli") {
				   bit(1) multilayer_flag;
				   bit(7) reserved0;
				   if (multilayer_flag==1) {
					   //32 bits
					  bit(3) dependency_id;
					  bit(1) depth_flag;
					  bit(4) reserved1;
					  bit(3) temporal_id;
					  bit(1) reserved2;
					  bit(4) quality_id;
					  bit(6) priority_id;
				   }  bit(10) view_id;
				   else{
					   //16bits
					  bit(6) layer_id;
					  bit(3) temporal_id;
					  bit(7) reserved3;
				} }
				*/

				uint8_t mmthsample_len;
				uint8_t mmthsample_sequence_number[4];

				if(mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_timed_flag) {

				//	uint16_t seconds;
				//	uint16_t microseconds;
					compute_ntp32_to_seconds_microseconds(mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp, &mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp_s, &mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp_us);
					_MPU_INFO("converting mmtp_timestamp: %u to seconds: %hu, microseconds: %hu", mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp, mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp_s, mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp_us);
					//on first init, p_sys->first_pts will always be 0 from calloc
//					uint64_t pts = compute_relative_ntp32_pts(p_sys->first_pts, mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp_s, mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp_us);
//					if(!p_sys->has_set_first_pts) {
//						p_sys->first_pts = pts;
//						p_sys->has_set_first_pts = 1;
//					}

					//build our PTS
					//mmtp_packet_header->mpu_data_unit_payload_fragments_timed.pts = pts;

					//112 bits in aggregate, 14 bytes
					uint8_t timed_mfu_block[14];
					buf = extract(buf, timed_mfu_block, 14);

					mmtp_packet_header->mpu_data_unit_payload_fragments_timed.movie_fragment_sequence_number 	= (timed_mfu_block[0] << 24) | (timed_mfu_block[1] << 16) | (timed_mfu_block[2]  << 8) | (timed_mfu_block[3]);
					mmtp_packet_header->mpu_data_unit_payload_fragments_timed.sample_number				 	  	= (timed_mfu_block[4] << 24) | (timed_mfu_block[5] << 16) | (timed_mfu_block[6]  << 8) | (timed_mfu_block[7]);
					mmtp_packet_header->mpu_data_unit_payload_fragments_timed.offset     					  	= (timed_mfu_block[8] << 24) | (timed_mfu_block[9] << 16) | (timed_mfu_block[10] << 8) | (timed_mfu_block[11]);
					mmtp_packet_header->mpu_data_unit_payload_fragments_timed.priority 							= timed_mfu_block[12];
					mmtp_packet_header->mpu_data_unit_payload_fragments_timed.dep_counter						= timed_mfu_block[13];

					//parse out mmthsample block if this is our first fragment or we are a complete fragment,
					if(mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_indicator == 0 || mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_indicator == 1) {

						//MMTHSample does not subclass box...
						//buf = extract(buf, &mmthsample_len, 1);
						buf = extract(buf, mmthsample_sequence_number, 4);

						uint8_t mmthsample_timed_block[19];
						buf = extract(buf, mmthsample_timed_block, 19);

						//read multilayerinfo
						uint8_t multilayerinfo_box_length[4];
						uint8_t multilayerinfo_box_name[4];
						uint8_t multilayer_flag;

						buf = extract(buf, multilayerinfo_box_length, 4);
						buf = extract(buf, multilayerinfo_box_name, 4);

						buf = extract(buf, &multilayer_flag, 1);

						int is_multilayer = (multilayer_flag >> 7) & 0x01;
						//if MSB is 1, then read multilevel struct, otherwise just pull layer info...
						if(is_multilayer) {
							uint8_t multilayer_data_block[4];
							buf = extract(buf, multilayer_data_block, 4);

						} else {
							uint8_t multilayer_layer_id_temporal_id[2];
							buf = extract(buf, multilayer_layer_id_temporal_id, 2);
						}

						_MPU_INFO("mpu mode (0x02), timed MFU, mpu_fragmentation_indicator: %d, movie_fragment_seq_num: %u, sample_num: %u, offset: %u, pri: %d, dep_counter: %d, multilayer: %d, mpu_sequence_number: %u",
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_indicator,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.movie_fragment_sequence_number,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.sample_number,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.offset,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.priority,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.dep_counter,
							is_multilayer,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mpu_sequence_number);
					} else {
						_MPU_INFO("mpu mode (0x02), timed MFU, mpu_fragmentation_indicator: %d, movie_fragment_seq_num: %u, sample_num: %u, offset: %u, pri: %d, dep_counter: %d, mpu_sequence_number: %u",
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_indicator,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.movie_fragment_sequence_number,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.sample_number,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.offset,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.priority,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.dep_counter,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mpu_sequence_number);
					}
					//end mfu box read

					to_read_packet_length = udp_raw_buf_size - (buf - raw_buf);
				} else {
					uint8_t non_timed_mfu_block[4];
					uint32_t non_timed_mfu_item_id;
					//only 32 bits
					buf = extract(buf, non_timed_mfu_block, 4);
					mmtp_packet_header->mpu_data_unit_payload_fragments_nontimed.non_timed_mfu_item_id = (non_timed_mfu_block[0] << 24) | (non_timed_mfu_block[1] << 16) | (non_timed_mfu_block[2] << 8) | non_timed_mfu_block[3];

					if(mmtp_packet_header->mpu_data_unit_payload_fragments_nontimed.mpu_fragmentation_indicator == 1) {
						//MMTHSample does not subclass box...
						//buf = extract(buf, &mmthsample_len, 1);

						buf = extract(buf, mmthsample_sequence_number, 4);

						uint8_t mmthsample_item_id[2];
						buf = extract(buf, mmthsample_sequence_number, 2);
						//end reading of mmthsample box
					}

					__LOG_DEBUG(p_demux, "mpu mode (0x02), non-timed MFU, item_id is: %zu", mmtp_packet_header->mpu_data_unit_payload_fragments_nontimed.non_timed_mfu_item_id);
					to_read_packet_length = udp_raw_buf_size - (buf - raw_buf);
				}

				__LOG_TRACE( p_demux, "%d:before reading fragment packet: reading length: %d (mmtp_raw_packet_size: %d, buf: %p, raw_buf:%p)",
						__LINE__,
						to_read_packet_length,
						mmtp_raw_packet_size,
						buf,
						raw_buf);

				block_t *tmp_mpu_fragment = block_Alloc(to_read_packet_length);
				//__LOG_INFO(p_demux, "%d::creating tmp_mpu_fragment, setting block_t->i_buffer to: %d", __LINE__, to_read_packet_length);

				buf = extract(buf, tmp_mpu_fragment->p_buffer, to_read_packet_length);
				tmp_mpu_fragment->i_buffer = to_read_packet_length;


				mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_data_unit_payload = block_Duplicate(tmp_mpu_fragment);

				//send off only the CLEAN mdat payload from our MFU
				remainingPacketLen = udp_raw_buf_size - (buf - raw_buf);
				__LOG_TRACE( p_demux, "%d:after reading fragment packet: remainingPacketLen: %d",
										__LINE__,
										remainingPacketLen);

			}

		} while(mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_aggregation_flag && remainingPacketLen>0);
	}

	__LOG_TRACE(p_demux, "%d:demux - return", __LINE__);

	//in case we were a fragmented packet we could run this loop again?
	return buf;
}






void mmtp_sub_flow_mpu_fragments_allocate(mmtp_sub_flow_t* entry) {
	entry->mpu_fragments = calloc(1, sizeof(mpu_fragments_t));
	entry->mpu_fragments->mmtp_sub_flow = entry;

	atsc3_vector_init(&entry->mpu_fragments->all_mpu_fragments_vector);
	atsc3_vector_init(&entry->mpu_fragments->mpu_metadata_fragments_vector);
	atsc3_vector_init(&entry->mpu_fragments->mpu_movie_fragment_metadata_vector);
	atsc3_vector_init(&entry->mpu_fragments->media_fragment_unit_vector);
}



mpu_data_unit_payload_fragments_t* mpu_data_unit_payload_fragments_find_mpu_sequence_number(mpu_data_unit_payload_fragments_vector_t *vec, uint32_t mpu_sequence_number) {
	for (size_t i = 0; i < vec->size; ++i) {
		mpu_data_unit_payload_fragments_t *mpu_fragments = vec->data[i];

		if (mpu_fragments->mpu_sequence_number == mpu_sequence_number) {
			return vec->data[i];
		}
	}
	return NULL;
}


mpu_data_unit_payload_fragments_t* mpu_data_unit_payload_fragments_get_or_set_mpu_sequence_number_from_packet(mpu_data_unit_payload_fragments_vector_t *vec, mmtp_payload_fragments_union_t *mpu_type_packet) {

	mpu_data_unit_payload_fragments_t *entry = mpu_data_unit_payload_fragments_find_mpu_sequence_number(vec, mpu_type_packet->mmtp_mpu_type_packet_header.mpu_sequence_number);
	if(!entry) {
		entry = calloc(1, sizeof(mpu_data_unit_payload_fragments_t));

		entry->mpu_sequence_number = mpu_type_packet->mmtp_mpu_type_packet_header.mpu_sequence_number;
		atsc3_vector_init(&entry->timed_fragments_vector);
		atsc3_vector_init(&entry->nontimed_fragments_vector);
		atsc3_vector_push(vec, entry);
	}

	return entry;
}


//push this to mpu_fragments_vector->all_fragments_vector first,
// 	then re-assign once fragment_type and fragmentation info are parsed
//mpu_sequence_number *SHOULD* only be resolved from the interior all_fragments_vector for tuple lookup
mpu_fragments_t* mpu_fragments_get_or_set_packet_id(mmtp_sub_flow_t* mmtp_sub_flow, uint16_t mmtp_packet_id) {

	mpu_fragments_t *entry = mmtp_sub_flow->mpu_fragments;
	if(!entry) {
		__PRINTF_DEBUG("*** %d:mpu_fragments_get_or_set_packet_id - adding vector: %p, all_fragments_vector is: %p\n",
				__LINE__, entry, entry->all_mpu_fragments_vector);

		mmtp_sub_flow_mpu_fragments_allocate(mmtp_sub_flow);
	}

	return entry;
}

void mpu_fragments_assign_to_payload_vector(mmtp_sub_flow_t* mmtp_sub_flow, mmtp_payload_fragments_union_t* mpu_type_packet) {
	//use mmtp_sub_flow ref, find packet_id, map into mpu/mfu vector
//	mmtp_sub_flow_t mmtp_sub_flow = mpu_type_packet->mpu_

	mpu_fragments_t *mpu_fragments = mmtp_sub_flow->mpu_fragments;
	__PRINTF_TRACE("%d:mpu_fragments_assign_to_payload_vector - mpu_fragments is:, all_mpu_frags_vector.size: %d %p\n", __LINE__, mpu_fragments, mpu_fragments->all_mpu_fragments_vector.size);

	mpu_data_unit_payload_fragments_t *to_assign_payload_vector = NULL;
	if(mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type == 0x00) {
		//push to mpu_metadata fragments vector
		to_assign_payload_vector = mpu_data_unit_payload_fragments_get_or_set_mpu_sequence_number_from_packet(&mpu_fragments->mpu_metadata_fragments_vector, mpu_type_packet);
	} else if(mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type == 0x01) {
		//push to mpu_movie_fragment
		to_assign_payload_vector = mpu_data_unit_payload_fragments_get_or_set_mpu_sequence_number_from_packet(&mpu_fragments->mpu_movie_fragment_metadata_vector, mpu_type_packet);
	} else if(mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type == 0x02) {
		//push to media_fragment
		to_assign_payload_vector = mpu_data_unit_payload_fragments_get_or_set_mpu_sequence_number_from_packet(&mpu_fragments->media_fragment_unit_vector, mpu_type_packet);
	}

	if(to_assign_payload_vector) {
		__PRINTF_TRACE("%d: to_assign_payload_vector, sequence_number: %d, size is: %d\n", __LINE__, mpu_type_packet->mmtp_mpu_type_packet_header.mpu_sequence_number, to_assign_payload_vector->timed_fragments_vector.size);
		if(mpu_type_packet->mmtp_mpu_type_packet_header.mpu_timed_flag) {
			__PRINTF_TRACE("%d:mpu_data_unit_payload_fragments_get_or_set_mpu_sequence_number_from_packet, sequence_number: %d, pushing to timed_fragments_vector: %p", __LINE__, to_assign_payload_vector->mpu_sequence_number, to_assign_payload_vector->timed_fragments_vector);
			atsc3_vector_push(&to_assign_payload_vector->timed_fragments_vector, mpu_type_packet);
		} else {
			atsc3_vector_push(&to_assign_payload_vector->nontimed_fragments_vector, mpu_type_packet);
		}

	}
}

mpu_fragments_t* mpu_fragments_find_packet_id(mmtp_sub_flow_vector_t *vec, uint16_t mmtp_packet_id) {
	mmtp_sub_flow_t *entry = mmtp_sub_flow_vector_find_packet_id(vec, mmtp_packet_id);
	if(entry) {
		return entry->mpu_fragments;
	}

	return NULL;
}
