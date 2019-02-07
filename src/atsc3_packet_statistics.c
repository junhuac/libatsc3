/*
 * atsc3_mmt_packet_statistics.c
 *
 *  Created on: Feb 6, 2019
 *      Author: jjustman
 */

#include "atsc3_listener_udp.h"
#include "atsc3_packet_statistics.h"


int comparator_packet_id_mmt_stats_t(const void *a, const void *b)
{
	__PS_TRACE("comparator_packet_id_mmt_stats_t with %u from %u", ((packet_id_mmt_stats_t *)a)->packet_id, ((packet_id_mmt_stats_t *)b)->packet_id);

	if ( ((packet_id_mmt_stats_t*)a)->packet_id <  ((packet_id_mmt_stats_t*)b)->packet_id ) return -1;
	if ( ((packet_id_mmt_stats_t*)a)->packet_id == ((packet_id_mmt_stats_t*)b)->packet_id ) return  0;
	if ( ((packet_id_mmt_stats_t*)a)->packet_id >  ((packet_id_mmt_stats_t*)b)->packet_id ) return  1;

	return 0;
}


packet_flow_t* find_packet_flow(uint32_t ip, uint16_t port) {
	for(int i=0; i < global_stats->packet_flow_n; i++ ) {
		packet_flow_t* packet_flow = global_stats->packet_flow_vector[i];
		__PS_TRACE("  find_packet_flow with ip: %u, port: %u", ip, port);

		if(packet_flow->ip == ip && packet_flow->port == port) {
			__PS_TRACE("  find_packet_flow returning with %p", packet_flow);

			return packet_flow;
		}
	}
	return NULL;
}

packet_id_mmt_stats_t* find_packet_id(uint32_t ip, uint16_t port, uint32_t packet_id) {
	for(int i=0; i < global_stats->packet_id_n; i++ ) {
		packet_id_mmt_stats_t* packet_mmt_stats = global_stats->packet_id_vector[i];
		__PS_TRACE("  find_packet_id with ip: %u, port: %u, %u", ip, port, packet_id, packet_mmt_stats->packet_id);

		if(packet_mmt_stats->ip == ip && packet_mmt_stats->port == port && packet_mmt_stats->packet_id == packet_id) {
			__PS_TRACE("  find_packet_id returning with %p", packet_mmt_stats);

			return packet_mmt_stats;
		}
	}

	return NULL;
}

packet_id_mmt_stats_t* find_or_get_packet_id(uint32_t ip, uint16_t port, uint32_t packet_id) {
	packet_id_mmt_stats_t* packet_mmt_stats = find_packet_id(ip, port, packet_id);
	if(!packet_mmt_stats) {
		if(global_stats->packet_id_n && global_stats->packet_id_vector) {

			__PS_TRACE("*before realloc to %p, %i, adding %u", global_stats->packet_id_vector, global_stats->packet_id_n, packet_id);

			global_stats->packet_id_vector = realloc(global_stats->packet_id_vector, (global_stats->packet_id_n + 1) * sizeof(packet_id_mmt_stats_t*));
			if(!global_stats->packet_id_vector) {
				abort();
			}

			packet_mmt_stats = global_stats->packet_id_vector[global_stats->packet_id_n++] = calloc(1, sizeof(packet_id_mmt_stats_t));
			if(!packet_mmt_stats) {
				abort();
			}

			//sort after realloc
		    qsort((void**)global_stats->packet_id_vector, global_stats->packet_id_n, sizeof(packet_id_mmt_stats_t**), comparator_packet_id_mmt_stats_t);

		    __PS_TRACE(" *after realloc to %p, %i, adding %u", packet_mmt_stats, global_stats->packet_id_n, packet_id);

		} else {
			global_stats->packet_id_n = 1;
			global_stats->packet_id_vector = calloc(1, sizeof(packet_id_mmt_stats_t*));
			global_stats->packet_id_vector[0] = calloc(1, sizeof(packet_id_mmt_stats_t));

			if(!global_stats->packet_id_vector) {
				abort();
			}

			packet_mmt_stats = global_stats->packet_id_vector[0];
			__PS_TRACE("*calloc %p for %u", packet_mmt_stats, packet_id);
		}
		packet_mmt_stats->ip = ip;
		packet_mmt_stats->port = port;
		packet_mmt_stats->packet_id = packet_id;

		packet_mmt_stats->mpu_stats_timed_sample_interval = 	calloc(1, sizeof(packet_id_mmt_timed_mpu_stats_t));
		packet_mmt_stats->mpu_stats_nontimed_sample_interval = calloc(1, sizeof(packet_id_mmt_nontimed_mpu_stats_t));
		packet_mmt_stats->signalling_stats_sample_interval = 	calloc(1, sizeof(packet_id_signalling_stats_t));

		packet_mmt_stats->mpu_stats_timed_lifetime = 	calloc(1, sizeof(packet_id_mmt_timed_mpu_stats_t));
		packet_mmt_stats->mpu_stats_nontimed_lifetime = calloc(1, sizeof(packet_id_mmt_nontimed_mpu_stats_t));
		packet_mmt_stats->signalling_stats_lifetime = 	calloc(1, sizeof(packet_id_signalling_stats_t));
	}

	return packet_mmt_stats;
}
void atsc3_packet_statistics_mmt_timed_mpu_stats_populate(mmtp_payload_fragments_union_t* mmtp_payload, packet_id_mmt_stats_t* packet_mmt_stats) {
	packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_timed_total++;
	if(packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_sequence_number) {
		packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_sequence_number_last = packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_sequence_number;
	} else {
		packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_sequence_number_last = 0;
	}
	packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_sequence_number = mmtp_payload->mmtp_mpu_type_packet_header.mpu_sequence_number;

	if(packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_fragementation_counter) {
		packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_fragementation_counter_last = packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_fragementation_counter;
	} else {
		packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_fragementation_counter_last = 0;
	}
	packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_fragementation_counter = mmtp_payload->mmtp_mpu_type_packet_header.mpu_fragmentation_counter;

}
void atsc3_packet_statistics_mmt_stats_populate(udp_packet_t* udp_packet, mmtp_payload_fragments_union_t* mmtp_payload) {


	packet_id_mmt_stats_t* packet_mmt_stats = find_or_get_packet_id(udp_packet->dst_ip_addr, udp_packet->dst_port, mmtp_payload->mmtp_packet_header.mmtp_packet_id);

	packet_mmt_stats->packet_counter_sample_interval_processed++;
	packet_mmt_stats->packet_counter_lifetime_processed++;

	//top level flow check from our new mmtp payload packet and our "current" reference packet

	if(packet_mmt_stats->has_packet_sequence_number &&
		mmtp_payload->mmtp_packet_header.packet_sequence_number != packet_mmt_stats->packet_sequence_number + 1) {

		//compute our intra packet gap, remember to add 1 because we have the acnchor packets
		packet_mmt_stats->packet_sequence_number_last_gap = mmtp_payload->mmtp_packet_header.packet_sequence_number - packet_mmt_stats->packet_sequence_number + 1;

		//compute our sample interval gap
		packet_mmt_stats->packet_sequence_number_sample_interval_gap += packet_mmt_stats->packet_sequence_number_last_gap;

		if(packet_mmt_stats->packet_sequence_number_last_gap > packet_mmt_stats->packet_sequence_number_max_gap) {
			packet_mmt_stats->packet_sequence_number_max_gap = packet_mmt_stats->packet_sequence_number_last_gap;
		}

		//add this gap into the total count of mmt packets missing
		packet_mmt_stats->packet_counter_sample_interval_missing += packet_mmt_stats->packet_sequence_number_last_gap;
		packet_mmt_stats->packet_counter_lifetime_missing += packet_mmt_stats->packet_sequence_number_last_gap;
		global_stats->packet_counter_mmtp_packets_missing += packet_mmt_stats->packet_sequence_number_last_gap;

		//push this to our missing packet flow for investigation
		__PS_WARN("packets missing:\t%u.%u.%u.%u:%u\tpacket_id:\t%d\tPSN_from:\t%d\tPSN_to:\t%d\tTotal_missing: %u",
				__toip(packet_mmt_stats),
				packet_mmt_stats->packet_id,
				packet_mmt_stats->packet_sequence_number,
				mmtp_payload->mmtp_packet_header.packet_sequence_number,
				packet_mmt_stats->packet_sequence_number_last_gap);

	}

	//remember, a lot of these values can roll over...

	//if we have a "current" packet sequence number, set it to our last value
	if(packet_mmt_stats->has_packet_sequence_number) {
		packet_mmt_stats->packet_sequence_number_last_value = packet_mmt_stats->packet_sequence_number;
		packet_mmt_stats->has_packet_sequence_number_last_value = true;
	} else {
		packet_mmt_stats->packet_sequence_number_last_value = 0;
	}

	//if we should reset our sample interval packet sequence number, i.e. NOT !packet_mmt_stats->has_packet_sequence_number_sample_interval_start
	if(!packet_mmt_stats->has_packet_sequence_number_sample_interval_start) {
		packet_mmt_stats->packet_sequence_number_sample_interval_start = mmtp_payload->mmtp_packet_header.packet_sequence_number;
		packet_mmt_stats->has_packet_sequence_number_sample_interval_start = true;
	}

	//if we haven't set our lifetime packet sequence number
	if(!packet_mmt_stats->has_packet_sequence_number_lifetime_start) {
		packet_mmt_stats->packet_sequence_number_lifetime_start = mmtp_payload->mmtp_packet_header.packet_sequence_number;
		packet_mmt_stats->has_packet_sequence_number_lifetime_start = true;
	}

	//update our "current" packet sequence number
	packet_mmt_stats->has_packet_sequence_number = true;
	packet_mmt_stats->packet_sequence_number = mmtp_payload->mmtp_packet_header.packet_sequence_number;

	if(packet_mmt_stats->has_timestamp) {
		packet_mmt_stats->has_timestamp_last = true;
		packet_mmt_stats->timestamp_last = packet_mmt_stats->timestamp;
	} else {
		packet_mmt_stats->timestamp_last = 0;
	}

	//set our timestamp
	packet_mmt_stats->timestamp = mmtp_payload->mmtp_packet_header.mmtp_timestamp;
	packet_mmt_stats->has_timestamp = true;

	//keep track of our starting timestamp sample interval for this flow - has_timestamp_sample_interval_start
	if(!packet_mmt_stats->has_timestamp_sample_interval_start) {
		packet_mmt_stats->timestamp_sample_interval_start = mmtp_payload->mmtp_packet_header.mmtp_timestamp;
		if(packet_mmt_stats->timestamp_sample_interval_start) {
			compute_ntp32_to_seconds_microseconds(packet_mmt_stats->timestamp_sample_interval_start, &packet_mmt_stats->timestamp_sample_interval_start_s, &packet_mmt_stats->timestamp_sample_interval_start_us);
			packet_mmt_stats->has_timestamp_sample_interval_start = true;
		} else {
			__PS_WARN("Missing sample start timestamp!");
			packet_mmt_stats->timestamp_sample_interval_start_s = 0;
			packet_mmt_stats->timestamp_sample_interval_start_us = 0;
		}
	}

	//keep track of our starting timestamp lifetime for this flow - has_timestamp_lifetime_start
	if(!packet_mmt_stats->has_timestamp_lifetime_start) {
		packet_mmt_stats->timestamp_lifetime_start = mmtp_payload->mmtp_packet_header.mmtp_timestamp;
		if(packet_mmt_stats->timestamp_lifetime_start) {
			compute_ntp32_to_seconds_microseconds(packet_mmt_stats->timestamp_lifetime_start, &packet_mmt_stats->timestamp_lifetime_start_s, &packet_mmt_stats->timestamp_lifetime_start_us);
			packet_mmt_stats->has_timestamp_lifetime_start = true;
		} else {
			__PS_WARN("Missing sample start timestamp!");
			packet_mmt_stats->timestamp_lifetime_start_s = 0;
			packet_mmt_stats->timestamp_lifetime_start_us = 0;

		}
	}

	//mpu metadata
	if(mmtp_payload->mmtp_packet_header.mmtp_payload_type == 0x0) {

		//assign our timed mpu stats
		if(mmtp_payload->mmtp_mpu_type_packet_header.mpu_timed_flag == 1) {
			atsc3_packet_statistics_mmt_timed_mpu_stats_populate(mmtp_payload, packet_mmt_stats);

		} else {
			//assign our non-timed stats here
			packet_mmt_stats->mpu_stats_nontimed_sample_interval->mpu_nontimed_total++;
		}
	} else if(mmtp_payload->mmtp_packet_header.mmtp_payload_type == 0x2) {
		//assign our signalling stats here
		packet_mmt_stats->signalling_stats_sample_interval->signalling_messages_total++;
	}

	global_stats->packet_id_delta = packet_mmt_stats;
}

int DUMP_COUNTER=0;
int DUMP_COUNTER_2=0;

void atsc3_packet_statistics_dump_global_stats(){
	bool has_output = false;
	DUMP_COUNTER++;
	if(DUMP_COUNTER%50 == 0) {
		struct timeval tNow;
		gettimeofday(&tNow, NULL);
		__PS_CLEAR();
		long long elapsedDurationUs = timediff(tNow, global_stats->program_timeval_start);

		__PS_STATS("-----------------------------------------------------------------------");
		__PS_STATS_G(" Global ATSC 3.0 Packet Counter Statistics:  Elapsed Duration: %-.2fs", elapsedDurationUs / 1000000.0);
		__PS_STATS_G("-----------------------------------------------------------------------");
		__PS_STATS_G(" LLS total packets received  : %'-u", 	global_stats->packet_counter_lls_packets_received);
		__PS_STATS_G(" > parsed good               : %'-u", 	global_stats->packet_counter_lls_packets_parsed);
		__PS_STATS_G(" > parsed error              : %'-u", 	global_stats->packet_counter_lls_packets_parsed_error);
		__PS_STATS_G(" - SLT packets decoded       : %'-u", 	global_stats->packet_counter_lls_slt_packets_parsed);
		__PS_STATS_G("   - SLT updates processed   : %'-u", 	global_stats->packet_counter_lls_slt_update_processed);
		__PS_STATS_G(" MMTP total packets received : %'-u", 	global_stats->packet_counter_mmtp_packets_received);
		__PS_STATS_G(" - type=0x0 MPU              : %'-u", 	global_stats->packet_counter_mmt_mpu);
		__PS_STATS_G("   - timed                   : %'-u", 	global_stats->packet_counter_mmt_timed_mpu);
		__PS_STATS_G("   - non-timed               : %'-u", 	global_stats->packet_counter_mmt_nontimed_mpu);
		__PS_STATS_G(" - type=0x1 Signaling        : %'-u",	global_stats->packet_counter_mmt_signaling);
		__PS_STATS_G(" - type=0x? Other            : %'-u",	global_stats->packet_counter_mmt_unknown);
		__PS_STATS_G(" > parsed errors             : %'-u",	global_stats->packet_counter_mmtp_packets_parsed_error);
		__PS_STATS_G(" > missing packets           : %'-u",	global_stats->packet_counter_mmtp_packets_missing);

		__PS_STATS_G(" ALC total packets received  : %'-u",	global_stats->packet_counter_alc_recv);
		__PS_STATS_G(" > parsed good               : %'-u",	global_stats->packet_counter_alc_packets_parsed);
		__PS_STATS_G(" > parsed errors             : %'-u",	global_stats->packet_counter_alc_packets_parsed_error);
		__PS_STATS_G(" Non ATSC3 Packets           : %'-u",   global_stats->packet_counter_filtered_ipv4);
		__PS_STATS(" -------------------------------------------");
		__PS_STATS_G(" Total Mulicast Packets RX   : %'-u",   global_stats->packet_counter_total_received);
		__PS_STATS(" -------------------------------------------");
	}

	if(DUMP_COUNTER%50==0) {
		//dump flow status
		for(int i=0; i < global_stats->packet_id_n; i++ ) {
			packet_id_mmt_stats_t* packet_mmt_stats = global_stats->packet_id_vector[i];

			double computed_flow_packet_loss = 0;
			if(packet_mmt_stats->packet_counter_lifetime_processed && packet_mmt_stats->packet_counter_lifetime_missing) {
				computed_flow_packet_loss = 100.0* (packet_mmt_stats->packet_counter_lifetime_missing / packet_mmt_stats->packet_counter_lifetime_processed);
			}
			uint16_t seconds;
			uint16_t microseconds;
			compute_ntp32_to_seconds_microseconds(packet_mmt_stats->timestamp, &seconds, &microseconds);

			__PS_STATS_F(" Interval Flow: %u.%u.%u.%u:%u, packet_id: %u, NTP range: %u.%03u to %u.%03u (%-u - %-u)", __toip(packet_mmt_stats),
																													packet_mmt_stats->packet_id,
																													packet_mmt_stats->timestamp_sample_interval_start_s,
																													packet_mmt_stats->timestamp_sample_interval_start_us/100,

																													seconds,
																													microseconds/100,
																													packet_mmt_stats->timestamp_sample_interval_start,
																													packet_mmt_stats->timestamp);
			//__PS_STATS(" --------------------------------------------------");

			//switch between interval and global stats

			//print out ntp sample

			__PS_STATS_F("  packet_sequence_number range: %-u to %-u (0x%08x to 0x%08x)",		packet_mmt_stats->packet_sequence_number_sample_interval_start, 	packet_mmt_stats->packet_sequence_number, packet_mmt_stats->packet_sequence_number_sample_interval_start,	packet_mmt_stats->packet_sequence_number);
			__PS_STATS_F("  packet RX count: %-6d  missing: %-6d  packet seq num gap : %-10d",	packet_mmt_stats->packet_counter_sample_interval_processed, packet_mmt_stats->packet_counter_sample_interval_missing, packet_mmt_stats->packet_sequence_number_sample_interval_gap);
			__PS_STATS_F("  mpu_sequence_number range: %-10u to %-10u (0x%08x to 0x%08x)", 	packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_sequence_number_last, packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_sequence_number_first, packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_sequence_number, packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_sequence_number);
			__PS_STATS_F("  mpu timed_total: %-6d   ",								packet_mmt_stats->mpu_stats_timed_sample_interval->mpu_timed_total); //mfu gap size: %-10d
			//__PS_STATS("   - Flow max mfu gap         : %-10d",	 										packet_mmt_stats->packet_sequence_number_max_gap);
			__PS_STATS_F("  mpu_nontimed_total           : %u", 									packet_mmt_stats->mpu_stats_nontimed_sample_interval->mpu_nontimed_total);
			__PS_STATS_F("  signalling_messages total    : %u", 									packet_mmt_stats->signalling_stats_sample_interval->signalling_messages_total);

			//clear out any sample interval attributes
			packet_mmt_stats->has_timestamp_sample_interval_start = false;
			packet_mmt_stats->packet_sequence_number_sample_interval_gap = 0;
			packet_mmt_stats->packet_sequence_number_sample_interval_start = 0;
			packet_mmt_stats->has_packet_sequence_number_sample_interval_start = false;

			if(DUMP_COUNTER%50 == 0) {

				__PS_STATS_F("  Lifetime NTP range   : %u.%u - %u.%u (%-u to %-u)",		 	packet_mmt_stats->timestamp_lifetime_start_s, packet_mmt_stats->timestamp_lifetime_start_us, seconds, microseconds, packet_mmt_stats->timestamp_lifetime_start, packet_mmt_stats->timestamp);
				__PS_STATS_F("  Total packet_seq_numbers     : %-u - %-u (0x%08x to0x%08x)",	packet_mmt_stats->packet_sequence_number_lifetime_start, packet_mmt_stats->packet_sequence_number_lifetime_start, packet_mmt_stats->packet_sequence_number, packet_mmt_stats->packet_sequence_number);
				__PS_STATS_F("   - Lifetime max sequence gap : %-10d",	 					packet_mmt_stats->packet_sequence_number_max_gap);
				__PS_STATS_F("  Total packets RX             : %u",							packet_mmt_stats->packet_counter_lifetime_processed);
				__PS_STATS_F("  Total missing packets        : %u",							packet_mmt_stats->packet_counter_lifetime_missing);
				__PS_STATS_F("  Loss Percent                 : %f,",							computed_flow_packet_loss);
				__PS_STATS(" --------------------------------------------------");
			}

		}

		__PS_REFRESH();
	}

	//check for any intra status update flow derivations from deltas
//	if(global_stats->packet_id_delta) {
//		packet_id_mmt_stats_t* packet_mmt_stats = global_stats->packet_id_delta;
//		if(packet_mmt_stats->mpu_stats_timed->mpu_sequence_number_last &&
//				(packet_mmt_stats->mpu_stats_timed->mpu_sequence_number_last != packet_mmt_stats->mpu_stats_timed->mpu_sequence_number && packet_mmt_stats->mpu_stats_timed->mpu_fragementation_counter_last != 0)) {
//
//			__PS_WARN(" **mpu sequence gap, packet_id: %u, FROM mpu_sequence:%u, packet_seq_num_last:%u, mpu_frag_counter_last: %d TO mpu_sequence:%u, packet_seq_num:%u, mpu_frag_counter: %u",
//					packet_mmt_stats->packet_id,
//					packet_mmt_stats->mpu_stats_timed->mpu_sequence_number_last,
//					packet_mmt_stats->packet_sequence_number_last_value,
//					packet_mmt_stats->mpu_stats_timed->mpu_fragementation_counter_last,
//					packet_mmt_stats->mpu_stats_timed->mpu_sequence_number,
//					packet_mmt_stats->packet_sequence_number,
//					packet_mmt_stats->mpu_stats_timed->mpu_fragementation_counter);
//
//			has_output=true;
//		}
//	}

	if(has_output) {
		__PS_STATS("");
	}
	//process any gaps or deltas

	global_stats->packet_id_delta = NULL;
}
