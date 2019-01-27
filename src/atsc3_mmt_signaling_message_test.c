/*
 *
 * atsc3_mmt_signaling_message_test.c:  driver for MMT signaling message mapping MPU sequence numbers to MPU presentatino time
 *
 */

#include "atsc3_mmtp_types.h"
#include "atsc3_mmtp_parser.h"
#include "atsc3_mmt_signaling_message.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>


#define __UNIT_TEST 1
#ifdef __UNIT_TEST

//system_time_message with packet_id=1
static char* __get_test_mmt_signaling_message_mpu_timestamp_descriptor()	{ return "62020023afb90000002b4f2f00351058a40000000012ce003f12ce003b04010000000000000000101111111111111111111111111111111168657631fd00ff00015f9001000023000f00010c000016cedfc2afb8d6459fff"; }

int test_mmt_signaling_message_mpu_timestamp_descriptor_table(char* base64_payload);

int main() {

	test_mmt_signaling_message_mpu_timestamp_descriptor_table(__get_test_mmt_signaling_message_mpu_timestamp_descriptor());

	return 0;
}



void __create_binary_payload(char *test_payload_base64, uint8_t **binary_payload, int * binary_payload_size) {
	int test_payload_base64_length = strlen(test_payload_base64);
	int test_payload_binary_size = test_payload_base64_length/2;

	uint8_t *test_payload_binary = calloc(test_payload_binary_size, sizeof(uint8_t));

	for (size_t count = 0; count < test_payload_binary_size; count++) {
	        sscanf(test_payload_base64, "%2hhx", &test_payload_binary[count]);
	        test_payload_base64 += 2;
	}

	*binary_payload = test_payload_binary;
	*binary_payload_size = test_payload_binary_size;
}


int test_mmt_signaling_message_mpu_timestamp_descriptor_table(char* base64_payload) {

	uint8_t* binary_payload;
	int binary_payload_size;

	__create_binary_payload(base64_payload, &binary_payload, &binary_payload_size);

	mmtp_payload_fragments_union_t* mmtp_payload_fragments = calloc(1, sizeof(mmtp_payload_fragments_union_t));

	uint8_t* raw_packet_ptr = NULL;
	raw_packet_ptr = mmtp_packet_header_parse_from_raw_packet(mmtp_payload_fragments, binary_payload, binary_payload_size);

	if(!raw_packet_ptr) {
		_MMSM_ERROR("test_mmt_signaling_message_mpu_timestamp_descriptor_table - raw packet ptr is null!");
		return -1;
	}
	uint8_t new_size = binary_payload_size - (raw_packet_ptr - binary_payload);
	raw_packet_ptr = signaling_message_parse_payload_header(mmtp_payload_fragments, raw_packet_ptr, new_size);

	new_size = binary_payload_size - (raw_packet_ptr - binary_payload);
	raw_packet_ptr = signaling_message_parse_payload_table(mmtp_payload_fragments, raw_packet_ptr, new_size);


	signaling_message_dump(mmtp_payload_fragments);



//	lls_table_t* lls = lls_table_create(binary_payload, binary_payload_size);
//	if(lls) {
//		lls_dump_instance_table(lls);
//	} else {
//		_LLS_ERROR("test_lls_create_SystemTime_table() - lls_table_t* is NULL");
//	}
//
	return 0;
}




#endif



