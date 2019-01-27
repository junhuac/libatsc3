/*
 *
 * atsc3_llt.c:  driver for ATSC 3.0 LLS listener over udp
 *
 */

#include "atsc3_lls.h"
#include "xml.h"


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


//endian warning, don't try and cast unless you mask..
typedef struct alp_packet_header  {
	uint8_t packet_type;
	uint8_t payload_configuration;
	uint8_t header_mode;
	uint8_t length;

} alp_packet_header_t;

typedef struct lmt_table_header {
	uint8_t num_PLPs_minus1;		/**< LCT version number */
	uint8_t reserved;	/**< congestion control flag */

} lmt_table_header_t;

typedef struct lmt_table_plp {
	uint8_t PLP_ID;			/**jdj-2019-01-07  -    Protocol-Specific Indication (PSI): 2 bits **/
	uint8_t	reserved;
	uint8_t num_multicasts;
} lmt_table_plp_t;

typedef struct lmt_table_multicast {
	uint32_t		src_ip_add;
	uint32_t		dst_ip_add;
	uint16_t		src_udp_port;
	uint16_t		dst_udp_port;
	uint8_t 		sid_flag:1;
	uint8_t 		compressed_flag:1;
	uint8_t			reserved:6;
	/*
	 * optional char if sid_flag==1
	 	 unsigned char	SID;
	   optional char if compressed_flag==1
		unsigned char	context_id;
	 *
	 */
} lmt_table_multicast_t;

/**
After base64 decoding the values returned include the entire ALP packet including the 2
byte ALP header, the ‘Additional Header Values for LMT’ as described in A330 Table 7.1
and the the actual LMT table as described in A330 Table 7.2.
 */
//redzone lmt table: { "0": { "plp_id": 0, "lmt": "gCoB//8cDwMDA8CoOz7gABc8E0kTST8AAAAA7/8BAQAAwAA/AAAAAO//AQIAAMABPw==\n" } }
//converted to base64:
static char *__get_test_lmt() { return "802a01ffff1c0f030303c0a83b3ee000173c134913493f00000000efff01010000c0003f00000000efff01020000c0013f";}

int main() {

	uint8_t *binary_payload;
	int binary_payload_size;

	__create_binary_payload(__get_test_lmt(), &binary_payload, &binary_payload_size);
	uint8_t *binary_payload_start = binary_payload;

	printf("LMT (link_mapping_table) dump\n");
	printf("-----------------------------\n");
	printf("base64 LMT: %s\n", __get_test_lmt());
	printf("-----------------------------\n");

	uint8_t alp_packet_header_byte_1 = *binary_payload++;
	uint8_t alp_packet_header_byte_2 = *binary_payload++;

	alp_packet_header_t alp_packet_header;
	alp_packet_header.packet_type = (alp_packet_header_byte_1 >> 5) & 0x7;
	alp_packet_header.payload_configuration = (alp_packet_header_byte_1 >> 4) & 0x1;
	alp_packet_header.header_mode = (alp_packet_header_byte_1 >> 3) & 0x01;
	alp_packet_header.length = (alp_packet_header_byte_1 & 0x7) << 8 | alp_packet_header_byte_2;

	printf("ALP packet type: : 0x%x (should be 0x4 - x100 - LLP signaling packet)\n", alp_packet_header.packet_type);
	printf("payload config   : %d\n", alp_packet_header.payload_configuration);
	printf("header mode      : %d\n", alp_packet_header.header_mode);
	printf("ALP header length: %d\n", alp_packet_header.length);
	printf("-----------------------------\n");

	//a/330 table 5.3
	if(alp_packet_header.payload_configuration == 0 && alp_packet_header.header_mode == 0) {
		//no additional header size
		printf(" no additional ALP header bytes\n");

	} else if (alp_packet_header.payload_configuration == 0 && alp_packet_header.header_mode == 1) {
		//one byte additional header
		uint8_t alp_additional_header_byte_1 = *binary_payload+=1;
		printf(" one additional ALP header byte: 0x%x\n", alp_additional_header_byte_1);
	} else if (alp_packet_header.payload_configuration == 1) {
		uint8_t alp_additional_header_byte_1 = *binary_payload+=1;
		printf(" one additional header byte -  0x%x\n", alp_additional_header_byte_1);
	}
	printf("-----------------------------\n");

	/**
	 * 5.10 additional header for signaling:
signaling_information_hdr() {
	signaling_type 				8 uimsbf
	signaling_type_extension 	16 bslbf
	signaling_version 			8 uimsbf
	signaling_format 			2 uimsbf
	signaling_encoding 			2 uimsbf
	reserved 					4 ‘1111’

	---40 bits total = 5 bytes
}
	 */

	uint8_t *signaling_information_hdr_bytes = binary_payload;
	binary_payload+=5;
	printf("signaling information header:\n");
	printf("signaling type           : %d (should be 0x1)\n", signaling_information_hdr_bytes[0]);
	printf("signaling type extension : 0x%x 0x%x (should be 0xFF 0xFF)\n", signaling_information_hdr_bytes[1], signaling_information_hdr_bytes[2]);
	printf("signaling version        : %d\n", signaling_information_hdr_bytes[3]);
	printf("signaling format         : 0x%x (should be 0)\n", (signaling_information_hdr_bytes[4] >> 6) &0x3);
	printf("signaling extension      : 0x%x (should be 0)\n", (signaling_information_hdr_bytes[4] >> 4) &0x3);
	printf("reserved                 : 0x%x (should be 0xF - 1111)\n", signaling_information_hdr_bytes[4] &0xF);
	printf("-----------------------------\n");

	uint8_t lmt_table_byte = *binary_payload++;
	//printf("lmt_table_byte: 0x%x\n", lmt_table_byte);
	lmt_table_header_t lmt_table_header;
	lmt_table_header.num_PLPs_minus1 = (lmt_table_byte >> 2) & 0x3F;
	lmt_table_header.reserved = (lmt_table_byte) & 0x3;
	printf("lmt table:\n");
	printf("num_PLPs_minus1: 0x%x (%d - should be 0)\n", lmt_table_header.num_PLPs_minus1, lmt_table_header.num_PLPs_minus1);
	printf("reserved bits  : 0x%x (should be hex:0x3 - xxxx xx11)\n", lmt_table_header.reserved);
	printf("-----------------------------\n");

	; //move one byte

	for(int i=0; i <= lmt_table_header.num_PLPs_minus1; i++) {
		uint8_t lmt_table_plp_byte = *binary_payload++;
		uint8_t lmt_table_plp_byte_2 = *binary_payload++;

		//printf("lmt bytes: 0x%x 0x%x", lmt_table_plp_byte, lmt_table_plp_byte_2);
		lmt_table_plp_t lmt_table_plp;
		lmt_table_plp.PLP_ID = (lmt_table_plp_byte >> 2) & 0x3F;
		lmt_table_plp.reserved = lmt_table_plp_byte & 0x3;
		lmt_table_plp.num_multicasts = lmt_table_plp_byte_2;

		printf("plp row:\n");
		printf("plp id        : 0x%x\n", lmt_table_plp.PLP_ID);
		printf("reserved bits : 0x%x (should be hex:0x3 - xxxx xx11)\n", lmt_table_plp.reserved);
		printf("num_multicasts: 0x%x (%d)\n", lmt_table_plp.num_multicasts, lmt_table_plp.num_multicasts);
		printf("-------------------------\n");

		for(int j=0; j < lmt_table_plp.num_multicasts; j++) {
			if(binary_payload - binary_payload_start >= binary_payload_size) {
				printf("----LMT PLP underflow!\n\n");
				exit(1);
			}
			lmt_table_multicast_t lmt_table_multicast;

			uint8_t *lmt_table_plp_byte = binary_payload;

			lmt_table_multicast.src_ip_add = (lmt_table_plp_byte[0] << 24) | (lmt_table_plp_byte[1] << 16) | (lmt_table_plp_byte[2] << 8) | lmt_table_plp_byte[3];
			lmt_table_multicast.dst_ip_add = (lmt_table_plp_byte[4] << 24) | (lmt_table_plp_byte[5] << 16) | (lmt_table_plp_byte[6] << 8) | lmt_table_plp_byte[7];
			lmt_table_multicast.src_udp_port = (lmt_table_plp_byte[8] << 8) | lmt_table_plp_byte[9];
			lmt_table_multicast.dst_udp_port = (lmt_table_plp_byte[10] << 8) | lmt_table_plp_byte[11];
			lmt_table_multicast.sid_flag = (lmt_table_plp_byte[12] >> 7) & 0x1;
			lmt_table_multicast.compressed_flag = (lmt_table_plp_byte[12] >> 6) & 0x1;
			lmt_table_multicast.reserved = lmt_table_plp_byte[12] & 0x3f;

			printf("Multicast Entry #%d\n", j);
			printf("src_ip_add     : %d.%d.%d.%d\n", (lmt_table_multicast.src_ip_add >> 24) & 0xFF, (lmt_table_multicast.src_ip_add >> 16) & 0xFF, (lmt_table_multicast.src_ip_add >> 8) & 0xFF, lmt_table_multicast.src_ip_add & 0xFF);
			printf("dst_ip_add     : %d.%d.%d.%d\n", (lmt_table_multicast.dst_ip_add >> 24) & 0xFF, (lmt_table_multicast.dst_ip_add >> 16) & 0xFF, (lmt_table_multicast.dst_ip_add >> 8) & 0xFF, lmt_table_multicast.dst_ip_add & 0xFF);
			printf("src_udp_port   : %d (0x%x 0x%x)\n", lmt_table_multicast.src_udp_port, (lmt_table_multicast.src_udp_port >> 8) & 0xFF, lmt_table_multicast.src_udp_port & 0xFF);
			printf("dst_udp_port   : %d (0x%x 0x%x)\n", lmt_table_multicast.dst_udp_port, (lmt_table_multicast.dst_udp_port >> 8) & 0xFF, lmt_table_multicast.dst_udp_port & 0xFF);
			printf("sid_flag       : 0x%x\n", lmt_table_multicast.sid_flag);
			printf("compressed_flag: 0x%x\n", lmt_table_multicast.compressed_flag);
			printf("reserved bits  : 0x%x (should be 0x3f - xx111111) \n", lmt_table_multicast.reserved);
			binary_payload+=13; 	//move 13bytes=104bits=32+32+16+16+1+1+6

			if(lmt_table_multicast.sid_flag == 1) {
				uint8_t sid = *binary_payload++;
				printf("sid            : 0x%x\n", sid);
			}

			if(lmt_table_multicast.compressed_flag == 1) {
				uint8_t context_id = *binary_payload++;
				printf("context_id     : 0x%x\n", context_id);
			}

			printf("-------------------------\n");

		}
	}

	return 0;
}
