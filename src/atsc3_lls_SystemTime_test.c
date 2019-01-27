/*
 *
 * atsc3_lls_SystemTime_test.c:  driver for ATSC 3.0 LLS listener over udp
 *
 */

#include "atsc3_lls.h"
#include "xml.h"


#define __UNIT_TEST 1
#ifdef __UNIT_TEST

//system_time_message with packet_id=1
static char* __get_test_system_time_message()	{ return "030100011f8b08089717185c000353797374656d54696d6500358dcb0a82401440f77ec570f77a0b89227c10151428056350cb61bc3e601cc3b966fe7d6eda1e38e744e9b733e243836b7b1bc33a588120abfbb2b5750c2357fe0ed2c48be4ec98baa2ed482c82753134ccef3de2344d8162a7837ea8f199675237d4298787421e433c916997f88cf2258b6b7ec6658020f4380c64f9c1fa56558e3886700b62649df55a993ff3efc5e602a27492158fcbb252c61160e2fd003518c11fb6000000"; }

int test_lls_create_SystemTime_table(char* base64_payload);

int main() {

	test_lls_create_SystemTime_table(__get_test_system_time_message());

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


int test_lls_create_SystemTime_table(char* base64_payload) {

	uint8_t *binary_payload;
	int binary_payload_size;

	__create_binary_payload(base64_payload, &binary_payload, &binary_payload_size);

	lls_table_t* lls = lls_table_create(binary_payload, binary_payload_size);
	if(lls) {
		lls_dump_instance_table(lls);
	} else {
		_LLS_ERROR("test_lls_create_SystemTime_table() - lls_table_t* is NULL");
	}
	return 0;
}




#endif



