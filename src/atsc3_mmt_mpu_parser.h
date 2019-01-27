/*
 * atsc3_mmt_mpu_parser.h
 *
 *  Created on: Jan 26, 2019
 *      Author: jjustman
 */

#ifndef ATSC3_MMT_MPU_PARSER_H_
#define ATSC3_MMT_MPU_PARSER_H_


#define _MPU_PRINTLN(...) printf(__VA_ARGS__);printf("\n")
#define _MPU_ERROR(...)   printf("%s:%d:ERROR:",__FILE__,__LINE__);_MPU_PRINTLN(__VA_ARGS__);
#define _MPU_WARN(...)    printf("%s:%d:WARN :",__FILE__,__LINE__);_MPU_PRINTLN(__VA_ARGS__);
#define _MPU_INFO(...)    printf("%s:%d:INFO :",__FILE__,__LINE__);_MPU_PRINTLN(__VA_ARGS__);
#define _MPU_DEBUG(...)   printf("%s:%d:DEBUG:",__FILE__,__LINE__);_MPU_PRINTLN(__VA_ARGS__);
#define _MPU_TRACE(...)   printf("%s:%d:TRACE:",__FILE__,__LINE__);_MPU_PRINTLN(__VA_ARGS__);

//packet type=v0/v1 have an upper bound of ~1432
#define UPPER_BOUND_MPU_FRAGMENT_SIZE 1432
#define MPU_REASSEMBLE_MAX_BUFFER 8192000
#define MIN(a,b) (((a)<(b))?(a):(b))


uint8_t* mmt_parse_payload(mmtp_sub_flow_vector_t* mmtp_sub_flow_vector, mmtp_payload_fragments_union_t* mmt_payload, uint8_t* udp_raw_buf, uint8_t udp_raw_buf_size);
void mmtp_sub_flow_mpu_fragments_allocate(mmtp_sub_flow_t* entry);
mpu_data_unit_payload_fragments_t* mpu_data_unit_payload_fragments_find_mpu_sequence_number(mpu_data_unit_payload_fragments_vector_t *vec, uint32_t mpu_sequence_number);
mpu_data_unit_payload_fragments_t* mpu_data_unit_payload_fragments_get_or_set_mpu_sequence_number_from_packet(mpu_data_unit_payload_fragments_vector_t *vec, mmtp_payload_fragments_union_t *mpu_type_packet);

mpu_fragments_t* mpu_fragments_get_or_set_packet_id(mmtp_sub_flow_t* mmtp_sub_flow, uint16_t mmtp_packet_id);
void mpu_fragments_assign_to_payload_vector(mmtp_sub_flow_t* mmtp_sub_flow, mmtp_payload_fragments_union_t* mpu_type_packet);
mpu_fragments_t* mpu_fragments_find_packet_id(mmtp_sub_flow_vector_t *vec, uint16_t mmtp_packet_id);




#endif /* ATSC3_MMT_MPU_PARSER_H_ */
