/*
 * mmtp_types.h
 *
 *  Created on: Jan 3, 2019
 *      Author: jjustman
 */

#ifndef MODULES_DEMUX_MMT_MMTP_TYPES_H_
#define MODULES_DEMUX_MMT_MMTP_TYPES_H_

#include "atsc3_vector.h"
#include "atsc3_mmtp_ntp32_to_pts.h"
//#include <vlc_common.h>
//#include <vlc_vector.h>

#include <assert.h>
#include <limits.h>

//#include "libmp4.h"
//#include "mp4.h"

#define _MMTP_PRINTLN(...) printf(__VA_ARGS__);printf("\n")
#define _MMTP_ERROR(...)   printf("%s:%d:ERROR:",__FILE__,__LINE__);_MMTP_PRINTLN(__VA_ARGS__);
#define _MMTP_WARN(...)    printf("%s:%d:WARN:",__FILE__,__LINE__);_MMTP_PRINTLN(__VA_ARGS__);
#define _MMTP_INFO(...)    //printf("%s:%d:INFO ",__FILE__,__LINE__);_MMTP_PRINTLN(__VA_ARGS__);

#define _MMTP_DEBUG(...)   if(_MMTP_DEBUG_ENABLED) { printf("%s:%d:DEBUG :",__FILE__,__LINE__);_MMTP_PRINTLN(__VA_ARGS__); }
//logging hack to quiet output....
//#define _MMTP_DEBUG(...)
//#define _MMTP_DEBUG(...)

#define __LOG_MPU_REASSEMBLY(...)

#define __LOG_DEBUG(...)
//(msg_Info(__VA_ARGS__))
#define __LOG_TRACE(...)
#define __PRINTF_DEBUG(...)
//(printf(__VA_ARGS__))
#define __PRINTF_TRACE(...)



#define MIN_MMTP_SIZE 32
#define MAX_MMTP_SIZE 1514

//packet type=v0/v1 have an upper bound of ~1432
#define UPPER_BOUND_MPU_FRAGMENT_SIZE 1432

//
#define MPU_REASSEMBLE_MAX_BUFFER 8192000

/**
 *
 * these sizes aren't bit-aligned to the 23008-1 spec, but they are right-shifted to LSB values
 *
 */

/**
 * base mmtp_packet_header fields
 *
 * clang doesn't know how to inherit from structs, e.g. -fms-extensions, so use a define instead
 * see https://stackoverflow.com/questions/1114349/struct-inheritance-in-c
 *
 * typedef struct mmtp_packet_header {
 *
 * todo, ptr back to chain to mmtp_packet_id
 */


typedef struct mmtp_sub_flow mmtp_sub_flow_t;

#define _MMTP_PACKET_HEADER_FIELDS 						\
	block_t*			raw_packet;						\
	mmtp_sub_flow_t*	mmtp_sub_flow;					\
	uint8_t 		    mmtp_packet_version; 			\
	uint8_t 		    packet_counter_flag; 			\
	uint8_t 		    fec_type; 						\
	uint8_t 		    mmtp_payload_type;				\
	uint8_t			    mmtp_header_extension_flag;		\
	uint8_t 		    mmtp_rap_flag;					\
	uint8_t 		    mmtp_qos_flag;					\
	uint8_t 		    mmtp_flow_identifer_flag;		\
	uint8_t 		    mmtp_flow_extension_flag;		\
	uint8_t 		    mmtp_header_compression;		\
	uint8_t			    mmtp_indicator_ref_header_flag;	\
	uint8_t 		    mmtp_type_of_bitrate;			\
	uint8_t 		    mmtp_delay_sensitivity;			\
	uint8_t 		    mmtp_transmission_priority;		\
	uint8_t 		    flow_label;						\
	uint16_t		    mmtp_header_extension_type;		\
	uint16_t		    mmtp_header_extension_length;	\
	uint8_t*		    mmtp_header_extension_value;	\
	uint16_t		    mmtp_packet_id; 				\
	uint32_t		    mmtp_timestamp;					\
	uint16_t		    mmtp_timestamp_s;				\
	uint16_t		    mmtp_timestamp_us;				\
	uint32_t		    packet_sequence_number;			\
	uint32_t		    packet_counter;					\

//DO NOT REFERENCE INTEREMDIATE STRUCTS DIRECTLY
typedef struct {
	_MMTP_PACKET_HEADER_FIELDS;
} __mmtp_packet_header_fields_t;

//define for mpu type common header fields for struct inheritance
//todo: add in MMTHSample box

#define _MMTP_MPU_TYPE_PACKET_HEADER_FIELDS \
	_MMTP_PACKET_HEADER_FIELDS;				\
	uint16_t mpu_payload_length;			\
	uint8_t mpu_fragment_type;				\
	uint8_t mpu_timed_flag;					\
	uint8_t mpu_fragmentation_indicator;	\
	uint8_t mpu_aggregation_flag;			\
	uint8_t mpu_fragmentation_counter;		\
	uint32_t mpu_sequence_number;			\
	uint16_t data_unit_length;				\
	block_t* mpu_data_unit_payload;			\

//DO NOT REFERENCE INTEREMDIATE STRUCTS DIRECTLY
typedef struct {
	_MMTP_MPU_TYPE_PACKET_HEADER_FIELDS;
} __mmtp_mpu_type_packet_header_fields_t;

//DO NOT REFERENCE INTEREMDIATE STRUCTS DIRECTLY
typedef struct {
	_MMTP_MPU_TYPE_PACKET_HEADER_FIELDS;
	uint32_t movie_fragment_sequence_number;
	uint32_t sample_number;
	uint32_t offset;
	uint8_t priority;
	uint8_t dep_counter;
	uint64_t pts;
	uint64_t last_pts;
} __mpu_data_unit_payload_fragments_timed_t;

//DO NOT REFERENCE INTEREMDIATE STRUCTS DIRECTLY
typedef struct {
	_MMTP_MPU_TYPE_PACKET_HEADER_FIELDS;
	uint32_t non_timed_mfu_item_id;

} __mpu_data_unit_payload_fragments_nontimed_t;

//DO NOT REFERENCE INTEREMDIATE STRUCTS DIRECTLY
typedef struct {
	_MMTP_PACKET_HEADER_FIELDS;

} __generic_object_fragments_t;

//DO NOT REFERENCE INTEREMDIATE STRUCTS DIRECTLY
typedef struct {
	_MMTP_PACKET_HEADER_FIELDS;

	//special mmtp payload header fields, these do not align with the bit specs in 23008-1, but are in logical order
	uint8_t		si_fragmentation_indiciator; //2 bits,
	uint8_t		si_additional_length_header; //1 bit
	uint8_t		si_aggregation_flag; 		 //1 bit
	uint8_t		si_fragmentation_counter;    //8 bits
	uint16_t	si_aggregation_message_length; //only set if si_aggregation_flag==1

	uint16_t	message_id;
	uint8_t		version;
	uint32_t	length;
	void*		extension;			//see atsc3_mmt_signaling_message.h for extension
	void*		payload;			//and payload types
} __signalling_message_fragments_t;

//DO NOT REFERENCE INTEREMDIATE STRUCTS DIRECTLY
typedef struct {
	_MMTP_PACKET_HEADER_FIELDS;

} __repair_symbol_t;
//DO NOT REFERENCE INTEREMDIATE STRUCTS DIRECTLY


//YOU CAN REFERENCE mmtp_payload_fragments_union_t* ONLY
//todo - convert this to discriminated union
typedef union mmtp_payload_fragments_union {
	__mmtp_packet_header_fields_t					mmtp_packet_header;
	__mmtp_mpu_type_packet_header_fields_t			mmtp_mpu_type_packet_header;

	__mpu_data_unit_payload_fragments_timed_t 		mpu_data_unit_payload_fragments_timed;
	__mpu_data_unit_payload_fragments_nontimed_t	mpu_data_unit_payload_fragments_nontimed;

	//add in the other mmtp types here
	__generic_object_fragments_t 					mmtp_generic_object_fragments;
	__signalling_message_fragments_t				mmtp_signalling_message_fragments;
	__repair_symbol_t								mmtp_repair_symbol;
} mmtp_payload_fragments_union_t;

typedef struct ATSC3_VECTOR(mmtp_payload_fragments_union_t *) 	mpu_type_packet_header_fields_vector_t;
typedef struct ATSC3_VECTOR(mmtp_payload_fragments_union_t *) 	mpu_data_unit_payload_fragments_timed_vector_t;
typedef struct ATSC3_VECTOR(mmtp_payload_fragments_union_t *)	mpu_data_unit_payload_fragments_nontimed_vector_t;
typedef struct ATSC3_VECTOR(mmtp_payload_fragments_union_t *) 	mmtp_generic_object_fragments_vector_t;
typedef struct ATSC3_VECTOR(mmtp_payload_fragments_union_t *) 	mmtp_signalling_message_fragments_vector_t;
typedef struct ATSC3_VECTOR(mmtp_payload_fragments_union_t *) 	mmtp_repair_symbol_vector_t;

//todo, make this union
typedef struct {
	uint32_t mpu_sequence_number;
	mpu_data_unit_payload_fragments_timed_vector_t 		timed_fragments_vector;
	mpu_data_unit_payload_fragments_nontimed_vector_t 	nontimed_fragments_vector;

} mpu_data_unit_payload_fragments_t;

typedef struct ATSC3_VECTOR(mpu_data_unit_payload_fragments_t *) mpu_data_unit_payload_fragments_vector_t;


//partial refactoring from vlc to libatsc3
#ifndef LIBATSC3_MPU_ISOBMFF_FRAGMENT_PARAMETERS_T_
#define LIBATSC3_MPU_ISOBMFF_FRAGMENT_PARAMETERS_T_

typedef struct {
	void*			mpu_demux_track;
	block_t*		p_mpu_block;
	uint32_t     	i_timescale;          /* movie time scale */
	uint64_t     	i_moov_duration;
	uint64_t     	i_cumulated_duration; /* Same as above, but not from probing, (movie time scale) */
	uint64_t     	i_duration;           /* Declared fragmented duration (movie time scale) */
	unsigned int 	i_tracks;       /* number of tracks */
	void*		  	*track;         /* array of track */
	bool        	b_fragmented;   /* fMP4 */
	bool         	b_seekable;

	/**
	 * declared in vlc_libatsc3_types.h for impl

	block_t* 		tmp_mpu_fragment_block_t;
	block_t* 		mpu_fragment_block_t;  //capture our MPU Metadat box

	MP4_Box_t*		mpu_fragments_p_root_box;
	MP4_Box_t*		mpu_fragments_p_moov;

	//reconstitue per movie fragment as needed
	block_t* 		mp4_movie_fragment_block_t;
	MP4_Box_t*		mpu_fragments_p_moof;


	struct
	{
		 uint32_t        i_current_box_type;
		 MP4_Box_t      *p_fragment_atom;
		 uint64_t        i_post_mdat_offset;
		 uint32_t        i_lastseqnumber;
	} context;
	*/
} mpu_isobmff_fragment_parameters_t;
#endif

typedef struct {
	mmtp_sub_flow_t *mmtp_sub_flow;
	uint16_t mmtp_packet_id;

	mpu_type_packet_header_fields_vector_t 		all_mpu_fragments_vector;

	//MPU Fragment type collections for reconstruction/recovery of fragments

	//MPU metadata, 							mpu_fragment_type==0x00
	mpu_data_unit_payload_fragments_vector_t 	mpu_metadata_fragments_vector;

	//Movie fragment metadata, 					mpu_fragment_type==0x01
	mpu_data_unit_payload_fragments_vector_t	mpu_movie_fragment_metadata_vector;

	//MPU (media fragment_unit),				mpu_fragment_type==0x02
	mpu_data_unit_payload_fragments_vector_t	media_fragment_unit_vector;

	mpu_isobmff_fragment_parameters_t			mpu_isobmff_fragment_parameters;

} mpu_fragments_t;

/**
 * todo:  impl's
 */


typedef struct mmtp_sub_flow {
	uint16_t mmtp_packet_id;

	//mmtp payload type collections for reconstruction/recovery of payload types

	//mpu (media_processing_unit):				paylod_type==0x00
	//mpu_fragments_vector_t 					mpu_fragments_vector;
	mpu_fragments_t								*mpu_fragments;

	//generic object:							payload_type==0x01
    mmtp_generic_object_fragments_vector_t 		mmtp_generic_object_fragments_vector;

	//signalling message: 						payload_type=0x02
	mmtp_signalling_message_fragments_vector_t 	mmtp_signalling_message_fragements_vector;

	//repair symbol:							payload_type==0x03
	mmtp_repair_symbol_vector_t 				mmtp_repair_symbol_vector;

} mmtp_sub_flow_t;


//todo - refactor mpu_fragments to vector, create a new tuple class for mmtp_sub_flow_sequence


typedef struct ATSC3_VECTOR(mmtp_sub_flow_t*) mmtp_sub_flow_vector_t;


#endif /* MODULES_DEMUX_MMT_MMTP_TYPES_H_ */
