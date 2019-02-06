/*
 * astc3_lls.h
 *
 *  Created on: Jan 5, 2019
 *      Author: jjustman
 */

#ifndef MODULES_DEMUX_MMT_ASTC3_LLS_H_
#define MODULES_DEMUX_MMT_ASTC3_LLS_H_

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "atsc3_utils.h"
#include "zlib.h"
#include "xml.h"

#define _LLS_PRINTLN(...) printf(__VA_ARGS__);printf("\n")
#define _LLS_PRINTF(...)  printf(__VA_ARGS__);

#define _LLS_ERROR(...)   printf("%s:%d:ERROR:",__FILE__,__LINE__);_LLS_PRINTLN(__VA_ARGS__);
#define _LLS_WARN(...)    printf("%s:%d:WARN:",__FILE__,__LINE__);_LLS_PRINTLN(__VA_ARGS__);
#define _LLS_INFO(...)    printf("%s:%d:INFO:",__FILE__,__LINE__);_LLS_PRINTLN(__VA_ARGS__);

#define _LLS_DEBUG(...)   if(_LLS_DEBUG_ENABLED) { printf("%s:%d:DEBUG:",__FILE__,__LINE__);_LLS_PRINTLN(__VA_ARGS__); }
#define _LLS_DEBUGF(...)  if(_LLS_DEBUG_ENABLED) { printf("%s:%d:DEBUG:",__FILE__,__LINE__);_LLS_PRINTF(__VA_ARGS__); }
#define _LLS_DEBUGA(...)  if(_LLS_DEBUG_ENABLED) { _LLS_PRINTF(__VA_ARGS__); }
#define _LLS_DEBUGN(...)  if(_LLS_DEBUG_ENABLED) { _LLS_PRINTLN(__VA_ARGS__); }
#define _LLS_DEBUGNT(...) if(_LLS_DEBUG_ENABLED){ _LLS_PRINTF(" ");_LLS_PRINTLN(__VA_ARGS__); }

#ifdef __ENABLE_LLS_TRACE
#define _LLS_TRACE(...)   printf("%s:%d:TRACE:",__FILE__,__LINE__);_LLS_PRINTLN(__VA_ARGS__);
#define _LLS_TRACEF(...)  printf("%s:%d:TRACE:",__FILE__,__LINE__);_LLS_PRINTF(__VA_ARGS__);
#define _LLS_TRACEA(...)  _LLS_PRINTF(__VA_ARGS__);
#define _LLS_TRACEN(...)  _LLS_PRINTLN(__VA_ARGS__);
#else
#define _LLS_TRACE(...)
#define _LLS_TRACEF(...)
#define _LLS_TRACEA(...)
#define _LLS_TRACEN(...)
#endif


#define LLS_DST_ADDR 3758102332
#define LLS_DST_PORT 4937

/***
 * From < A/331 2017 - Signaling Delivery Sync > https://www.atsc.org/wp-content/uploads/2017/12/A331-2017-Signaling-Deivery-Sync-FEC-3.pdf
 * LLS shall be transported in IP packets with address:
 * 224.0.23.60 and destination port 4937/udp
 *
 *
 *UDP/IP packets delivering LLS data shall be formatted per the bit stream syntax given in Table 6.1 below.
 *UDP/IP The first byte of every UDP/IP packet carrying LLS data shall be the start of an LLS_table().
 *UDP/IP  The maximum length of any LLS table is limited by the largest IP packet that can be delivered from the PHY layer, 65,507 bytes5.
 *UDP/IP
 *      Syntax
 *

Syntax							Bits			Format
------							----			------
LLS_table() {

	LLS_table_id 				8
	LLS_group_id 				8
	group_count_minus1 			8
	LLS_table_version 			8
	switch (LLS_table_id) {
		case 0x01:
			SLT					var
			break;
		case 0x02:
			RRT					var
			break;
		case 0x03:
			SystemTime			var
			break;
		case 0x04:
			AEAT 				var
			break;
		case 0x05:
			OnscreenMessageNotification	var
			break;
		default:
			reserved			var
	}
}

No. of Bits
8 8 8 8
var var var var var var
Format
uimsbf uimsbf uimsbf uimsbf
Sec. 6.3
See Annex F Sec. 6.4 Sec. 6.5 Sec. 6.6
     }
 *
 */



/*
 *
 * To create the proper LLS table type instance, invoke
 *

 	lls_table_t* lls = lls_create_table(binary_payload, binary_payload_size);
	if(lls) {
		lls_dump_instance_table(lls);
	}

 */

typedef struct llt_xml_payload {
	uint8_t *xml_payload_compressed;
	uint xml_payload_compressed_size;
	uint8_t *xml_payload;
	uint xml_payload_size;


} lls_xml_payload_t;

/**
 *  |SLT|, attributes len: 70, val: xmlns="tag:atsc.org,2016:XMLSchemas/ATSC3/Delivery/SLT/1.0/" bsid="50"
children: 569:dump_xml_string::xml_string: len: 7, is_self_closing: 0, val: |Service|, attributes len: 172, val: serviceId="1001" globalServiceID="urn:atsc:serviceid:ateme_mmt_1" majorChannelNo="10" minorChannelNo="1" serviceCategory="1" shortServiceName="ATEME MMT 1" sltSvcSeqNum="0"
69:dump_xml_string::xml_string: len: 21, is_self_closing: 1, val: |BroadcastSvcSignaling|, attributes len: 118, val: slsProtocol="2" slsDestinationIpAddress="239.255.10.1" slsDestinationUdpPort="51001" slsSourceIpAddress="172.16.200.1"
69:dump_xml_string::xml_string: len: 7, is_self_closing: 0, val: |Service|, attributes len: 172, val: serviceId="1002" globalServiceID="urn:atsc:serviceid:ateme_mmt_2" majorChannelNo="10" minorChannelNo="2" serviceCategory="1" shortServiceName="ATEME MMT 2" sltSvcSeqNum="0"
69:dump_xml_string::xml_string: len: 21, is_self_closing: 1, val: |BroadcastSvcSignaling|, attributes len: 118, val: slsProtocol="2" slsDestinationIpAddress="239.255.10.2" slsDestinationUdpPort="51002" slsSourceIpAddress="172.16.200.1"
69:dump_xml_string::xml_string: len: 7, is_self_closing: 0, val: |Service|, attributes len: 172, val: serviceId="1003" globalServiceID="urn:atsc:serviceid:ateme_mmt_3" majorChannelNo="10" minorChannelNo="3" serviceCategory="1" shortServiceName="ATEME MMT 3" sltSvcSeqNum="0"
69:dump_xml_string::xml_string: len: 21, is_self_closing: 1, val: |BroadcastSvcSignaling|, attributes len: 118, val: slsProtocol="2" slsDestinationIpAddress="239.255.10.3" slsDestinationUdpPort="51003" slsSourceIpAddress="172.16.200.1"
69:dump_xml_string::xml_string: len: 7, is_self_closing: 0, val: |Service|, attributes len: 172, val: serviceId="1004" globalServiceID="urn:atsc:serviceid:ateme_mmt_4" majorChannelNo="10" minorChannelNo="4" serviceCategory="1" shortServiceName="ATEME MMT 4" sltSvcSeqNum="0"
69:dump_xml_string::xml_string: len: 21, is_self_closing: 1, val: |BroadcastSvcSignaling|, attributes len: 118, val: slsProtocol="2" slsDestinationIpAddress="239.255.10.4" slsDestinationUdpPort="51004" slsSourceIpAddress="172.16.200.1"
69:dump_xml_string::xml_string: len: 7, is_self_closing: 0, val: |Service|, attributes len: 117, val: serviceId="5009" globalServiceID="urn:atsc:serviceid:esg" serviceCategory="4" shortServiceName="ESG" sltSvcSeqNum="0"
69:dump_xml_string::xml_string: len: 21, is_self_closing: 1, val: |BroadcastSvcSignaling|, attributes len: 118, val: slsProtocol="1" slsDestinationIpAddress="239.255.20.9" slsDestinationUdpPort="52009" slsSourceIpAddress="172.16.200.1"
 */

/*
 * <SLT xmlns="tag:atsc.org,2016:XMLSchemas/ATSC3/Delivery/SLT/1.0/" bsid="50">
 *
 *
 */
typedef struct slt_entry {
	uint bsid; //broadcast stream id

} slt_entry_t;



/*
 *
 * A/331 Section 6.3 Service List Table XML

<?xml version="1.0" encoding="UTF-8"?>
<SLT xmlns="tag:atsc.org,2016:XMLSchemas/ATSC3/Delivery/SLT/1.0/" bsid="50">
   <Service serviceId="1001" globalServiceID="urn:atsc:serviceid:ateme_mmt_1" majorChannelNo="10" minorChannelNo="1" serviceCategory="1" shortServiceName="ATEME MMT 1" sltSvcSeqNum="0">
      <BroadcastSvcSignaling slsProtocol="2" slsDestinationIpAddress="239.255.10.1" slsDestinationUdpPort="51001" slsSourceIpAddress="172.16.200.1" />
   </Service>
   <Service serviceId="1002" globalServiceID="urn:atsc:serviceid:ateme_mmt_2" majorChannelNo="10" minorChannelNo="2" serviceCategory="1" shortServiceName="ATEME MMT 2" sltSvcSeqNum="0">
      <BroadcastSvcSignaling slsProtocol="2" slsDestinationIpAddress="239.255.10.2" slsDestinationUdpPort="51002" slsSourceIpAddress="172.16.200.1" />
   </Service>
   <Service serviceId="1003" globalServiceID="urn:atsc:serviceid:ateme_mmt_3" majorChannelNo="10" minorChannelNo="3" serviceCategory="1" shortServiceName="ATEME MMT 3" sltSvcSeqNum="0">
      <BroadcastSvcSignaling slsProtocol="2" slsDestinationIpAddress="239.255.10.3" slsDestinationUdpPort="51003" slsSourceIpAddress="172.16.200.1" />
   </Service>
   <Service serviceId="1004" globalServiceID="urn:atsc:serviceid:ateme_mmt_4" majorChannelNo="10" minorChannelNo="4" serviceCategory="1" shortServiceName="ATEME MMT 4" sltSvcSeqNum="0">
      <BroadcastSvcSignaling slsProtocol="2" slsDestinationIpAddress="239.255.10.4" slsDestinationUdpPort="51004" slsSourceIpAddress="172.16.200.1" />
   </Service>
   <Service serviceId="5009" globalServiceID="urn:atsc:serviceid:esg" serviceCategory="4" shortServiceName="ESG" sltSvcSeqNum="0">
      <BroadcastSvcSignaling slsProtocol="1" slsDestinationIpAddress="239.255.20.9" slsDestinationUdpPort="52009" slsSourceIpAddress="172.16.200.1" />
   </Service>
</SLT>


 Table 6.4 Code Values for SLT.Service@serviceCategory


	serviceCategory 		Meaning
	---------------			-------------
	0						ATSC Reserved
	1						Linear A/V service
	2						Linear audio only service
	3						App-based service
	4						ESG service (program guide)
	5						EAS service (emergency alert)
	Other values			ATSC Reserved

  	slsProtocol				Meaning
 	---------- 				-------------
 	0 						ATSC Reserved
 	1						ROUTE
 	2						MMTP
 	other values			ATSC Reserved

 */
enum serviceCategory {
	SERVICE_CATEGORY_ATSC_RESERVED=0,
	SERVICE_CATEGORY_LINEAR_AV_SERVICE=1,
	SERVICE_CATEGORY_LINEAR_AUDIO_ONLY_SERVICE=2,
	SERVICE_CATEGORY_APP_BASED_SERVICE=3,
	SERVICE_CATEGORY_ESG_SERVICE=4,
	SERVICE_CATEGORY_EAS_SERVICE=5,
	SERVICE_CATEGORY_ATSC_RESERVED_OTHER=-1	};

enum slsProtocol {
	SLS_PROTOCOL_ATSC_RESERVED=0,
	SLS_PROTOCOL_ROUTE=1,
	SLS_PROTOCOL_MMTP=2,
	SLS_PROTOCOL_ATSC_RESERVED_OTHER=-1};

typedef struct broadcast_svc_signaling {
	int 	sls_protocol;
	char*	sls_destination_ip_address;
	char*	sls_destination_udp_port;
	char*	sls_source_ip_address;

} broadcast_svc_signaling_t;
/*
 *    <Service serviceId="1001" globalServiceID="urn:atsc:serviceid:ateme_mmt_1" majorChannelNo="10" minorChannelNo="1" serviceCategory="1" shortServiceName="ATEME MMT 1" sltSvcSeqNum="0">
 *
 */
typedef struct service {
	uint16_t	service_id;
	char*		global_service_id;
	uint		major_channel_no;
	uint 		minor_channel_no;
	uint		service_category;
	char*		short_service_name;
	uint8_t 	slt_svc_seq_num;  //Version of SLT service info for this service.
	broadcast_svc_signaling_t broadcast_svc_signaling;
} service_t;


typedef struct slt_table {
	int*				bsid;			//list
	int					bsid_n;
	char*			 	slt_capabilities;
	service_t**			service_entry; 	//list
	int					service_entry_n;

} slt_table_t;

typedef struct rrt_table {

} rrt_table_t;

/** from atsc a/331 section 6.4
 *

6.4 System Time Fragment

System time is delivered in the ATSC PHY layer as a 32-bit count of the number of seconds, a 10-
bit fraction of a second (in units of milliseconds), and optionally 10-bit microsecond and
nanosecond components, since January 1, 1970 00:00:00, International Atomic Time (TAI), which
is the Precision Time Protocol (PTP) epoch as defined in IEEE 1588 [47]. Further time-related
information is signaled in the XML SystemTime element delivered in LLS.

 */

typedef struct system_time_table {
	int16_t 	current_utc_offset;	//required
	uint16_t 	ptp_prepend; 		//opt
	bool		leap59;				//opt
	bool		leap61;				//opt
	char*		utc_local_offset;	//required
	bool		ds_status;			//opt
	uint8_t		ds_day_of_month;	//opt
	uint8_t		ds_hour;			//opt

} system_time_table_t;

typedef struct aeat_table { } aeat_table_t;
typedef struct on_screen_message_notification { } on_screen_message_notification_t;
typedef struct lls_reserved_table { } lls_reserved_table_t;

typedef enum {
	SLT = 1,
	RRT,
	SystemTime,
	AEAT,
	OnscreenMessageNotification,
	RESERVED
} lls_table_type_t;

typedef struct lls_table {
	uint8_t								lls_table_id; //map via lls_table_id_type;
	uint8_t								lls_group_id;
	uint8_t 							group_count_minus1;
	uint8_t								lls_table_version;
	lls_xml_payload_t					raw_xml;

	union {

		slt_table_t							slt_table;
		rrt_table_t							rrt_table;
		system_time_table_t					system_time_table;
		aeat_table_t						aeat_table;
		on_screen_message_notification_t	on_screen_message_notification;
		lls_reserved_table_t				lls_reserved_table;
	};

} lls_table_t;



lls_table_t* lls_create_base_table( uint8_t* lls, int size);

/**
 *
 * Raw SLT example:

0000   01 01 00 02 1f 8b 08 08 92 17 18 5c 00 03 53 4c   ...........\..SL
0010   54 00 b5 d5 5b 6f 82 30 14 00 e0 f7 fd 0a d2 e7   T.µÕ[o.0..à÷ý.Òç
0020   0d 4a 41 37 0d 60 9c 9a c5 44 8d 09 2e d9 9b a9   .JA7.`..ÅD...Ù.©
0030   d0 61 17 68 5d 5b cd fc f7 3b a8 cb e2 bc 44 16   Ða.h][Íü÷;¨Ëâ¼D.
0040   7d 22 9c 4b cf e9 f7 00 41 eb ab c8 ad 15 53 9a   }".KÏé÷.Aë«È..S.
0050   4b 11 22 d7 c6 c8 62 22 91 29 17 59 88 96 e6 fd   K."×ÆÈb".).Y..æý
0060   e1 09 b5 a2 bb 20 1e 4c 2c a8 14 3a 44 86 66 4d   á.µ¢» .L,¨.:D.fM
0070   6a 74 62 4b 95 dd 13 ec d6 9b 6f c3 41 9c cc 59   jtbK.Ý.ìÖ.oÃA.ÌY
0080   41 b5 d3 9e c4 1d cf e9 b2 9c c3 99 6b 07 da 1c   AµÓ.Ä.Ïé².Ã.k.Ú.
0090   38 d3 41 d6 4c f3 34 44 35 8c a2 20 66 6a c5 13   8ÓAÖLó4D5.¢ fjÅ.
00a0   66 e9 ed b3 0f 71 17 63 17 59 59 2e 67 34 df a5   féí³.q.c.YY.g4ß¥
00b0   fb 5d 98 af c4 66 54 73 57 ca 53 78 65 05 9b 16   û].¯ÄfTsWÊSxe...
00c0   85 99 42 43 41 3f a4 ea cc a9 10 2c 1f c9 f2 18   ..BCA?¤êÌ©.,.Éò.
00d0   88 71 b1 1f 43 3f 83 3a d0 9b 49 b5 de c6 e6 52   .q±.C?.:Ð.IµÞÆæR
00e0   99 dd a8 11 2d 58 88 da 93 de b0 67 0d 87 13 ab   .Ý¨.-X.Ú.Þ°g...«
00f0   4c e7 26 5e 25 31 fb 1c 2d 8b 10 95 5b 3f 2b 49   Lç&^%1û.-...[?+I
0100   d3 84 ea 4d 9c 67 82 e6 40 04 75 7a ac a4 91 89   Ó.êM.g.æ@.uz¬¤..
0110   cc 43 44 ca 3e dd 65 da 70 41 0d 80 f6 17 ed 34   ÌCDÊ>ÝeÚpA..ö.í4
0120   55 4c 83 1a f1 1a 36 a9 d5 6c 17 db ee df b2 d7   UL..ñ.6©Õl.Ûîß²×
0130   74 31 86 6d 80 67 eb 00 d9 58 2e 15 18 fc f6 bb   t1.m.gë.ÙX...üö»
0140   8f c4 76 eb 36 c1 65 bf 13 05 ce 6e f7 53 9c a4   .Ävë6Áe¿..În÷S.¤
0150   2a 27 b9 8c 93 54 e7 24 b7 e5 3c 28 db e3 24 d7   *'¹..Tç$·å<(Ûã$×
0160   e1 f4 aa 72 7a 97 71 7a d5 39 bd db 72 7a 67 39   áôªrz.qzÕ9½Ûrzg9
0170   bd eb 70 fa 55 39 fd cb 38 fd ea 9c fe 6d 39 fd   ½ëpúU9ýË8ýê.þm9ý
0180   b3 9c fe 15 38 6b 18 37 2e e3 64 3a 3b e2 e3 1f   ³.þ.8k.7.ãd:;âã.
0190   f3 e9 c5 2f ff 74 39 f8 ba 1d 71 21 d8 6e 9c 76   óéÅ/ÿt9øº.q!Øn.v
01a0   21 9b 0b 55 73 29 ff 34 d1 dd 37 2e 0e fb 8f ce   !..Us)ÿ4ÑÝ7..û.Î
01b0   06 00 00                                          ...

Raw SystemTime message:
0000   01 00 5e 00 17 3c 00 1c 42 22 fa 9f 08 00 45 00   ..^..<..B"ú...E.
0010   00 dd 01 00 40 00 01 11 c0 27 c0 a8 00 04 e0 00   .Ý..@...À'À¨..à.
0020   17 3c 90 8b 13 49 00 c9 2d 76 03 01 00 01 1f 8b   .<...I.É-v......
0030   08 08 97 17 18 5c 00 03 53 79 73 74 65 6d 54 69   .....\..SystemTi
0040   6d 65 00 35 8d cb 0a 82 40 14 40 f7 7e c5 70 f7   me.5.Ë..@.@÷~Åp÷
0050   7a 0b 89 22 7c 10 15 14 28 05 63 50 cb 61 bc 3e   z.."|...(.cPËa¼>
0060   60 1c c3 b9 66 fe 7d 6e da 1e 38 e7 44 e9 b7 33   `.Ã¹fþ}nÚ.8çDé·3
0070   e2 43 83 6b 7b 1b c3 3a 58 81 20 ab fb b2 b5 75   âC.k{.Ã:X. «û²µu
0080   0c 23 57 fe 0e d2 c4 8b e4 ec 98 ba a2 ed 48 2c   .#Wþ.ÒÄ.äì.º¢íH,
0090   82 75 31 34 cc ef 3d e2 34 4d 81 62 a7 83 7e a8   .u14Ìï=â4M.b§.~¨
00a0   f1 99 67 52 37 d4 29 87 87 42 1e 43 3c 91 69 97   ñ.gR7Ô)..B.C<.i.
00b0   f8 8c f2 25 8b 6b 7e c6 65 80 20 f4 38 0c 64 f9   ø.ò%.k~Æe. ô8.dù
00c0   c1 fa 56 55 8e 38 86 70 0b 62 64 9d f5 5a 99 3f   ÁúVU.8.p.bd.õZ.?
00d0   f3 ef c5 e6 02 a2 74 92 15 8f cb b2 52 c6 11 60   óïÅæ.¢t...Ë²RÆ.`
00e0   e2 fd 00 35 18 c1 1f b6 00 00 00                  âý.5.Á.¶...

see atsc3_lls_test.c for base64 string getters of test payloads
 *
 */


lls_table_t* lls_create_xml_table( uint8_t* lls_packet, int size);
//todo - rename this lls_table_create
lls_table_t* lls_table_create( uint8_t* lls_packet, int size);
//todo - rename this lls_table_free
void lls_table_free(lls_table_t* lls_table);
int lls_create_table_type_instance(lls_table_t* lls_table, xml_node_t* xml_node);

void lls_dump_instance_table(lls_table_t *base_table);

//xml parsing methods
xml_document_t* xml_payload_document_parse(uint8_t *xml, int xml_size);
xml_node_t* xml_payload_document_extract_root_node(xml_document_t*);

//etst methods

int build_SLT_table(lls_table_t *lls_table, xml_node_t *xml_root);
int build_SystemTime_table(lls_table_t* lls_table, xml_node_t* xml_root);

int build_SLT_BROADCAST_SVC_SIGNALING_table(service_t* service_table, xml_node_t *xml_node, kvp_collection_t* kvp_collection);

// internal helper methods here
int __unzip_gzip_payload(uint8_t *input_payload, uint input_payload_size, uint8_t **decompressed_payload);


#endif /* MODULES_DEMUX_MMT_ASTC3_LLS_H_ */
