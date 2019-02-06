/*
 *
 * atsc3_llt.c:  driver for ATSC 3.0 LLS listener over udp
 *
 *
 * jjustman@ngbp.org
 *
 *
 * Borrowed from A/331 6.3 Service List Table (SLT)
 *
 *
 * 6.3 Service List Table (SLT)
 *  The Service List Table (SLT) is one of the instance types of LLS information.
 *  The function of the SLT is similar to that of the Program Association Table (PAT) in MPEG-2 Systems [33],
 *  and the Fast Information Channel (FIC) found in ATSC A/153, Part 3 [44]. For a receiver first encountering the
 *  broadcast emission, this is the place to start. It supports a rapid channel scan which allows a receiver to
 *  build a list of all the services it can receive, with their channel name, channel number, etc., and it provides
 *  bootstrap information that allows a receiver to discover the SLS for each service. For ROUTE/DASH-delivered services,
 *  the bootstrap information includes the source IP address, the destination IP address and the destination port of the
 *  LCT channel that carries the ROUTE-specific SLS.
 *
 *  For MMTP/MPU-delivered services, the bootstrap information includes the destination IP address and destination
 *  port of the MMTP session carrying the MMTP- specific SLS.
 */

#include "atsc3_utils.h"
#include "atsc3_lls.h"
#include "xml.h"
int _LLS_DEBUG_ENABLED = 1;

static lls_table_t* __lls_create_base_table_raw(uint8_t* lls, int size) {

	//zero out full struct
	lls_table_t *base_table = calloc(1, sizeof(lls_table_t));

	//read first 32 bytes in
	base_table->lls_table_id = lls[0];
	base_table->lls_group_id = lls[1];
	base_table->group_count_minus1 = lls[2];
	base_table->lls_table_version = lls[3];

	int remaining_payload_size = (size > 65531) ? 65531 : size;

	uint8_t *temp_gzip_payload = calloc(size, sizeof(uint8_t));
	//FILE *f = fopen("slt.gz", "w");

	for(int i=4; i < remaining_payload_size; i++) {
		//printf("i:0x%x ", lls[i]);
		//fwrite(&lls[i], 1, 1, f);
		temp_gzip_payload[i-4] = lls[i];
	}
	base_table->raw_xml.xml_payload_compressed = temp_gzip_payload;
	base_table->raw_xml.xml_payload_compressed_size = remaining_payload_size - 4;


	//printf("first 4 hex: 0x%x 0x%x 0x%x 0x%x", temp_gzip_payload[0], temp_gzip_payload[1], temp_gzip_payload[2], temp_gzip_payload[3]);

	return base_table;
}


/**
 * footnote 5
 * The maximum size of the IP datagram is 65,535 bytes.
 * The maximum UDP data payload is 65,535 minus 20 bytes for the IP header minus 8 bytes for the UDP header.
 */

#define GZIP_CHUNK_INPUT_SIZE_MAX 65507
#define GZIP_CHUNK_INPUT_READ_SIZE 1024
#define GZIP_CHUNK_OUTPUT_BUFFER_SIZE 1024*8

int __unzip_gzip_payload(uint8_t *input_payload, uint input_payload_size, uint8_t **decompressed_payload) {

	if(input_payload_size > GZIP_CHUNK_INPUT_SIZE_MAX) return -1;

	uint input_payload_offset = 0;
	uint output_payload_offset = 0;
    unsigned char *output_payload = NULL;

    int ret;
    unsigned have;
    z_stream strm;

    uint8_t *decompressed;

    strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;
	strm.data_type = Z_TEXT;

	//treat this input_payload as gzip not just delfate
	ret = inflateInit2(&strm, 16+MAX_WBITS);

	if (ret != Z_OK)
	   return ret;

	do {

		strm.next_in = &input_payload[input_payload_offset];

		uint payload_chunk_size = input_payload_size - input_payload_offset > GZIP_CHUNK_INPUT_READ_SIZE ? GZIP_CHUNK_INPUT_READ_SIZE : input_payload_size - input_payload_offset;
		strm.avail_in = payload_chunk_size;

		if (strm.avail_in <= 0)
			break;

		do {
			if(!output_payload) {
				output_payload = calloc(GZIP_CHUNK_OUTPUT_BUFFER_SIZE + 1, sizeof(uint8_t));
			} else {
				output_payload = realloc(output_payload, output_payload_offset + GZIP_CHUNK_OUTPUT_BUFFER_SIZE + 1);
			}

			if(!output_payload)
				return -1;

			strm.avail_out = GZIP_CHUNK_OUTPUT_BUFFER_SIZE;
			strm.next_out = &output_payload[output_payload_offset];

			ret = inflate(&strm, Z_NO_FLUSH);

			//assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
			switch (ret) {
				case Z_NEED_DICT:
					ret = Z_DATA_ERROR;     /* and fall through */
				case Z_DATA_ERROR:
				case Z_MEM_ERROR:
					(void)inflateEnd(&strm);
				return ret;
			}

			if(strm.avail_out == 0) {
				output_payload_offset += GZIP_CHUNK_OUTPUT_BUFFER_SIZE;
			}
		} while (strm.avail_out == 0);

		input_payload_offset += GZIP_CHUNK_INPUT_READ_SIZE;

	} while (ret != Z_STREAM_END && input_payload_offset < input_payload_size);


	int paylod_len = (output_payload_offset + (GZIP_CHUNK_OUTPUT_BUFFER_SIZE - strm.avail_out));
	/* clean up and return */
	output_payload[paylod_len] = '\0';
	*decompressed_payload = output_payload;

	(void)inflateEnd(&strm);
	return ret == Z_STREAM_END ?  paylod_len : Z_DATA_ERROR;

}

lls_table_t* lls_create_xml_table( uint8_t* lls_packet, int size) {
	lls_table_t *lls_table = __lls_create_base_table_raw(lls_packet, size);

	uint8_t *decompressed_payload;
	int ret = __unzip_gzip_payload(lls_table->raw_xml.xml_payload_compressed, lls_table->raw_xml.xml_payload_compressed_size, &decompressed_payload);

	if(ret > 0) {
		lls_table->raw_xml.xml_payload = decompressed_payload;
		lls_table->raw_xml.xml_payload_size = ret;

		return lls_table;
	}

	return NULL;
}

lls_table_t* lls_table_create( uint8_t* lls_packet, int size) {
	int res = 0;
	xml_document_t* xml_document = NULL;
	xml_node_t* xml_root_node = NULL;

	lls_table_t* lls_table = lls_create_xml_table(lls_packet, size);

	if(!lls_table) {
		_LLS_ERROR("lls_create_table - error creating instance of LLS table and subclass");
		return NULL;
	}

	//create the xml document payload
	_LLS_TRACE("lls_create_table, raw xml payload is: \n%s", lls_table->raw_xml.xml_payload);
	xml_document = xml_payload_document_parse(lls_table->raw_xml.xml_payload, lls_table->raw_xml.xml_payload_size);

	//extract the root node
	xml_root_node = xml_payload_document_extract_root_node(xml_document);
	if(!xml_root_node)
			goto cleanup;

	_LLS_TRACE("lls_create_table: calling lls_create_table_type_instance with xml children count: %d\n", xml_node_children(xml_root));

	res = lls_create_table_type_instance(lls_table, xml_root_node);

	if(res) {
		//unable to instantiate lls_table, set lls_table ptr to null
		//TODO free our lls_xml_table
		_LLS_ERROR("lls_table_create: Unable to instantiate lls_table!");
		lls_table = NULL;
		goto cleanup;
	}

cleanup:


	if(xml_document) {
		//xml_document_free will release the root node for us... but keep the ra
		xml_document_free(xml_document, false);
		xml_document = NULL;
	}

	return lls_table;
}

void lls_table_free(lls_table_t* lls_table) {
	if(!lls_table) {
		_LLS_TRACE("lls_table_free: lls_table == NULL");
		return;
	}

	//free any instance specific mallocs

	if(lls_table->lls_table_id == SLT) {

		//for each service entry alloc, free
		for(int i=0; i < lls_table->slt_table.service_entry_n; i++) {
			if(lls_table->slt_table.service_entry[i]) {
				freesafe(lls_table->slt_table.service_entry[i]->global_service_id);
				freesafe(lls_table->slt_table.service_entry[i]->short_service_name);

				//clear all char* in broadcast_svc_signaling
				freesafe(lls_table->slt_table.service_entry[i]->broadcast_svc_signaling.sls_destination_ip_address);
				freesafe(lls_table->slt_table.service_entry[i]->broadcast_svc_signaling.sls_destination_udp_port);
				freesafe(lls_table->slt_table.service_entry[i]->broadcast_svc_signaling.sls_source_ip_address);

				free(lls_table->slt_table.service_entry[i]);
			}
		}

		if(lls_table->slt_table.service_entry)
			free(lls_table->slt_table.service_entry);

		if(lls_table->slt_table.bsid)
					free(lls_table->slt_table.bsid);

	} else if(lls_table->lls_table_id == RRT) {
	//	_LLS_ERROR("lls_create_table_type_instance: LLS table RRT not supported yet");
	} else if(lls_table->lls_table_id == SystemTime) {
		freesafe(lls_table->system_time_table.utc_local_offset);

	//	ret = build_SystemTime_table(lls_table, xml_root);
	} else if(lls_table->lls_table_id == AEAT) {
	//	_LLS_ERROR("lls_create_table_type_instance: LLS table AEAT not supported yet");
	} else if(lls_table->lls_table_id == OnscreenMessageNotification) {
	//	_LLS_ERROR("lls_create_table_type_instance: LLS table OnscreenMessageNotification not supported yet");
	}


	//free any cloned xmlstrings

	//free global table object
	if(lls_table->raw_xml.xml_payload_compressed) {
		free(lls_table->raw_xml.xml_payload_compressed);
		lls_table->raw_xml.xml_payload_compressed = NULL;
	}
	if(lls_table->raw_xml.xml_payload) {
		free(lls_table->raw_xml.xml_payload);
		lls_table->raw_xml.xml_payload = NULL;
	}
	free(lls_table);
}

/**
 * note, caller is responsible for freeing xml_document_type with xml_document_free
 *
 */
xml_document_t* xml_payload_document_parse(uint8_t *xml, int xml_size) {
	xml_document_t* document = xml_parse_document(xml, xml_size);
	if (!document) {
		_LLS_ERROR("xml_payload_document_parse: Could not parse document");
		return NULL;
	}

	return document;
}

//chomp past root xml document declaration
xml_node_t* xml_payload_document_extract_root_node(xml_document_t* document) {

	xml_node_t* root = xml_document_root(document);
	xml_string_t* root_node_name = xml_node_name(root); //root

	if(xml_string_equals_ignore_case(root_node_name, "?xml")) {
		root = xml_node_child(root, 0);
		root_node_name = xml_node_name(root); //root
		dump_xml_string(root_node_name);
	} else {
		_LLS_ERROR("xml_payload_document_extract_root_node: unable to parse out ?xml preamble");
		return NULL;
	}

	_LLS_TRACE("atsc3_lls.c:parse_xml_payload, returning document: %p", root);
	dump_xml_string(root_node_name);
	return root;
}

//caller must free xml_root
int lls_create_table_type_instance(lls_table_t* lls_table, xml_node_t* xml_root) {

	xml_string_t* root_node_name = xml_node_name(xml_root); //root

	uint8_t* node_name = xml_string_clone(root_node_name);
	_LLS_TRACE("lls_create_table_type_instance: lls_table_id: %d, node ptr: %p, name is: %s", lls_table->lls_table_id, root_node_name, node_name);

	int ret = -1;
	if(lls_table->lls_table_id == SLT) {
		//build SLT table
		ret = build_SLT_table(lls_table, xml_root);

	} else if(lls_table->lls_table_id == RRT) {
		_LLS_ERROR("lls_create_table_type_instance: LLS table RRT not supported yet");
	} else if(lls_table->lls_table_id == SystemTime) {
		ret = build_SystemTime_table(lls_table, xml_root);
	} else if(lls_table->lls_table_id == AEAT) {
		_LLS_ERROR("lls_create_table_type_instance: LLS table AEAT not supported yet");
	} else if(lls_table->lls_table_id == OnscreenMessageNotification) {
		_LLS_ERROR("lls_create_table_type_instance: LLS table OnscreenMessageNotification not supported yet");
	} else {
		_LLS_ERROR("lls_create_table_type_instance: Unknown LLS table type: %d",  lls_table->lls_table_id);

	}
	_LLS_DEBUG("lls_create_table_type_instance: returning ret: %d, lls_table_id: %d, node ptr: %p, name is: %s", ret, lls_table->lls_table_id, root_node_name, node_name);

	freesafe(node_name);

	return ret;
}

#define LLS_SLT_SIMULCAST_TSID 				"SimulcastTSID"
#define LLS_SLT_SVC_CAPABILITIES			"SvcCapabilities"
#define LLS_SLT_BROADCAST_SVC_SIGNALING 	"BroadcastSvcSignaling"
#define LLS_SLT_SVC_INET_URL				"SvcInetUrl"
#define LLS_SLT_OTHER_BSID					"OtherBsid"

int build_SLT_table(lls_table_t *lls_table, xml_node_t *xml_root) {
	/** bsid **/

	xml_string_t* root_node_name = xml_node_name(xml_root); //root
	dump_xml_string(root_node_name);

	uint8_t* slt_attributes = xml_attributes_clone(root_node_name);
	_LLS_DEBUG("build_SLT_table, attributes are: %s", (const char*)slt_attributes);

	kvp_collection_t* slt_attributes_collecton = kvp_collection_parse(slt_attributes);
	char* bsid_char = kvp_collection_get(slt_attributes_collecton, "bsid");
	//if there is a space, split and callocif(strnstr(bsid, "", ))

	//TODO: fix me
	if(bsid_char) {
		int bsid_i;
		bsid_i = atoi(bsid_char);
		freesafe(bsid_char);

		lls_table->slt_table.bsid_n = 1;
		lls_table->slt_table.bsid =  (int*)calloc(lls_table->slt_table.bsid_n , sizeof(int));
		lls_table->slt_table.bsid[0] = bsid_i;
	}

	_LLS_TRACE("build_SLT_table, attributes are: %s\n", slt_attributes);

	int svc_size = xml_node_children(xml_root);

	//build our service rows
	for(int i=0; i < svc_size; i++) {
		xml_node_t* service_row_node = xml_node_child(xml_root, i);
		xml_string_t* service_row_node_xml_string = xml_node_name(service_row_node);

		/** push service row **/
		lls_table->slt_table.service_entry_n++;
		//TODO - grow this dynamically to N?
		if(!lls_table->slt_table.service_entry) {
			lls_table->slt_table.service_entry = (service_t**)calloc(32, sizeof(service_t**));
		}

		//service_row_node_xml_string
		uint8_t* child_row_node_attributes_s = xml_attributes_clone(service_row_node_xml_string);
		kvp_collection_t* service_attributes_collecton = kvp_collection_parse(child_row_node_attributes_s);

		lls_table->slt_table.service_entry[lls_table->slt_table.service_entry_n-1] = calloc(1, sizeof(service_t));
		service_t* service_entry = lls_table->slt_table.service_entry[lls_table->slt_table.service_entry_n-1];
		//map in other attributes, e.g


		int scratch_i = 0;
		char* serviceId = kvp_collection_get(service_attributes_collecton, "serviceId");

		if(!serviceId) {
			_LLS_ERROR("missing required element - serviceId!");
			return -1;
		}

		scratch_i = atoi(serviceId);
		freesafe(serviceId);
		service_entry->service_id = scratch_i & 0xFFFF;
		_LLS_TRACE("service id is: %s, int is: %d, uint_16: %u", serviceId, scratch_i, (scratch_i & 0xFFFF));

		//copy our char* elements
		service_entry->global_service_id  = kvp_collection_get(service_attributes_collecton, "globalServiceID");
		service_entry->short_service_name = kvp_collection_get(service_attributes_collecton, "shortServiceName");

		char* majorChannelNo  = kvp_collection_get(service_attributes_collecton, "majorChannelNo");
		char* minorChannelNo  = kvp_collection_get(service_attributes_collecton, "minorChannelNo");
		char* serviceCategory = kvp_collection_get(service_attributes_collecton, "serviceCategory");
		char* sltSvcSeqNum    = kvp_collection_get(service_attributes_collecton, "sltSvcSeqNum");

		//optional parameters here
		if(majorChannelNo) {
			scratch_i = atoi(majorChannelNo);
			service_entry->major_channel_no = scratch_i & 0xFFFF;
			freesafe(majorChannelNo);
		}

		if(minorChannelNo) {
			scratch_i = atoi(minorChannelNo);
			service_entry->minor_channel_no = scratch_i & 0xFFFF;
			freesafe(minorChannelNo);
		}

		if(serviceCategory) {
			scratch_i = atoi(serviceCategory);
			service_entry->service_category = scratch_i & 0xFFFF;
			freesafe(serviceCategory);
		}

		if(sltSvcSeqNum) {
			scratch_i = atoi(sltSvcSeqNum);
			service_entry->slt_svc_seq_num = scratch_i & 0xFFFF;
			freesafe(sltSvcSeqNum);
		}

		int svc_child_size = xml_node_children(service_row_node);

		dump_xml_string(service_row_node_xml_string);

		for(int j=0; j < svc_child_size; j++) {

			xml_node_t* child_row_node = xml_node_child(service_row_node, j);
			xml_string_t* child_row_node_xml_string = xml_node_name(child_row_node);

			//this is a malloc
			uint8_t* child_row_node_attributes_s = xml_attributes_clone(child_row_node_xml_string);
			kvp_collection_t* kvp_child_attributes = kvp_collection_parse(child_row_node_attributes_s);

			dump_xml_string(child_row_node_xml_string);

			if(xml_string_equals_ignore_case(child_row_node_xml_string, LLS_SLT_SIMULCAST_TSID)) {
				_LLS_ERROR("build_SLT_table - not supported: LLS_SLT_SIMULCAST_TSID");
			} else if(xml_string_equals_ignore_case(child_row_node_xml_string, LLS_SLT_SVC_CAPABILITIES)) {
				_LLS_ERROR("build_SLT_table - not supported: LLS_SLT_SVC_CAPABILITIES");
			} else if(xml_string_equals_ignore_case(child_row_node_xml_string, LLS_SLT_BROADCAST_SVC_SIGNALING)) {
				build_SLT_BROADCAST_SVC_SIGNALING_table(service_entry, service_row_node, kvp_child_attributes);

			} else if(xml_string_equals_ignore_case(child_row_node_xml_string, LLS_SLT_SVC_INET_URL)) {
				_LLS_ERROR("build_SLT_table - not supported: LLS_SLT_SVC_INET_URL");
			} else if(xml_string_equals_ignore_case(child_row_node_xml_string, LLS_SLT_OTHER_BSID)) {
				_LLS_ERROR("build_SLT_table - not supported: LLS_SLT_OTHER_BSID");
			} else {
				_LLS_ERROR("build_SLT_table - unknown type: %s\n", xml_string_clone(child_row_node_xml_string));
			}

			//cleanup
			free(child_row_node_attributes_s);
			kvp_collection_free(kvp_child_attributes);
		}

		//cleanup

		if(service_attributes_collecton) {
			kvp_collection_free(service_attributes_collecton);
		}
		if(child_row_node_attributes_s) {
			free(child_row_node_attributes_s);
		}
	}

	if(slt_attributes) {
		free(slt_attributes);
	}
	if(slt_attributes_collecton) {
		kvp_collection_free(slt_attributes_collecton);
	}

	return 0;
}

int build_SLT_BROADCAST_SVC_SIGNALING_table(service_t* service_table, xml_node_t *service_row_node, kvp_collection_t* kvp_collection) {
	int ret = 0;
	xml_string_t* service_row_node_xml_string = xml_node_name(service_row_node);
	uint8_t *svc_attributes = xml_attributes_clone(service_row_node_xml_string);
	_LLS_TRACE("build_SLT_BROADCAST_SVC_SIGNALING_table - attributes are: %s", svc_attributes);

	char* slsProtocol = kvp_collection_get(kvp_collection, "slsProtocol");
	if(!slsProtocol) {
		_LLS_ERROR("build_SLT_BROADCAST_SVC_SIGNALING_table: missing slsProtocol value");
		ret = -1;
		goto cleanup;
	}

	int scratch_i=0;
	service_table->broadcast_svc_signaling.sls_protocol = atoi(slsProtocol);
	freesafe(slsProtocol);

	service_table->broadcast_svc_signaling.sls_destination_ip_address = kvp_collection_get(kvp_collection, "slsDestinationIpAddress");
	service_table->broadcast_svc_signaling.sls_destination_udp_port = kvp_collection_get(kvp_collection, "slsDestinationUdpPort");
	service_table->broadcast_svc_signaling.sls_source_ip_address = kvp_collection_get(kvp_collection, "slsSourceIpAddress");


	//kvp_find_key(kvp_collection, "slsProtocol";

cleanup:
	//cleanup
	if(svc_attributes) {
		free(svc_attributes);
	}

	return ret;
}

/** payload looks like:
 *
 * <SystemTime xmlns="http://www.atsc.org/XMLSchemas/ATSC3/Delivery/SYSTIME/1.0/" currentUtcOffset="37" utcLocalOffset="-PT5H" dsStatus="false"/>
 */
int build_SystemTime_table(lls_table_t* lls_table, xml_node_t* xml_root) {

	int ret = 0;

	xml_string_t* root_node_name = xml_node_name(xml_root); //root
	dump_xml_string(root_node_name);

	uint8_t* SystemTime_attributes = xml_attributes_clone(root_node_name);
	kvp_collection_t* SystemTime_attributes_collecton = kvp_collection_parse(SystemTime_attributes);

	int scratch_i = 0;

	char* currentUtcOffset =	kvp_collection_get(SystemTime_attributes_collecton, "currentUtcOffset");
	char* ptpPrepend = 			kvp_collection_get(SystemTime_attributes_collecton, "ptpPrepend");
	char* leap59 =				kvp_collection_get(SystemTime_attributes_collecton, "leap59");
	char* leap61 = 				kvp_collection_get(SystemTime_attributes_collecton, "leap61");
	char* utcLocalOffset = 		kvp_collection_get(SystemTime_attributes_collecton, "utcLocalOffset");
	char* dsStatus = 			kvp_collection_get(SystemTime_attributes_collecton, "dsStatus");
	char* dsDayOfMonth = 		kvp_collection_get(SystemTime_attributes_collecton, "dsDayOfMonth");
	char* dsHour = 				kvp_collection_get(SystemTime_attributes_collecton, "dsHour");

	if(!currentUtcOffset || !utcLocalOffset) {
		_LLS_ERROR("build_SystemTime_table, required elements missing: currentUtcOffset: %p, utcLocalOffset: %p", currentUtcOffset, utcLocalOffset);
		ret = -1;
		goto cleanup;
	}

	scratch_i = atoi(currentUtcOffset);
	freesafe(currentUtcOffset);

	//munge negative sign
	if(scratch_i < 0) {
		lls_table->system_time_table.current_utc_offset = (1 << 15) | (scratch_i & 0x7FFF);
	} else {
		lls_table->system_time_table.current_utc_offset = scratch_i & 0x7FFF;
	}

	lls_table->system_time_table.utc_local_offset = utcLocalOffset;

	if(ptpPrepend) {
		scratch_i = atoi(ptpPrepend);
		lls_table->system_time_table.ptp_prepend = scratch_i & 0xFFFF;
	}

	if(leap59) {
		lls_table->system_time_table.leap59 = strcasecmp(leap59, "t") == 0;
	}

	if(leap61) {
		lls_table->system_time_table.leap61 = strcasecmp(leap61, "t") == 0;
	}

	if(dsStatus) {
		lls_table->system_time_table.ds_status = strcasecmp(dsStatus, "t") == 0;
		freesafe(dsStatus);
	}

	if(dsDayOfMonth) {
		scratch_i = atoi(dsDayOfMonth);
		lls_table->system_time_table.ds_status = scratch_i & 0xFF;
		freesafe(dsDayOfMonth);
	}

	if(dsHour) {
		scratch_i = atoi(dsHour);
		lls_table->system_time_table.ds_status = scratch_i & 0xFF;
		freesafe(dsHour);
	}

cleanup:
	if(SystemTime_attributes_collecton) {
		kvp_collection_free(SystemTime_attributes_collecton);
	}

	if(SystemTime_attributes) {
		free(SystemTime_attributes);
	}

	return ret;
}


void lls_dump_instance_table(lls_table_t* base_table) {
	_LLS_TRACE("dump_instance_table: base_table address: %p", base_table);

	_LLS_INFO("");
	_LLS_INFO("--------------------------");
	_LLS_INFO(" LLS Base Table:");
	_LLS_INFO("--------------------------");
	_LLS_INFO(" lls_table_id             : %d (0x%x)", base_table->lls_table_id, base_table->lls_table_id);
	_LLS_INFO(" lls_group_id             : %d (0x%x)", base_table->lls_group_id, base_table->lls_group_id);
	_LLS_INFO(" group_count_minus1       : %d (0x%x)", base_table->group_count_minus1, base_table->group_count_minus1);
	_LLS_INFO(" lls_table_version        : %d (0x%x)", base_table->lls_table_version, base_table->lls_table_version);
	_LLS_INFO(" xml decoded payload size : %d", 	base_table->raw_xml.xml_payload_size);
	_LLS_INFO(" --------------------------");

	if(base_table->raw_xml.xml_payload) {
		_LLS_INFO("\t%s", base_table->raw_xml.xml_payload);
	}

	_LLS_INFO(" --------------------------");

	if(base_table->lls_table_id == SLT) {

		_LLS_INFO("SLT: Service contains %d entries:", base_table->slt_table.service_entry_n);

		for(int i=0l; i < base_table->slt_table.service_entry_n; i++) {
			service_t* service = base_table->slt_table.service_entry[i];
			_LLS_INFO(" -----------------------------");
			_LLS_INFO("  service_id                  : %d", service->service_id);
			_LLS_INFO("  global_service_id           : %s", service->global_service_id);
			_LLS_INFO("  major_channel_no            : %d", service->major_channel_no);
			_LLS_INFO("  minor_channel_no            : %d", service->minor_channel_no);
			_LLS_INFO("  service_category            : %d", service->service_category);
			_LLS_INFO("  short_service_name          : %s", service->short_service_name);
			_LLS_INFO("  slt_svc_seq_num             : %d", service->slt_svc_seq_num);
			_LLS_INFO(" -----------------------------");
			_LLS_INFO("  broadcast_svc_signaling");
			_LLS_INFO(" -----------------------------");
			_LLS_INFO("    sls_protocol              : %d", service->broadcast_svc_signaling.sls_protocol);
			_LLS_INFO("    sls_destination_ip_address: %s", service->broadcast_svc_signaling.sls_destination_ip_address);
			_LLS_INFO("    sls_destination_udp_port  : %s", service->broadcast_svc_signaling.sls_destination_udp_port);
			_LLS_INFO("    sls_source_ip_address     : %s", service->broadcast_svc_signaling.sls_source_ip_address);

		}
		_LLS_DEBUGN("--------------------------");
	}

	//decorate with instance types: hd = int16_t, hu = uint_16t, hhu = uint8_t
	if(base_table->lls_table_id == SystemTime) {
		_LLS_INFO(" SystemTime:");
		_LLS_INFO(" --------------------------");
		_LLS_INFO("  current_utc_offset       : %hd", base_table->system_time_table.current_utc_offset);
		_LLS_INFO("  ptp_prepend              : %hu", base_table->system_time_table.ptp_prepend);
		_LLS_INFO("  leap59                   : %d",  base_table->system_time_table.leap59);
		_LLS_INFO("  leap61                   : %d",  base_table->system_time_table.leap61);
		_LLS_INFO("  utc_local_offset         : %s",  base_table->system_time_table.utc_local_offset);

		_LLS_INFO("  ds_status                : %d",  base_table->system_time_table.ds_status);
		_LLS_INFO("  ds_day_of_month          : %hhu", base_table->system_time_table.ds_day_of_month);
		_LLS_INFO("  ds_hour                  : %hhu", base_table->system_time_table.ds_hour);
		_LLS_DEBUGN("--------------------------");

	}
	_LLS_DEBUGN("");

}


