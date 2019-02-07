/*
 * atsc3_lls_tools.h
 *
 *  Created on: Feb 6, 2019
 *      Author: jjustman
 */
#include <assert.h>
#include <stdbool.h>

#include "atsc3_lls.h"

#include "mad.h"
#include "alc_session.h"


#ifndef __LLS_SESSION_RELAX_SOURCE_IP_CHECK__
#define __LLS_SESSION_RELAX_SOURCE_IP_CHECK__ true
#endif

#ifndef ATSC3_LLS_ALC_TOOLS_H_
#define ATSC3_LLS_ALC_TOOLS_H_

//alc - assume single session for now

typedef struct lls_alc_session {
	int lls_slt_service_id_alc;

	bool sls_relax_source_ip_check;
	uint32_t sls_source_ip_address;

	uint32_t sls_destination_ip_address;
	uint16_t sls_destination_udp_port;

	alc_arguments_t* alc_arguments;
	alc_session_t* alc_session;

} lls_alc_session_t;

typedef struct lls_session {
	lls_table_t* lls_table_slt;
	lls_alc_session_t* lls_slt_alc_session;

} lls_session_t;

lls_session_t* lls_session_create();
void lls_session_free(lls_session_t** lls_session_ptr);


#endif /* ATSC3_LLS_ALC_TOOLS_H_ */
