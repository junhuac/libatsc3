/*
 * atsc3_lls_alc_tools.c
 *
 *  Created on: Feb 6, 2019
 *      Author: jjustman
 */

#include "atsc3_lls_alc_tools.h"

lls_session_t* lls_session_create() {
	lls_session_t* lls_session = calloc(1, sizeof(*lls_session));
	assert(lls_session);
	lls_session->lls_slt_alc_session = calloc(1, sizeof(*lls_session->lls_slt_alc_session));
	assert(lls_session->lls_slt_alc_session);
	lls_session->lls_slt_alc_session->sls_relax_source_ip_check = __LLS_SESSION_RELAX_SOURCE_IP_CHECK__;


	//do not instantiate any other lls_table_xxx types, as they will need to be assigned

	return lls_session;
}

void lls_session_free(lls_session_t** lls_session_ptr) {
	lls_session_t* lls_session = *lls_session_ptr;
	if(lls_session) {

		free(lls_session);
	}
	*lls_session_ptr = NULL;
}


