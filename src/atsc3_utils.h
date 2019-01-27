/*
 * atsc3_utils.h
 *
 *  Created on: Jan 6, 2019
 *      Author: jjustman
 */

#ifndef ATSC3_UTILS_H_
#define ATSC3_UTILS_H_

#include <stdlib.h>
#include <stdio.h>

#include "fixups.h"

#define uS 1000000ULL

#define _ATSC3_UTILS_PRINTLN(...) printf(__VA_ARGS__);printf("\n")
#define _ATSC3_UTILS_PRINTF(...)  printf(__VA_ARGS__);

#define _ATSC3_UTILS_ERROR(...)   printf("%s:%d:ERROR:",__FILE__,__LINE__);_ATSC3_UTILS_PRINTLN(__VA_ARGS__);
#define _ATSC3_UTILS_WARN(...)    printf("%s:%d:WARN :",__FILE__,__LINE__);_ATSC3_UTILS_PRINTLN(__VA_ARGS__);
#define _ATSC3_UTILS_INFO(...)    printf("%s:%d:INFO :",__FILE__,__LINE__);_ATSC3_UTILS_PRINTLN(__VA_ARGS__);
#define _ATSC3_UTILS_DEBUG(...)   printf("%s:%d:DEBUG:",__FILE__,__LINE__);_ATSC3_UTILS_PRINTLN(__VA_ARGS__);

#ifdef __ENABLE_ATSC3_UTILS_TRACE
#define _ATSC3_UTILS_TRACE(...)   printf("%s:%d:TRACE:",__FILE__,__LINE__);_ATSC3_UTILS_PRINTLN(__VA_ARGS__);
#define _ATSC3_UTILS_TRACEF(...)  printf("%s:%d:TRACE:",__FILE__,__LINE__);_ATSC3_UTILS_PRINTF(__VA_ARGS__);
#define _ATSC3_UTILS_TRACEA(...)  _ATSC3_UTILS_PRINTF(__VA_ARGS__);
#define _ATSC3_UTILS_TRACEN(...)  _ATSC3_UTILS_PRINTLN(__VA_ARGS__);
#else
#define _ATSC3_UTILS_TRACE(...)
#define _ATSC3_UTILS_TRACEF(...)
#define _ATSC3_UTILS_TRACEA(...)
#define _ATSC3_UTILS_TRACEN(...)
#endif

void* extract(uint8_t *bufPosPtr, uint8_t *dest, int size);

//key=value or key="value" attribute par collection parsing and searching
typedef struct kvp {
	char* key;
	char* val;
} kvp_t;

typedef struct kvp_collection {
	kvp_t **kvp_collection;
	int 	size_n;
} kvp_collection_t;

kvp_collection_t* kvp_collection_parse(uint8_t* input_string);

//return the cloned value from the collection for datamodel construction
char* kvp_collection_get(kvp_collection_t *collection, char* key);

//return the reference pointer to the value
char* kvp_collection_get_reference_p(kvp_collection_t *collection, char* key);

void kvp_collection_free(kvp_collection_t* collection);
void freesafe(void* tofree);


#endif /* ATSC3_UTILS_H_ */
