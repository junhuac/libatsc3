/*
 * atsc3_utils.c
 *
 *  Created on: Jan 19, 2019
 *      Author: jjustman
 */

#include "atsc3_utils.h"
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>

long long timediff(struct timeval t1, struct timeval t0) {
	return  (t1.tv_sec-t0.tv_sec)*1000000LL + t1.tv_usec-t0.tv_usec;
}

//walk thru [] of uint8*s and move our pointer for N elements
void* extract(uint8_t *bufPosPtr, uint8_t *dest, int size) {
	for(int i=0; i < size; i++) {
		dest[i] = *bufPosPtr++;
	}
	return bufPosPtr;
}

void kvp_collection_free(kvp_collection_t* collection) {
	if(!collection || !collection->size_n) return;

	//free each entry and their corresponding key/val char*
	for(int i=0; i < collection->size_n; i++) {
		kvp_t* kvp_to_free = collection->kvp_collection[i];
		if(kvp_to_free->key) {
			free(kvp_to_free->key);
			kvp_to_free->key = NULL;
		}
		if(kvp_to_free->val) {
				free(kvp_to_free->val);
				kvp_to_free->val = NULL;
		}
		free(kvp_to_free);
		collection->kvp_collection[i] = NULL;
	}

	free(collection->kvp_collection);
	collection->kvp_collection = NULL;
	free(collection);
}

char* kvp_collection_get_reference_p(kvp_collection_t *collection, char* key) {
	for(int i=0; i < collection->size_n; i++) {
		kvp_t* check = collection->kvp_collection[i];
		_ATSC3_UTILS_TRACE("kvp_find_key: checking: %s against %s, resolved val is: %s", key, check->key, check->val);
		if(strcasecmp(key, check->key) == 0) {
			_ATSC3_UTILS_TRACE("kvp_find_key: MATCH for key: %s, resolved val is: %s", check->key, check->val);
			return check->val;
		}
	}
	return NULL;
}

char* kvp_collection_get(kvp_collection_t *collection, char* key) {
	char* val = NULL;
	val = kvp_collection_get_reference_p(collection, key);

	if(!val) return NULL;

	//don't forget our null terminator
	int len = strlen(val) + 1;
	char* newval = calloc(len, sizeof(char));

	if(!newval) {
		_ATSC3_UTILS_ERROR("kvp_collection_get: unable to clone val return!");
		return NULL;
	}
	memcpy(newval, val, len);
	_ATSC3_UTILS_TRACE("kvp_collection_get: cloning len: %d, val: %s, newval: %s", len, val, newval);


	return newval;
}


kvp_collection_t* kvp_collection_parse(uint8_t* input_string) {
	int input_len = strlen((const char*)input_string);
	_ATSC3_UTILS_TRACE("kvp_parse_string: input string len: %d, input string:\n\n%s\n\n", input_len, input_string);
	kvp_collection_t *collection = calloc(1, sizeof(kvp_collection_t));

	//a= is not valid, must be at least 3 chars
	//return an empty collection
	if(input_len < 3)
			return collection;

	//find out how many ='s we have, as that will tell us how many kvp_t entries to create
	//first position can never be =
	int quote_depth = 0;
	int equals_count = 0;
	for(int i=1; i < input_len; i++) {
		if(input_string[i] == '"') {
			if(quote_depth)
				quote_depth--;
			else
				quote_depth++;
		} else if(input_string[i] == '=') {
			if(!quote_depth)
				equals_count++;
		}
	}

	_ATSC3_UTILS_TRACE("parse_kvp_string: creating %d entries", equals_count);

	equals_count = equals_count < 0 ? 0 : equals_count;

	//if we couldn't parse this, just return the empty (0'd collection)
	if(!equals_count) return collection;

	collection->kvp_collection = (kvp_t**)calloc(equals_count, sizeof(kvp_t**));
	collection->size_n = equals_count;

	quote_depth = 0;
	int kvp_position = 0;
	int token_key_start = 0;
	int token_val_start = 0;

	kvp_t* current_kvp = NULL;

	for(int i=1; i < input_len && kvp_position <= equals_count; i++) {
		if(!current_kvp) {
			//alloc our entry
			collection->kvp_collection[kvp_position] = calloc(1, sizeof(kvp_t));
			current_kvp = collection->kvp_collection[kvp_position];
		}
		if(isspace(input_string[i]) && !quote_depth) {
			token_key_start = i + 1; //walk forward
		} else {
			if(input_string[i] == '"' && input_string[i-1] != '\\') {
				if(quote_depth) {
					quote_depth--;

					//extract value here
					int len = i - token_val_start;
					current_kvp->val = (char*) calloc(len + 1, sizeof(char*));
					strncpy(current_kvp->val, (const char*)&input_string[token_val_start], len);
					current_kvp->val[len] = '\0';

					_ATSC3_UTILS_TRACE("parse_kvp_string: marking key: %s, token_val_start: %d, len: %d, val: %s", current_kvp->key, token_val_start, len, current_kvp->val);

					//collection->kvp_collection[kvp_position] = (kvp_t*)calloc(1, sizeof(kvp_t*));
					kvp_position++;
					current_kvp = NULL;

				} else {
					quote_depth++;
					token_val_start = i + 1;
				}
			} else if(input_string[i] == '=') {
				if(!quote_depth) {
					//extract key here
					int len = i - token_key_start;

					current_kvp->key = (char*)calloc(len + 1, sizeof(char));
					strncpy(current_kvp->key, (const char*)&input_string[token_key_start], len);
					current_kvp->key[len] = '\0';

					_ATSC3_UTILS_TRACE("parse_kvp_string: marking token_key_start: %d, len: %d, val is: %s", token_key_start, len, current_kvp->key);


				} else {
					//ignore it if we are in a quote value
				}
			}
		}
	}

	_ATSC3_UTILS_TRACE("kvp_parse_string - size is: %d", collection->size_n);
	return collection;
}



block_t* block_Alloc(int len) {
	block_t* new_block = calloc(1, sizeof(block_t));
	new_block->p_buffer = calloc(len, sizeof(uint8_t*));
	new_block->i_buffer = len;

	return new_block;
}

/**
 * todo, fix me to use ** to null out block_t ref
 */

block_t* block_Duplicate(block_t* a) {
	block_t* b= block_Alloc(a->i_buffer);
	memcpy(b->p_buffer, a->p_buffer, a->i_buffer);
	b->i_buffer = a->i_buffer;

	return b;
}

void block_Release(block_t* a) {
	if(a) {
		if(a->p_buffer) {
			free(a->p_buffer);
			a->p_buffer = NULL;
		}
		free(a);
		a = NULL;
	}
}

void freesafe(void* tofree) {
	if(tofree) {
		free(tofree);
	}
}

void freeclean(void** tofree) {
	if(*tofree) {
		free(*tofree);
		tofree = NULL;
	}
}


uint32_t parseIpAddressIntoIntval(char* dst_ip_original) {
	uint32_t ipAddressAsInteger = 0;
	char* dst_ip = strlcopy(dst_ip_original);

	char* pch = strtok (dst_ip,".");
	int offset = 24;

	while (pch != NULL && offset>=0) {
		uint8_t octet = atoi(pch);
		ipAddressAsInteger |= octet << offset;
		offset-=8;
		pch = strtok (NULL, " ,.-");
	}
	freesafe(dst_ip);
	return ipAddressAsInteger;
}

uint16_t parsePortIntoIntval(char* dst_port) {

	int dst_port_filter_int = atoi(dst_port);
	uint16_t dst_port_filter = 0;
	dst_port_filter |= dst_port_filter_int & 0xFFFF;

	return dst_port_filter;
}

//alloc and copy - note limited to 16k
char* strlcopy(char* src) {
	int len = strnlen(src, 16384);
	char* dest = calloc(len, sizeof(char*));
	return strncpy(dest, src, len);
}
