/*
 * atsc3_alc_utils.c
 *
 *  Created on: Feb 6, 2019
 *      Author: jjustman
 *
 *	< https://tools.ietf.org/html/rfc5775 >
 *      4.4.  Receiver Operation

   The receiver operation, when using ALC, includes all the points made
   about the receiver operation when using the LCT building block
   [RFC5651], the FEC building block [RFC5052], and the multiple rate
   congestion control building block.

   To be able to participate in a session, a receiver needs to obtain
   the required Session Description as listed in Section 2.4.  How
   receivers obtain a Session Description is outside the scope of this
   document.

   As described in Section 2.3, a receiver needs to obtain the required
   FEC Object Transmission Information for each object for which the
   receiver receives and processes packets.




Luby, et al.                 Standards Track                   [Page 15]

RFC 5775               ALC Protocol Instantiation             April 2010


   Upon receipt of each packet, the receiver proceeds with the following
   steps in the order listed.

   1.  The receiver MUST parse the packet header and verify that it is a
       valid header.  If it is not valid, then the packet MUST be
       discarded without further processing.

   2.  The receiver MUST verify that the sender IP address together with
       the TSI carried in the header matches one of the (sender IP
       address, TSI) pairs that was received in a Session Description
       and to which the receiver is currently joined.  If there is not a
       match, then the packet MUST be silently discarded without further
       processing.  The remaining steps are performed within the scope
       of the (sender IP address, TSI) session of the received packet.

   3.  The receiver MUST process and act on the CCI field in accordance
       with the multiple rate congestion control building block.

   4.  If more than one object is carried in the session, the receiver
       MUST verify that the TOI carried in the LCT header is valid.  If
       the TOI is not valid, the packet MUST be discarded without
       further processing.

   5.  The receiver SHOULD process the remainder of the packet,
       including interpreting the other header fields appropriately, and
       using the FEC Payload ID and the encoding symbol(s) in the
       payload to reconstruct the corresponding object.

   It is RECOMMENDED that packet authentication be used.  If packet
   authentication is used, then it is RECOMMENDED that the receiver
   immediately check the authenticity of a packet before proceeding with
   step (3) above.  If immediate checking is possible and if the packet
   fails the check, then the receiver MUST silently discard the packet.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "alc_rx.h"
#include "alc_channel.h"

static int __INT_LOOP_COUNT=0;


#define println(...) printf(__VA_ARGS__);printf("\n")

#define __PRINTLN(...) printf(__VA_ARGS__);printf("\n")
#define __PRINTF(...)  printf(__VA_ARGS__);

#define __ERROR(...)   printf("%s:%d:ERROR:",__FILE__,__LINE__);__PRINTLN(__VA_ARGS__);
#define __WARN(...)    printf("%s:%d:WARN:",__FILE__,__LINE__);__PRINTLN(__VA_ARGS__);
#define __INFO(...)    printf("%s:%d:INFO:",__FILE__,__LINE__);__PRINTLN(__VA_ARGS__);

#ifdef _ENABLE_DEBUG
#define __DEBUG(...)   printf("%s:%d:DEBUG:",__FILE__,__LINE__);__PRINTLN(__VA_ARGS__);
#define __DEBUGF(...)  printf("%s:%d:DEBUG:",__FILE__,__LINE__);__PRINTF(__VA_ARGS__);
#define __DEBUGA(...) 	__PRINTF(__VA_ARGS__);
#define __DEBUGN(...)  __PRINTLN(__VA_ARGS__);
#else
#define __DEBUG(...)
#define __DEBUGF(...)
#define __DEBUGA(...)
#define __DEBUGN(...)
#endif

int dumpAlcPacketToObect(alc_packet_t* alc_packet) {

	int bytesWritten = 0;
    mkdir("route", 0777);

	char *myFilePathName = calloc(128, sizeof(char));
	int filename_pos = 0;
	__DEBUG("have tsi: %s, toi: %s, sbn: %x, esi: %x len: %d",
			alc_packet->tsi, alc_packet->toi,
			alc_packet->esi, alc_packet->sbn, alc_packet->alc_len);

	FILE *f = NULL;

	//if no TSI, this is metadata and create a new object for each payload
	if(!alc_packet->tsi) {
		snprintf(myFilePathName,127, "route/%s-%s-%d", alc_packet->tsi, alc_packet->toi, __INT_LOOP_COUNT++);
		f = fopen(myFilePathName, "w");

	} else {
		snprintf(myFilePathName,127, "route/%s-%s", alc_packet->tsi, alc_packet->toi);

		if(alc_packet->esi>0) {
			__DEBUG("alc_rx.c - dumping to file in append mode: %s, esi: %d", myFilePathName, alc_packet->esi);
			f = fopen(myFilePathName, "a");
		} else {
			__DEBUG("alc_rx.c - dumping to file in write mode: %s, esi: %d", myFilePathName, alc_packet->esi);
			//open as write
			f = fopen(myFilePathName, "w");
		}
	}

	if(!f) {
		__WARN("alc_rx.c - UNABLE TO OPEN FILE %s", myFilePathName);
		goto cleanup;
	}

	for(int i=0; i < alc_packet->alc_len; i++) {
		fputc(alc_packet->alc_payload[i], f);
		bytesWritten++;
	}

	fclose(f);

	__DEBUG("alc_rx.c - dumping to file complete: %s", myFilePathName);
	free(myFilePathName);

	cleanup:
		if(alc_packet) {
			alc_packet_free(alc_packet);

		}

	return bytesWritten;
}
