/*
 * mmtp_ntp32_to_pts.h
 *
 *  Created on: Jan 8, 2019
 *      Author: jjustman
 */

#ifndef MODULES_DEMUX_MMT_MMTP_NTP32_TO_PTS_H_
#define MODULES_DEMUX_MMT_MMTP_NTP32_TO_PTS_H_

#include "atsc3_utils.h"
#include <time.h>
#include <stdio.h>


/**
 * convert ntp "short-format" packet time into a future re-clocked pts
 * short-format is:
 *
 * 	int16_t seconds
 * 	int16_t s_fragment
 *
 * 	seconds rolls over at 65535 from every ntp epoc, so we need to un-bias this when computing a future offset
 *
 * 	instead
 */
#define REBASE_PTS_OFFSET 0

void compute_ntp32_to_seconds_microseconds(uint32_t timestamp, uint16_t *seconds, uint16_t *microseconds);
uint64_t compute_relative_ntp32_pts(uint64_t first_pts, uint16_t mmtp_timestamp_s, uint16_t mmtp_timestamp_microseconds);
int64_t rebase_now_with_ntp32(uint16_t mmtp_timestamp_s, uint16_t mmtp_timestamp_microseconds);


#endif /* MODULES_DEMUX_MMT_MMTP_NTP32_TO_PTS_H_ */
