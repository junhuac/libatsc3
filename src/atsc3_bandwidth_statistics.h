/*
 * atsc3_bandwidth_statistics.h
 *
 *  Created on: Feb 6, 2019
 *      Author: jjustman
 */
#include <time.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <stdbool.h>
#include <unistd.h>
#include <locale.h>

#include "output_statistics_ncurses.h"
#include "atsc3_utils.h"


#ifndef ATSC3_BANDWIDTH_STATISTICS_H_
#define ATSC3_BANDWIDTH_STATISTICS_H_

#ifndef __BW_STATS_NCURSES
#define __BW_STATS(...)   printf("%s:%d: ","bw_stats",__LINE__);__PRINTLN(__VA_ARGS__);
#define __BW_STATS_I(...)  printf("%s:%d: ","bw_stats",__LINE__);
#define __BW_STATS_L(...)  __PRINTLN(__VA_ARGS__);

#define __BW_STATS_BORDER(...) __BW_STATS(__VA_ARGS__)
#define __BW_STATS_REFRESH()
#define __BW_CLEAR()
#endif

#define __BW_TRACE(...)   //printf("%s:%d:TRACE: ",__FILE__,__LINE__);__PRINTLN(__VA_ARGS__);

typedef struct bandwith_statistics {
	//using sig_atomic_t so parser thread doesn't need to be synchronized for locks for updating the current value
	//only the collation thread should touch grand_total_rx

	sig_atomic_t	interval_total_current_rx;
	uint32_t		interval_total_last_rx;
	uint32_t		grand_total_rx;

	sig_atomic_t	interval_lls_current_rx;
	uint32_t		interval_lls_last_rx;
	uint32_t		grand_lls_rx;

	sig_atomic_t	interval_mmt_current_rx;
	uint32_t		interval_mmt_last_rx;
	uint32_t		grand_mmt_rx;

	sig_atomic_t	interval_alc_current_rx;
	uint32_t		interval_alc_last_rx;
	uint32_t		grand_alc_rx;

	sig_atomic_t	interval_filtered_current_rx;
	uint32_t		interval_filtered_last_rx;
	uint32_t		grand_filtered_rx;

	struct timeval 	snapshot_timeval_start;
	struct timeval 	program_timeval_start;
} bandwidth_statistics_t;

bandwidth_statistics_t *global_bandwidth_statistics;
void *printBandwidthStatistics(void *vargp);

#endif /* ATSC3_BANDWIDTH_STATISTICS_H_ */
