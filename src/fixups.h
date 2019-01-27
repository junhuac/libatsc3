/*
 * fixups.h
 *
 *  Created on: Jan 21, 2019
 *      Author: jjustman
 */

#ifndef MODULES_DEMUX_MMT_FIXUPS_H_
#define MODULES_DEMUX_MMT_FIXUPS_H_


//fixups

#ifndef HAVE_TIMESPEC_GET
#define TIME_UTC 1
struct timespec;
int timespec_get(struct timespec *, int);
#endif



#endif /* MODULES_DEMUX_MMT_FIXUPS_H_ */
