/*****************************************************************************
 * mmtp_demuxer.c : mmtp demuxer for ngbp
 *****************************************************************************
 *
 * a sample MMT ISO-23008-1 de-muxer/de-encapsulator for live MMT video playback in VLC
 * uses MFU re-assembly for delivery to hevc and audio decoder. allows playback of
 * ATSC 3.0 live video streams via mulicast-udp for NGBP.
 *
 * Author: jjustman@ngbp.org
 *
 * TODO:
 *
 * 	MMT spec scope:
 *
 * 		- add in base signaling implementation for PA table processing,
 * 			- support packet_id selection via consuming MPT table messages rather than building es streams for all packet_id
 *		- reduce "observed" jitter by using timestamp (short-format NTP) of packet payload for es block PTS + jitter buffer time
 *		- (excluded from atsc 3.0 a/331 spec) NRT asset support to object on disk
 *		- (excluded from atsc 3.0 a/331 spec) GFD support to object on disk
 *		- overlay text support for diagnostics:
 *			- mmt packet_id v/a identification
 *			- mmt packet loss, e.g. via packet_counter gaps
 *			- missing fragments
 *			- decoder errors
 *			- avg bitrate, etc
 *			- PA messages
 *
 *
 *		- refactor out main MMT processing into standalone libmmt project
 *			- add in interface hooks and mappipngs from VLC to libmmt other players/platforms/connected devices/tv's etc
 *
 *	ATSC 3.0/331
 *		- add in default LLS (low-level-signaling) SLT (service list table) listening to:
 *			LLS shall be transported in IP packets with address 224.0.23.60 and destination port 4937/udp.1
 *		- provide channel selection via SLT table or
 *		- use SystemTime instead of local clock time
 *
 *		-add in SLS (See section 7.2/7.3/7.4)
 *			via USBD/USD – User Service Bundle Description / User Service Description
 *
 *
 *			MMTP session carries MMTP-specific signaling messages specific to its session or each asset delivered by the MMTP session.
The following MMTP messages shall be delivered by the MMTP session signaled in the SLT:
• MMT Package Table (MPT) message: This message carries an MP (MMT Package) table which contains the list of all Assets and their location information as specified in subclause 10.3.4 of ISO/IEC 23008-1) [37].
• MMT ATSC3 (MA3) message mmt_atsc3_message(): This message carries system metadata specific for ATSC 3.0 services including Service Layer Signaling as specified in Section 7.2.3.1.
The following MMTP messages shall be delivered by the MMTP session signaled in the SLT, if required:
• Media Presentation Information (MPI) message: This message carries an MPI table which contains the whole document or a subset of a document of presentation information. An MP table associated with the MPI table also can be delivered by this message (see subclause 10.3.3 of ISO/IEC 23008-1) [37];
 *
 *
 *	ATSC 3.0/332
 *
 *		- Consume Service Fragments for on-screen EPG
 *
 * genesis: 2018-12-21
 *
 *
 *
 *  MMTP Packet V=0
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=0|C|FEC|r|X|R|RES|   type    |            packet_id          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |					     	timestamp						   | 64
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |					 packet_sequence_number				 	   | 96
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |					     packet_counter				 	       | 128
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | 						 Header Extension				   ..... 160 == 20 bytes
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | 						   Payload Data				       ..... 192
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |				      source_FEC_payload_ID					   | 224
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  ---
 *
 *  MMTP Packet V=1
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=1|C|FEC|X|R|Q|F|E|B|I| type  |           packet_id           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |					     	timestamp						   | 64
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |					 packet_sequence_number				 	   | 96
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |					     packet_counter				 	       | 128
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |r|TB | DS  | TP  | flow_label  |         extension_header  ....| 160+n == 20bytes
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | 						   Payload Data				       ..... 192
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |				      source_FEC_payload_ID					   | 224
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Semantics
 *
 * version  				indicates the version number of the MMTP protocol. This field shall be set
 * (V: 2 bits)			  	to "00" to for ISO 23008-1 2017, and 01 for QoS support.
 *
 * 							NOTE If version is set to 01, the length of type is set to 4 bits.
 *
 * packet_counter_flag   	1 in this field indicates that the packet_counter field is present.
 * (C: 1 bit)
 *
 * FEC_type  				indicates the type of the FEC scheme used for error protection of MMTP packets.
 * (FEC: 2 bits)			Valid values of this field are listed in Table 8.
 *								0	MMTP packet without source_FEC_payload_ID field (NO FEC applied)
 *								1	MMTP packet with source_FEC_payload_ID field
 *								2 	MMTP packet for repair symbol(s) for FEC Payload Mode 0 (FEC repair packet)
 *								3	MMTP packet for repair symbol(s) for FEC Payload Mode 1 (FEC repair packet)
 *
 * reserved					reserved for future use (in V=0, bit position 5 only)
 * (r: 1 bit)
 *
 * extension_flag			when set to 1, this flag indicates the header_extension field is present
 * (X: 1 bit) 					V=0, bit position 6
 *								V=1, bit position 5
 * RAP_flag
 * (R: 1 bit)				when set to 1, this flag indicates that the payload contains a Random Access Point to the datastream of that data type,
 *							defined by the data type itself.
 *
 * reserved					V=0 only - reserverd for future use
 * (RES: 2 bits)
 *
 * Compression_flag			V=1 only - this field will identify if header compression is used.
 * (B: 1 bit) 	 	 	 	 	 	 	 	 	 B=0, full size header will be used
 * 	 	 	 	 	 	 	 	 	 	 	 	 B=1, reduced size header will be used
 *
 * Indicator_flag			V=1 only - if set to I=1, this header is a reference header which will be
 * (I: 1 bit) 									 used later for a future packet with reduced headers.
 *
 * Payload Type				Payload data type and definitions, differs between V=0 and V=1
 * (type: 6 bits when V=0)
 * 							Value		Data Type			Definition of data unit
 * 							-----		---------			-----------------------
 * 							0x00		MPU					media-aware fragment of the MPU
 * 							0x01		generic object		generic such as complete MPU or another type
 * 							0x02		signaling message	one or more signaling messages
 * 							0x03		repair symbol		a single complete repair signal
 * 							0x04-0x1F	reserved 			for ISO use
 * 							0x20-0x3F	reserved			private use
 *
 * Payload Type
 * (type: 4 bits when V=1)
 * 							Value		Data Type			Definition of data unit
 * 							-----		---------			----------------------
 * 							0x0			MPU					media-aware fragment of the MPU
 * 							0x1			generic object		generic such as complete MPU or another type
 * 							0x2			signaling message	one or more signaling messages
 * 							0x3			repair signal		a single complete repair signal
 * 							0x4-0x9		reserved			for ISO use
 * 							0xA-0xF		reserved			private use
 *
 * packet_id				See ISO 23008-1 page 27
 * (16 bits)				used to distinguish one asset from another,
 * 							packet_id to asset_id is captured in the MMT Package Table as part of signaling message
 *
 * packet_sequence_number	used to distinguish between packets with the same packet_id
 * (32 bits)				begings at arbritary value, increases by one for each MMTP packet received,
 * 							and will wraparound to 0 at INT_MAX
 *
 * timestamp				time instance of MMTP packet delivery based upon UTC.
 * (32 bits)				short format defined in IETF RFC 5905 NTPv4 clause 6.
 *
 * packet_counter			integer value for counting MMTP packets, incremented by 1 when a MMTP packet is sent regardless of its packet_id value.
 * (32 bits)				arbitrary value, wraps around to 0
 * 							all packets of an MMTP flow shall have the same setting for packet_counter_flag (c)
 *
 * source_FEC_payload_ID	used only when FEC type=1.  MMTP packet will be AL-FEC Payload ID Mode
 * (32 bits)
 *
 * header_extension			contains user-defined information, used for proprietary extensions to the payload format
 * (16/16bits)						to enable applications and media types that require additional information the payload format header
 *
 * QoS_classifer flag		a value of 1 indicates the Qos classifer information is used
 * (Q: 1 bit)
 *
 * flow_identifer_flag		when set to 1, indicates that the flow identifier is used
 * (F:1 bit)					flow_label and flow_extnesion_flag fields, characteristics or ADC in a package
 *
 * flow_extension_flag		if there are more than 127 flows, this bit set set to 1 and more byte can be used in extension_header
 * (E: 1 bit)
 *
 * reliability_flag			when reliability flag is set to 0, data is loss tolerant (e.g media display), and pre-emptable by "transmission priority"
 * (r: 1 bit)				when reliability flag is set to 1, data is not loss tolerant (e.g signaling) and will pre-empt "transmission priority"
 *
 * type_of_bitrate			00 		constant bitrate, e.g. CBR
 * (TB: 2 bits)				01 		non-constrant bitrate, e.g. nCBR
 * 							10-11	reserved
 *
 * delay_sensitivity		indicates the sensitivty of the delay for end-to-end delivery
 * (DS: 3 bits)
 * 							111		conversational services (~100ms)
 * 							110		live-streming service (~1s)
 * 							101		delay-sensitive interactive service (~2s)
 * 							100		interactive service (~5s)
 * 							011		streaming service (~10s)
 * 							010		non-realtime service
 * 							001		reserved
 * 							000		reserved
 *
 * transmission_priority	provides the transmission priority of the packet, may be mapped
 * (TP: 3 bits)				to the NRI of the NAL, DSCP of IETF or other prioty fields from:
 * 							highest: 7 (1112)
 * 							lowest:  0 (0002)
 *
 * flow label				indicates the flow identifier, representing a bitstream or a group of bitstreams
 * (7 bits)					who's network resources are reserved according to an ADC or packet.
 * 							Range from 0-127, arbitrarily assigned in a session.
 *
----
 * Notes: alpha MMT parser and MPU/MFU chained demuxing
 *
 * Dependencies: pcap MMT unicast replay files or live ATSC 3.0 network mulitcast reception/reflection (see https://redzonereceiver.tv/)
 *
 * airwavez redzone SDR USB dongle
 *
 * the user space module can be flakey with recovery if the usb connection drops.
 * i use a script similar to the following to turn up, tune and monitor:
 *

#!/bin/bash

# Allow Multicast IP on the enp0s6 interface and route it there instead of to the wired interface
sudo ifconfig lo -multicast
sudo ifconfig enp0s5 -multicast
sudo ifconfig enp0s6 multicast
sudo route del -net 224.0.0.0 netmask 240.0.0.0 dev lo
sudo route add -net 224.0.0.0 netmask 240.0.0.0 dev enp0s6


#start userspace driver
klatsc30_web_ui -f -p 8080 &

sleep 10
#tune to channel 43 - you'll need to find a testing market (e.g. dallas or phenix)
wget 'http://127.0.0.1:8080/networktuner/tunefrequency?json={"operating_mode":"ATSC3","frequency_plan":"US_BROADCAST","frequency_Hz":647000000, "plp0_id":0}'


sleep 5

#start ff for monitoring
firefox http://127.0.0.1:8080

 *
 *
 * replay:
 * wireshark tcp captures must be in libpcap format, and most likely need to have packet checksums realcualted before replay:
 * e.g. tcprewrite --fixcsum -i 2018-12-17-mmt-airwavz-bad-checksums.pcap -o 2018-12-17-mmt-airwavz-recalc.pcap
 * replay via, e.g. bittwist -i enp0s6 2018-12-17-mmt-airwavz-recalc.pcap -v
 *
 *
 * lastly, i then have a host only interface between my ubuntu and mac configured in parallels, but mac's management of the mulitcast routes is a bit weird,
 * the two scripts will revoke any autoconfigured interface mulitcast routes, and then manually add the dedicated 224 route to the virtual host-only network:
 *
 *
cat /usr/local/bin/deleteMulticastRoute
netstat -nr
sudo route delete -net 224.0.0.0/4
sudo route delete -host 239.255.10.2
sudo route delete -host 239.255.255.250
sudo route delete -net 255.255.255.255/32

 cat /usr/local/bin/addVnic1MulitcastRoute
sudo route -nv add -net 224.0.0.0/4 -interface vnic1

 *
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif


#include "atsc3_utils.h"
#include "mmtp_types.h"
#include "mmtp_stats_marquee.h"

/** cascasde libmp4 headers here ***/

#include "mp4.h"

#include <vlc_common.h>
#include <vlc_demux.h>
#include <vlc_charset.h>                           /* EnsureUTF8 */
#include <vlc_modules.h>

#include <vlc_input.h>
#include <vlc_aout.h>
#include <vlc_plugin.h>
#include <vlc_dialog.h>
#include <vlc_url.h>
#include <vlc_vector.h>
#include <vlc_filter.h>

#include <assert.h>
#include <limits.h>
#include "../codec/cc.h"
#include "heif.h"
#include "../av1_unpack.h"





#define _MMT_UTILS_PRINTLN(...) printf(__VA_ARGS__);printf("\n")
#define _MMT_UTILS_PRINTF(...)  printf(__VA_ARGS__);

#define _MMT_UTILS_ERROR(...)   printf("%s:%d:ERROR:",__FILE__,__LINE__);_MMT_UTILS_PRINTLN(__VA_ARGS__);
#define _MMT_UTILS_WARN(...)    printf("%s:%d:WARN :",__FILE__,__LINE__);_MMT_UTILS_PRINTLN(__VA_ARGS__);
#define _MMT_UTILS_INFO(...)    printf("%s:%d:INFO :",__FILE__,__LINE__);_MMT_UTILS_PRINTLN(__VA_ARGS__);
#define _MMT_UTILS_DEBUG(...)  printf("%s:%d:DEBUG:",__FILE__,__LINE__);_MMT_UTILS_PRINTLN(__VA_ARGS__);

#define _MMT_UTILS_TRACE(...)

//printf("%s:%d:TRACE:",__FILE__,__LINE__);_MMT_UTILS_PRINTLN(__VA_ARGS__);


block_t* reassembled_mpu_final;

#define ACCESS_TEXT N_("MMTP Demuxer module")

static int  Open( vlc_object_t * );
static void Close ( vlc_object_t * );

#define MIN(a,b) (((a)<(b))?(a):(b))

#define DEMUX_INCREMENT VLC_TICK_FROM_MS(250) /* How far the pcr will go, each round */
#define DEMUX_TRACK_MAX_PRELOAD VLC_TICK_FROM_SEC(15) /* maximum preloading, to deal with interleaving */

#define INVALID_PRELOAD  UINT_MAX

#define VLC_DEMUXER_EOS (VLC_DEMUXER_EGENERIC - 1)
#define VLC_DEMUXER_FATAL (VLC_DEMUXER_EGENERIC - 2)

static int __MFU_COUNTER=1;


vlc_module_begin ()
    set_shortname("MMTP")
    set_category( CAT_INPUT )
    set_subcategory( SUBCAT_INPUT_DEMUX )
    set_description( N_("MMTP Demuxer") )
    set_capability( "demux", 500 )
  //  add_module("demuxdump-access", "sout access", "file",
  //            ACCESS_TEXT, ACCESS_TEXT)
  //  add_savefile("demuxdump-file", "stream-demux.dump",
  //               FILE_TEXT, FILE_LONGTEXT)
  //  add_bool( "demuxdump-append", false, APPEND_TEXT, APPEND_LONGTEXT,
  //           false )
    set_callbacks( Open, Close )
    add_shortcut( "MMTP" )
vlc_module_end ()


static int   Demux   ( demux_t * );
static int   Control ( demux_t *, int, va_list );

void processMpuPacket(demux_t* p_obj, mmtp_sub_flow_t *mmtp_sub_flow, mmtp_payload_fragments_union_t* mpu_type_packet);
void createTracksFromMpuMetadata(demux_t *p_obj, mmtp_sub_flow_t* mmtp_sub_flow);

void dumpMpu(demux_t *p_demux, block_t *mpu);
void dumpMfu(demux_t *p_demux, block_t *mpu);
void dumpReassembeled(demux_t *p_demux, block_t *mpu, uint32_t mpu_sequence_number, uint32_t mpu_sample_number);



/*****************************************************************************
 * borrowed from libmp4 -
 *****************************************************************************/

const uint32_t rgi_pict_atoms[2] = { ATOM_PICT, ATOM_pict };
const char *psz_meta_roots[] = { "/moov/udta/meta/ilst",
                                 "/moov/meta/ilst",
                                 "/moov/udta/meta",
                                 "/moov/udta",
                                 "/meta/ilst",
                                 "/udta",
                                 NULL };

static void MP4_TrackSetup( demux_t *, mpu_isobmff_fragment_parameters_t* isobmff_parameters, mp4_track_t *, MP4_Box_t  *, bool, bool );
static void MP4_TrackInit( mp4_track_t * );
static MP4_Box_t * MP4_GetTrexByTrackID( MP4_Box_t *p_moov, const uint32_t i_id );
static int CreateTracks( mpu_isobmff_fragment_parameters_t *isobmff_parameters, unsigned i_tracks );

static stime_t GetMoovTrackDuration( demux_sys_t *p_sys, unsigned i_track_ID );

static int  ProbeFragments( demux_t *p_demux, mpu_isobmff_fragment_parameters_t* isobmff_parameters, bool b_force, bool *pb_fragmented );

//short reads from UDP may happen on starutp buffering or truncation
#define MAX_MMT_REFRAGMENT_SIZE 65535


/**
 *
 * keycode mapping:
 *
 * Marquee
 *
 * key   	keycode  	OSD display
 * ---   	-------  	-----------
 * a     	97       	show show nrt/gfd messages
 * c     	99       		* 3.0 show SLS messages
 *
 * i     	105    		show packet_id's and video/audio identificaion
 *
 * l	 	108        		* 3.0 show LLS messages from 224.0.23.60/4937
 * p     	112    		show pps and packet loss statistics via packet counter gaps
 * s    	115			show signalling messages
 * key-up	2293760			* 3.0 increment channel
 * key-down 2359296			* 3.0 decrement channel
 */


static int vlc_key_to_action (vlc_object_t *obj, const char *varname, vlc_value_t prevkey, vlc_value_t curkey, void *d)
{
    void *const *map = d;
    const struct mapping **pent;
    uint32_t keycode = curkey.i_int;
    msg_Dbg(obj, "%d:key_to_action, keycode: %u", __LINE__, keycode);

    vlc_object_t *my_object_ref = d;

 //   vlc_object_t *my_object_ref = obj;

    switch(keycode) {

    	case 105:

    		activate_info_subtitle(my_object_ref);

//    		filter_chain_t *p_chain;
//			filter_owner_t owner;
//			memset(&owner, 0, sizeof(owner));
//		//	owner.video = &transcode_filter_video_cbs;
//			p_chain = filter_chain_NewVideo(obj, false, &owner);
//
//    		if(!p_chain)
//    			return NULL;
//    		filter_chain_AppendFilter(p_chain, "marq", )
//    		filter_chain_Reset(p_chain, p_srcfmt, &requestedoutput);
//    		filter_chain_AppendFilter()

    		break;


    }

    return VLC_SUCCESS;
}



/*
 * Initializes the MMTP demuxer
 *
 * set some default values and init our mmtp sub flow vector for re-assembly
 */

static int Open( vlc_object_t * p_this )
{
    demux_t *p_demux = (demux_t*)p_this;
    demux_sys_t *p_sys = NULL;

    p_demux->pf_demux = Demux;
    p_demux->pf_control = Control;

    p_sys = calloc( 1, sizeof( demux_sys_t ) );


    if ( !p_sys )
          return VLC_EGENERIC;

    p_demux->p_sys = p_sys;

    p_sys->obj = p_this;
    p_sys->context.i_lastseqnumber = UINT32_MAX;
    p_sys->p_mpu_block = NULL;

//    p_sys->b_seekable = true;
//    p_sys->b_fragmented = true;

    //vlc_stream_fifo doesn't support seeking, which is required for libmp4 box parsing, so double buffer into s_frag

    p_sys->last_mpu_sequence_number = -1;
    p_sys->last_mpu_fragment_type = -1;
    p_sys->has_processed_ftype_moov = 0;

    mmtp_sub_flow_vector_init(&p_sys->mmtp_sub_flow_vector);


    var_Create(VLC_OBJECT(p_this)->obj.libvlc, "key-pressed", VLC_VAR_INTEGER);
    var_AddCallback(p_this->obj.libvlc, "key-pressed", vlc_key_to_action, (void*)p_this);


    __LOG_INFO(p_demux, "mmtp_demuxer.open() - complete, p_sys->mmtp_sub_flow_vector is: %p", p_sys->mmtp_sub_flow_vector);

    return VLC_SUCCESS;
}


/**
 * Destroys the MMTP-demuxer
 *
 * todo: clear our re-assembly vectors
 */
static void Close( vlc_object_t *p_this )
{
    demux_t *p_demux = (demux_t*)p_this;
	demux_sys_t *p_sys = p_demux->p_sys;


    if(p_sys) {
    	free(p_sys);
    }
    p_demux->p_sys = NULL;

    __LOG_INFO(p_demux, "mmtp_demuxer.close()");
}

/**
 *
 * mmtp demuxer,
 * 	rebuild UDP packets into one MFU packet, push to es for output
 *
 * 	todo:
 * 		decode
 *
 * use p_sys->s for udp,
 * use p_sys->s_frag for fragmented mp4 demux / decoding
 *
 */

static int Demux( demux_t *p_demux )
{
	demux_sys_t *p_sys = p_demux->p_sys;
	mmtp_sub_flow_vector_t *mmtp_sub_flow_vector = &p_sys->mmtp_sub_flow_vector;
	mmtp_sub_flow_t *mmtp_sub_flow = NULL;
	mmtp_payload_fragments_union_t *mmtp_packet_header = NULL;
	block_t *mmtp_raw_packet_block;

	ssize_t mmtp_raw_packet_size = -1;

	//__LOG_INFO(p_demux, "mmtp_demuxer.demux()");

    /* Get a new MMTP packet, use p_demux->s as the blocking reference and 1514 as the max mtu in udp.c*/
    //vlc_stream_Block will try and fill MAX_MTU_SIZE instead of relying on the
    //  MMTP udp frame size
    //readPartial still reads a block_chain
    // if( !( mmtp_raw_packet_size = vlc_stream_ReadPartial( p_demux->s, (void*)rawBuf, MAX_MMTP_SIZE ) ) )

	block_t *read_block;

    if( !( read_block = vlc_stream_ReadBlock( p_demux->s) ) )
    {
		msg_Err( p_demux, "mmtp_demuxer - access request returned null!");
		return VLC_DEMUXER_SUCCESS;
	}

    __LOG_TRACE(p_demux, "%d:mmtp_demuxer: vlc_stream_readblock size is: %d", __LINE__, read_block->i_buffer);
    mmtp_raw_packet_size =  read_block->i_buffer;

   	if( mmtp_raw_packet_size > MAX_MMTP_SIZE || mmtp_raw_packet_size < MIN_MMTP_SIZE) {
   		msg_Err( p_demux, "%d:mmtp_demuxer - size from UDP was under/over heureis/max, dropping %d bytes", __LINE__, mmtp_raw_packet_size);
   		//   		free(raw_buf); //only free raw_buf
   		return VLC_DEMUXER_SUCCESS;
   	}


	mmtp_raw_packet_block = block_Duplicate(read_block);

	mmtp_packet_header = mmtp_packet_header_allocate_from_raw_packet(mmtp_raw_packet_block);

	int i_status = mmtp_packet_header_parse_from_raw_packet(mmtp_packet_header, p_demux);


	if(i_status != VLC_DEMUXER_SUCCESS) {
   		msg_Err( p_demux, "%d:mmtp_demuxer - mmtp_packet_header_parse_from_raw_packet failed, dropping packet", __LINE__);

   		return VLC_DEMUXER_SUCCESS;
	}



	/*****
	 * checkpoint for vlc de-factorting
	 */







	//resync our buf positions
	uint8_t *raw_buf = p_sys->raw_buf;
	uint8_t *buf = p_sys->buf;

	//create a sub_flow with this packet_id
	__LOG_DEBUG( p_demux, "%d:mmtp_demuxer, after mmtp_packet_header_parse_from_raw_packet, mmtp_packet_id is: %d, mmtp_payload_type: 0x%x, packet_counter: %d, remaining len: %d, mmtp_raw_packet_size: %d, buf: %p, raw_buf:%p",
			__LINE__,
			mmtp_packet_header->mmtp_packet_header.mmtp_packet_id,
			mmtp_packet_header->mmtp_packet_header.mmtp_payload_type,
			mmtp_packet_header->mmtp_packet_header.packet_counter,
			(mmtp_raw_packet_size - (buf - raw_buf)),
			mmtp_raw_packet_size,
			buf,
			raw_buf);

	mmtp_sub_flow = mmtp_sub_flow_vector_get_or_set_packet_id(mmtp_sub_flow_vector, mmtp_packet_header->mmtp_packet_header.mmtp_packet_id);
	__LOG_DEBUG( p_demux, "%d:mmtp_demuxer - mmtp_sub_flow is: %p, mmtp_sub_flow->mpu_fragments: %p", __LINE__, mmtp_sub_flow, mmtp_sub_flow->mpu_fragments);

	//push this to the proper fragment container, continue parsing below
	mmtp_sub_flow_push_mmtp_packet(mmtp_sub_flow, mmtp_packet_header);

	//if our header extension length is set, then block extract the header extension length, adn we should be at our payload data
	uint8_t *mmtp_header_extension_value = NULL;

	if(mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_flag & 0x1) {
		//clamp mmtp_header_extension_length
		mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_length = MIN(mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_length, 2^16);

		__LOG_DEBUG( p_demux, "mmtp_header_extension_flag, header extension size: %d, packet version: %d, payload_type: 0x%X, packet_id 0x%hu, timestamp: 0x%X, packet_sequence_number: 0x%X, packet_counter: 0x%X",
				mmtp_packet_header->mmtp_packet_header.mmtp_packet_version,
				mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_length,
				mmtp_packet_header->mmtp_packet_header.mmtp_payload_type,
				mmtp_packet_header->mmtp_packet_header.mmtp_packet_id,
				mmtp_packet_header->mmtp_packet_header.mmtp_timestamp,
				mmtp_packet_header->mmtp_packet_header.packet_sequence_number,
				mmtp_packet_header->mmtp_packet_header.packet_counter);

		mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_value = malloc(mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_length);
		//read the header extension value up to the extension length field 2^16
		buf = extract(buf, &mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_value, mmtp_packet_header->mmtp_packet_header.mmtp_header_extension_length);
	}

	if(mmtp_packet_header->mmtp_packet_header.mmtp_payload_type == 0x1) {
		msg_Warn(p_demux, "%d:mmtp_payload_type: DROPPING payload: 0x1 - generic object", __LINE__);
		goto done;
	}

	if(mmtp_packet_header->mmtp_packet_header.mmtp_payload_type == 0x2) {
		msg_Warn(p_demux, "%d:mmtp_payload_type: DROPPING payload: 0x2 - signalling message", __LINE__);
		goto done;
	}

	if(mmtp_packet_header->mmtp_packet_header.mmtp_payload_type == 0x0) {
		//VECTOR:  TODO - refactor this into helper method

		//pull the mpu and frag iformation

		uint8_t mpu_payload_length_block[2];
		uint16_t mpu_payload_length = 0;

		//msg_Warn( p_demux, "buf pos before mpu_payload_length extract is: %p", (void *)buf);
		buf = extract(buf, &mpu_payload_length_block, 2);
		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_payload_length = (mpu_payload_length_block[0] << 8) | mpu_payload_length_block[1];
		//__LOG_DEBUG( p_demux, "mmtp_demuxer - doing mpu_payload_length: %hu (0x%X 0x%X)",  mpu_payload_length, mpu_payload_length_block[0], mpu_payload_length_block[1]);

		uint8_t mpu_fragmentation_info;
		//msg_Warn( p_demux, "buf pos before extract is: %p", (void *)buf);
		buf = extract(buf, &mpu_fragmentation_info, 1);

		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragment_type = (mpu_fragmentation_info & 0xF0) >> 4;
		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_timed_flag = (mpu_fragmentation_info & 0x8) >> 3;
		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator = (mpu_fragmentation_info & 0x6) >> 1;
		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_aggregation_flag = (mpu_fragmentation_info & 0x1);

		__LOG_DEBUG( p_demux, "%d:mmtp_demuxer - mmtp packet: mpu_fragmentation_info is: 0x%x, mpu_fragment_type: 0x%x, mpu_timed_flag: 0x%x, mpu_fragmentation_indicator: 0x%x, mpu_aggregation_flag: 0x%x",
					__LINE__,
					mpu_fragmentation_info,
					mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragment_type,
					mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_timed_flag,
					mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator,
					mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_aggregation_flag);



		uint8_t mpu_fragmentation_counter;
		//msg_Warn( p_demux, "buf pos before extract is: %p", (void *)buf);
		buf = extract(buf, &mpu_fragmentation_counter, 1);
		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragmentation_counter = mpu_fragmentation_counter;

		//re-fanagle
		uint8_t mpu_sequence_number_block[4];

		buf = extract(buf, &mpu_sequence_number_block, 4);
		mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_sequence_number = (mpu_sequence_number_block[0] << 24)  | (mpu_sequence_number_block[1] <<16) | (mpu_sequence_number_block[2] << 8) | (mpu_sequence_number_block[3]);
		__LOG_DEBUG( p_demux, "%d:mmtp_demuxer - mmtp packet: mpu_payload_length: %hu (0x%X 0x%X), mpu_fragmentation_counter: %d, mpu_sequence_number: %d",
				__LINE__,
				mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_payload_length,
				mpu_payload_length_block[0],
				mpu_payload_length_block[1],
				mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragmentation_counter,
				mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_sequence_number);


		mpu_fragments_assign_to_payload_vector(mmtp_sub_flow, mmtp_packet_header);

		//VECTOR: assign data unit payload once parsed, eventually replacing processMpuPacket

		int remainingPacketLen = -1;

		//todo - if FEC_type != 0, parse out source_FEC_payload_ID trailing bits...
		do {
			//pull out aggregate packets data unit length
			int to_read_packet_length = -1;
			//mpu_fragment_type

			//only read DU length if mpu_aggregation_flag=1
			if(mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_aggregation_flag) {
				uint8_t data_unit_length_block[2];
				buf = extract(buf, &data_unit_length_block, 2);
				mmtp_packet_header->mmtp_mpu_type_packet_header.data_unit_length = (data_unit_length_block[0] << 8) | (data_unit_length_block[1]);
				to_read_packet_length = mmtp_packet_header->mmtp_mpu_type_packet_header.data_unit_length;
				__LOG_DEBUG(p_demux, "%d:mpu data unit size: %d, mpu_aggregation_flag:1, to_read_packet_length: %d",
						__LINE__, mmtp_packet_header->mmtp_mpu_type_packet_header.data_unit_length, to_read_packet_length);

			} else {
				to_read_packet_length = mmtp_raw_packet_size - (buf-raw_buf);
				__LOG_DEBUG(p_demux, "%d:skipping data_unit_size: mpu_aggregation_flag:0, raw packet size: %d, buf: %p, raw_buf: %p, to_read_packet_length: %d",
						__LINE__, mmtp_raw_packet_size, buf, raw_buf, to_read_packet_length);
			}

			//if we are MPU metadata or movie fragment metadatas
			if(mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_fragment_type != 0x2) {
				//read our packet length just as a mpu metadata fragment or movie fragment metadata
				//read our packet length without any mfu
				block_t *tmp_mpu_fragment = block_Alloc(to_read_packet_length);
				__LOG_DEBUG(p_demux, "%d::creating tmp_mpu_fragment, setting block_t->i_buffer to: %d", __LINE__, to_read_packet_length);

				buf = extract(buf, tmp_mpu_fragment->p_buffer, to_read_packet_length);
				tmp_mpu_fragment->i_buffer = to_read_packet_length;

				mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_data_unit_payload = block_Duplicate(tmp_mpu_fragment);

				processMpuPacket(p_demux, mmtp_sub_flow, mmtp_packet_header);

				remainingPacketLen = mmtp_raw_packet_size - (buf - raw_buf);
				//this should only be non-zero if mpu_aggregration_flag=1
				//__LOG_INFO(p_demux, "%d::mpu_fragment_type: %hu, remainingPacketLen: %d", __LINE__, mpu_fragment_type, remainingPacketLen);

			} else {
				//mfu's have time and un-timed additional DU headers, so recalc to_read_packet_len after doing extract
				//we use the du_header field
				//parse data unit header here based upon mpu timed flag

				/**
				* MFU mpu_fragmentation_indicator==1's are prefixed by the following box, need to remove
				*
				aligned(8) class MMTHSample {
				   unsigned int(32) sequence_number;
				   if (is_timed) {

					//interior block is 152 bits, or 19 bytes
					  signed int(8) trackrefindex;
					  unsigned int(32) movie_fragment_sequence_number
					  unsigned int(32) samplenumber;
					  unsigned int(8)  priority;
					  unsigned int(8)  dependency_counter;
					  unsigned int(32) offset;
					  unsigned int(32) length;
					//end interior block

					  multiLayerInfo();
				} else {
						//additional 2 bytes to chomp for non timed delivery
					  unsigned int(16) item_ID;
				   }
				}

				aligned(8) class multiLayerInfo extends Box("muli") {
				   bit(1) multilayer_flag;
				   bit(7) reserved0;
				   if (multilayer_flag==1) {
					   //32 bits
					  bit(3) dependency_id;
					  bit(1) depth_flag;
					  bit(4) reserved1;
					  bit(3) temporal_id;
					  bit(1) reserved2;
					  bit(4) quality_id;
					  bit(6) priority_id;
				   }  bit(10) view_id;
				   else{
					   //16bits
					  bit(6) layer_id;
					  bit(3) temporal_id;
					  bit(7) reserved3;
				} }
				*/

				uint8_t mmthsample_len;
				uint8_t mmthsample_sequence_number[4];

				if(mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_timed_flag) {

				//	uint16_t seconds;
				//	uint16_t microseconds;
					compute_ntp32_to_seconds_microseconds(mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp, &mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp_s, &mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp_us);
					__LOG_INFO(p_demux, "%d: converting mmtp_timestamp: %u to seconds: %hu, microseconds: %hu", __LINE__, mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp, mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp_s, mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp_us);
					//on first init, p_sys->first_pts will always be 0 from calloc
					uint64_t pts = compute_relative_ntp32_pts(p_sys->first_pts, mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp_s, mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mmtp_timestamp_us);
					if(!p_sys->has_set_first_pts) {
						p_sys->first_pts = pts;
						p_sys->has_set_first_pts = 1;
					}

					//build our PTS
					mmtp_packet_header->mpu_data_unit_payload_fragments_timed.pts = pts;

					//112 bits in aggregate, 14 bytes
					uint8_t timed_mfu_block[14];
					buf = extract(buf, timed_mfu_block, 14);

					mmtp_packet_header->mpu_data_unit_payload_fragments_timed.movie_fragment_sequence_number 	= (timed_mfu_block[0] << 24) | (timed_mfu_block[1] << 16) | (timed_mfu_block[2]  << 8) | (timed_mfu_block[3]);
					mmtp_packet_header->mpu_data_unit_payload_fragments_timed.sample_number				 	  	= (timed_mfu_block[4] << 24) | (timed_mfu_block[5] << 16) | (timed_mfu_block[6]  << 8) | (timed_mfu_block[7]);
					mmtp_packet_header->mpu_data_unit_payload_fragments_timed.offset     					  	= (timed_mfu_block[8] << 24) | (timed_mfu_block[9] << 16) | (timed_mfu_block[10] << 8) | (timed_mfu_block[11]);
					mmtp_packet_header->mpu_data_unit_payload_fragments_timed.priority 							= timed_mfu_block[12];
					mmtp_packet_header->mpu_data_unit_payload_fragments_timed.dep_counter						= timed_mfu_block[13];

					//parse out mmthsample block if this is our first fragment or we are a complete fragment,
					if(mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_indicator == 0 || mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_indicator == 1) {

						//MMTHSample does not subclass box...
						//buf = extract(buf, &mmthsample_len, 1);
						buf = extract(buf, mmthsample_sequence_number, 4);

						uint8_t mmthsample_timed_block[19];
						buf = extract(buf, mmthsample_timed_block, 19);

						//read multilayerinfo
						uint8_t multilayerinfo_box_length[4];
						uint8_t multilayerinfo_box_name[4];
						uint8_t multilayer_flag;

						buf = extract(buf, multilayerinfo_box_length, 4);
						buf = extract(buf, multilayerinfo_box_name, 4);

						buf = extract(buf, &multilayer_flag, 1);

						int is_multilayer = (multilayer_flag >> 7) & 0x01;
						//if MSB is 1, then read multilevel struct, otherwise just pull layer info...
						if(is_multilayer) {
							uint8_t multilayer_data_block[4];
							buf = extract(buf, multilayer_data_block, 4);

						} else {
							uint8_t multilayer_layer_id_temporal_id[2];
							buf = extract(buf, multilayer_layer_id_temporal_id, 2);
						}

						__LOG_INFO(p_demux, "%d:mpu mode (0x02), timed MFU, mpu_fragmentation_indicator: %d, movie_fragment_seq_num: %u, sample_num: %u, offset: %u, pri: %d, dep_counter: %d, multilayer: %d, mpu_sequence_number: %u",
							__LINE__,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_indicator,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.movie_fragment_sequence_number,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.sample_number,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.offset,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.priority,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.dep_counter,
							is_multilayer,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mpu_sequence_number);
					} else {
						__LOG_INFO(p_demux, "%d:mpu mode (0x02), timed MFU, mpu_fragmentation_indicator: %d, movie_fragment_seq_num: %u, sample_num: %u, offset: %u, pri: %d, dep_counter: %d, mpu_sequence_number: %u",
							__LINE__,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_indicator,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.movie_fragment_sequence_number,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.sample_number,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.offset,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.priority,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.dep_counter,
							mmtp_packet_header->mpu_data_unit_payload_fragments_timed.mpu_sequence_number);
					}
					//end mfu box read

					to_read_packet_length = mmtp_raw_packet_size - (buf - raw_buf);
				} else {
					uint8_t non_timed_mfu_block[4];
					uint32_t non_timed_mfu_item_id;
					//only 32 bits
					buf = extract(buf, non_timed_mfu_block, 4);
					mmtp_packet_header->mpu_data_unit_payload_fragments_nontimed.non_timed_mfu_item_id = (non_timed_mfu_block[0] << 24) | (non_timed_mfu_block[1] << 16) | (non_timed_mfu_block[2] << 8) | non_timed_mfu_block[3];

					if(mmtp_packet_header->mpu_data_unit_payload_fragments_nontimed.mpu_fragmentation_indicator == 1) {
						//MMTHSample does not subclass box...
						//buf = extract(buf, &mmthsample_len, 1);

						buf = extract(buf, mmthsample_sequence_number, 4);

						uint8_t mmthsample_item_id[2];
						buf = extract(buf, mmthsample_sequence_number, 2);
						//end reading of mmthsample box
					}

					__LOG_DEBUG(p_demux, "mpu mode (0x02), non-timed MFU, item_id is: %zu", mmtp_packet_header->mpu_data_unit_payload_fragments_nontimed.non_timed_mfu_item_id);
					to_read_packet_length = mmtp_raw_packet_size - (buf - raw_buf);
				}

				__LOG_TRACE( p_demux, "%d:before reading fragment packet: reading length: %d (mmtp_raw_packet_size: %d, buf: %p, raw_buf:%p)",
						__LINE__,
						to_read_packet_length,
						mmtp_raw_packet_size,
						buf,
						raw_buf);

				block_t *tmp_mpu_fragment = block_Alloc(to_read_packet_length);
				//__LOG_INFO(p_demux, "%d::creating tmp_mpu_fragment, setting block_t->i_buffer to: %d", __LINE__, to_read_packet_length);

				buf = extract(buf, tmp_mpu_fragment->p_buffer, to_read_packet_length);
				tmp_mpu_fragment->i_buffer = to_read_packet_length;
				tmp_mpu_fragment->i_pts = mmtp_packet_header->mpu_data_unit_payload_fragments_timed.pts;
				tmp_mpu_fragment->i_length = 16683;

				mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_data_unit_payload = block_Duplicate(tmp_mpu_fragment);

				//send off only the CLEAN mdat payload from our MFU
				processMpuPacket(p_demux, mmtp_sub_flow, mmtp_packet_header);

				remainingPacketLen = mmtp_raw_packet_size - (buf - raw_buf);
				__LOG_TRACE( p_demux, "%d:after reading fragment packet: remainingPacketLen: %d",
										__LINE__,
										remainingPacketLen);

			}

		} while(mmtp_packet_header->mmtp_mpu_type_packet_header.mpu_aggregation_flag && remainingPacketLen>0);
	}

	__LOG_TRACE(p_demux, "%d:demux - return", __LINE__);

done:
	return VLC_DEMUXER_SUCCESS;
}


/** todo - add
 * DEMUX_SET_GROUP_DEFAULT ?
 *
 * DEMUX_FILTER_DISABLE
 *
 */
static int Control( demux_t *p_demux, int i_query, va_list args )
{
   // __LOG_INFO(p_demux, "control: query is: %d", i_query);
	demux_sys_t *p_sys = p_demux->p_sys;

    bool *pb;
    double f, *pf;

    unsigned *flags;

    switch ( i_query )
    {
    	case DEMUX_CAN_SEEK:
        case DEMUX_CAN_PAUSE:
        case DEMUX_CAN_CONTROL_PACE:
            pb = va_arg ( args, bool* );
            *pb = false;
            break;


        case DEMUX_GET_PTS_DELAY:
                    *va_arg( args, vlc_tick_t * ) =1000000;
        	return VLC_SUCCESS;

        case DEMUX_GET_META:
        case DEMUX_GET_SIGNAL:
        case DEMUX_GET_TITLE:
        case DEMUX_GET_SEEKPOINT:
        case DEMUX_GET_TITLE_INFO:
        case DEMUX_IS_PLAYLIST:
        	return VLC_EGENERIC;
        //position is from range of 0-1, s0 just report 0.0
        case DEMUX_GET_POSITION:
        	pf = va_arg( args, double * );
        	*pf = 0.0;
        	return VLC_SUCCESS;

        case DEMUX_GET_LENGTH:
			*va_arg ( args, vlc_tick_t * ) = 0;

			//	vlc_tick_from_sec( p_sys->frames_total * p_sys->frame_rate_denom / p_sys->frame_rate_num );
			break;


		case DEMUX_GET_TIME:
			*va_arg( args, vlc_tick_t * ) = p_sys->last_pts - p_sys->first_pts;
			break;

        case DEMUX_GET_ATTACHMENTS:
        	return VLC_EGENERIC;
        	break;
    }

    return VLC_SUCCESS; //demux_vaControlHelper( p_demux->s, 0, -1, 0, 1, i_query, args );

}

/**
 * only flush out mpu packet when our mpq_sequence_id changes
 *
 *
 * if(mpu_fragment_type == 0 && !tracksConfigured) then
 *
 * 		LoadInitFrag ?
 * 			if( ( p_ftyp = MP4_BoxGet( mmtp_sub_flow->mpu_fragments_p_root_box, "/ftyp" ) ) )
 * 			getMvhd
 * 			createTracks
 * 				es_out_Add
 * else if(mpu_fragment_type == 2) then
 *
 * 	es_out_Send
 *
 *
 *void getMvhd() {

	p_mvhd = MP4_BoxGet( p_sys->p_moov, "mvhd" );
	if( p_mvhd && BOXDATA(p_mvhd) && BOXDATA(p_mvhd)->i_timescale )
	{
		p_sys->i_timescale = BOXDATA(p_mvhd)->i_timescale;
		p_sys->i_moov_duration = p_sys->i_duration = BOXDATA(p_mvhd)->i_duration;
		p_sys->i_cumulated_duration = BOXDATA(p_mvhd)->i_duration;
	}
	else
	{
		msg_Warn( p_demux, "No valid mvhd found" );
		//goto error;
	}
}
 */

/**
 * ala java multiKeyMap
 * map of <mmtp_packet_id, mpu_sequence_number, movie_fragment_sequence_number> => mpu
 * mpu {
 * 	mpu_metadata - contains ftyp/mmpu/moov/meta boxes for <packet_id> key
 * 	movie_fragment_metadata - contains moof/mdat boxes for <packet_id, mpu_sequence_number> mfu's
 * 	mfu - media_fragment_unit
 *
 *  if(timed) movie_fragment_sequence_number
 * 	mpu_fragment first_mpu_fragment
 *  TreeSet<mpu_fragment>::ordered sample_number
 *
 * 	last_fragment
 *mmtp_mpu_type_packet_header_fields_t
 *mmtp_payload_fragments_union_t
 */

//mpu_type_packet->mmtp_mpu_type_packet_header.

void processMpuPacket(demux_t* p_obj, mmtp_sub_flow_t *mmtp_sub_flow, mmtp_payload_fragments_union_t* mpu_type_packet) {

    mpu_isobmff_fragment_parameters_t *isobmff_parameters = &mmtp_sub_flow->mpu_fragments->mpu_isobmff_fragment_parameters;

    block_t* tmp_mpu_fragment = mpu_type_packet->mmtp_mpu_type_packet_header.mpu_data_unit_payload;

    __LOG_DEBUG(p_obj, "%d:processMpuPacket - mmtp_sub_flow.packet_id is: %hu, mmtp_sub_flow.mpu_fragments_p_root_box is: %p, mpu_sequence_number: %u, mpu_fragment_type: 0x%x, mpu_fragmentation_indicator: 0x%x, sample_num: %d, offset: %d",
					__LINE__, mmtp_sub_flow->mmtp_packet_id,
					isobmff_parameters->mpu_fragments_p_root_box,
					mpu_type_packet->mmtp_mpu_type_packet_header.mpu_sequence_number,
					mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type,
					mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator,
					mpu_type_packet->mpu_data_unit_payload_fragments_timed.sample_number,
					mpu_type_packet->mpu_data_unit_payload_fragments_timed.offset);
//	, mpu_sample_number, mpu_offset, mpu_fragment_type, mpu_fragmentation_indicator, (void*) tmp_mpu_fragment, (void*)p_sys->p_mpu_block);

	//only flush out and process the MPU if our sequence number has incremented
	//TODO - check mmpu box for is_complete for mpu_sequence_number, use or conditional as mpu_seuqence_number is uint32...
	//p_sys->last_mpu_sequence_number == -1 &&

    //
    //if our mpu_fragment type is either MPU metadata (0x00 - ftyp) or Fragment metadata (0x01 - moof)

    /**
     *
     todo - extract moof sample count per track: for complete mpu reassembly visibility
	 dg-komo-mac148:mfu jjustman$ mp4dump 109140-2

[moof] size=8+1092
  [mfhd] size=12+4
    sequence number = 1
  [traf] size=8+1016
    [tfhd] size=12+4, flags=20000
      track ID = 1
    [tfdt] size=12+8, version=1
      base media decode time = 0
    [trun] size=12+968, flags=f01
      sample count = 60
      data offset = 1108
  [traf] size=8+44
    [tfhd] size=12+12, flags=20018
      track ID = 2
      default sample duration = 1
      default sample size = 34
    [trun] size=12+8, flags=1
      sample count = 60
      data offset = 319533
      */

	if(mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type == 0x00 || mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type == 0x01) {
		__LOG_DEBUG(p_obj, "%d:processMpuPacket - mpu_fragment_type: %d, root_box: %p, moov_box: %p",
																			__LINE__,
																			mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type,
																			isobmff_parameters->mpu_fragments_p_root_box,
																			isobmff_parameters->mpu_fragments_p_moov);

		if(mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type == 0x00 && !isobmff_parameters->mpu_fragments_p_root_box) {
			__LOG_DEBUG(p_obj, "%d:processMpuPacket - MPU metadata - creating new root_box", __LINE__ );

			//firts, make a copy of the block_t buffer for re-constituion later with movie fragment metadata
			isobmff_parameters->mpu_fragment_block_t = block_Duplicate(tmp_mpu_fragment);

			stream_t* tmp_box_stream = vlc_stream_MemoryNew( p_obj, isobmff_parameters->mpu_fragment_block_t->p_buffer, isobmff_parameters->mpu_fragment_block_t->i_buffer, true);
			MP4_Box_t *p_root = MP4_BoxGetRoot(tmp_box_stream);
		    if(!p_root) {
		        msg_Warn( p_obj, "%d:processMpuPacket - MPU: MP4_BoxGetRoot returned null", __LINE__);
		        return;
		    }

		    isobmff_parameters->mpu_fragments_p_root_box = p_root;
		    isobmff_parameters->mpu_fragments_p_moov = MP4_BoxGet(p_root, "/moov" );

		    __LOG_DEBUG(p_obj, "%d:processMpuPacket - MP4_BoxGetRoot, p_root: %p", __LINE__, isobmff_parameters->mpu_fragments_p_root_box);

			//remap into p_demux

		    __LOG_DEBUG(p_obj, "%d:processMpuPacket - createTracksFromMpuMetadata, !p_root_box", __LINE__ );

			createTracksFromMpuMetadata(p_obj, mmtp_sub_flow);
			if( isobmff_parameters->track[0].fmt.i_cat == VIDEO_ES ) {
				__VIDEO_OUTPUT_ES_FORMAT = &isobmff_parameters->track[0].fmt;
			}

		   //dont delete stream fragment here
		//	vlc_stream_Delete(tmp_mpu_fragment_stream);

		} else if(mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type == 0x01) {

			//get our isobmff_parameters->mp4_mpu_metadata_box_s =  vlc_stream_MemoryNew( p_obj, tmp_mpu_fragment->p_buffer, tmp_mpu_fragment->i_buffer, true);
			//and combine with our movie fragment metadata
			block_t *first = calloc(1, sizeof(block_t));
			block_t **reassembled_mpu = &first;
			block_ChainLastAppend(&reassembled_mpu, block_Duplicate(isobmff_parameters->mpu_fragment_block_t));
			block_ChainLastAppend(&reassembled_mpu, block_Duplicate(tmp_mpu_fragment));
			isobmff_parameters->mp4_movie_fragment_block_t = block_ChainGather(first);
#define __REPARSE_MFU 1
#ifdef __REPARSE_MFU

			stream_t* tmp_box_stream = vlc_stream_MemoryNew( p_obj, isobmff_parameters->mp4_movie_fragment_block_t->p_buffer, isobmff_parameters->mp4_movie_fragment_block_t->i_buffer, true);

			MP4_Box_t *p_moof = MP4_BoxGetRoot(tmp_box_stream);
			if(!p_moof) {
				msg_Warn( p_obj, "%d:processMpuPacket - MovieFragmentMetadata: MP4_BoxGetRoot returned null", __LINE__);
				return;
			}
			isobmff_parameters->mpu_fragments_p_moof =  MP4_BoxGet(p_moof, "/moof");

		    msg_Warn(p_obj, "%d:processMpuPacket - MP4_BoxGetRoot, p_moof: %p ", __LINE__, isobmff_parameters->mpu_fragments_p_moof);

			//TODO - parsae out
//			 [traf] size=8+1016
//			    [tfhd] size=12+4, flags=20000
//			      track ID = 1
//			    [tfdt] size=12+8, version=1
//			      base media decode time = 0
//			    [trun] size=12+968, flags=f01
//			      sample count = 60
//			      data offset = 1108
//			      entry 0000 = sample_duration:16683, sample_size:89965, sample_flags:2000000, sample_composition_time_offset:50050

			__LOG_DEBUG(p_obj, "%d:processMpuPacket - fragment metadata - mpu_fragment_type=0x%x, p_root_box: %p",
					__LINE__,
					mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type,
					isobmff_parameters->mpu_fragments_p_root_box );

#endif
		}
		return;
	}

	if(!isobmff_parameters->mpu_fragments_p_root_box) {
		msg_Warn(p_obj, "%d:processMpuPacket - no mpu_fragments_p_root_box! fragment metadata - mpu_fragment_type=0x%x, p_root_box: %p",
							__LINE__,
							mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type,
							isobmff_parameters->mpu_fragments_p_root_box );
		return;
	}


	int i_track = 0;
    mp4_track_t *p_track = &isobmff_parameters->track[i_track];

	//set dummy PCR for now...
	struct timespec ts;
	timespec_get(&ts, TIME_UTC);

	uint64_t t = ((ts.tv_sec) * uS) + ((ts.tv_nsec) / 1000ULL) ; // convert tv_sec & tv_usec to millisecond
	demux_sys_t *p_sys_priv = p_obj->p_sys;
	if(!p_sys_priv->has_set_first_pcr) {
		p_sys_priv->first_pcr = t;
	}
	//uint64_t new_pcr = t - p_sys_priv->first_pcr;
	uint64_t pcr_buf = 4000000; //250000
	//msg_Info(p_obj, "%d:mpu pts is: %llu", __LINE__, mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts);

	//
	uint64_t new_pcr = mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts > pcr_buf ? mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts - pcr_buf : mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts;

	//convert to microseconds
//	es_out_SetPCR( p_obj->out, new_pcr);

//	msg_Info(p_obj, "%d:es_out_setPcr, compairing from new: %	llu, to last: %llu", new_pcr, mpu_type_packet->mpu_data_unit_payload_fragments_timed.last_pt);


	if(!p_sys_priv->has_set_first_pcr && new_pcr > mpu_type_packet->mpu_data_unit_payload_fragments_timed.last_pts ) {
	//	msg_Info(p_obj, "%d:es_out_setPcr - using PTS-buf: %llu", __LINE__, new_pcr);

		es_out_SetPCR(p_obj->out, new_pcr);
		p_sys_priv->has_set_first_pcr = 1;

	// 	mpu_type_packet->mpu_data_unit_payload_fragments_timed.last_pts = new_pcr;
	}

	//es_out_SetPCR(p_obj->out, mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts);

	//allow for single audio fragment push
	if( isobmff_parameters->track[i_track].fmt.i_cat == AUDIO_ES ) {
		if(mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator == 0x00) {
			tmp_mpu_fragment->i_length = 21333;

			//audio samples should be at
			//entry 0000 = sample_duration:21333, sample_size:512, sample_flags:2000000, sample_composition_time_offset:0
			//entry 0001 = sample_duration:21333, sample_size:513, sample_flags:10000, sample_composition_time_offset:0

			if(mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts) {
				msg_Info(p_obj, "%d: setting tmp_mpu_fragment.pts = %llu, pcr: %llu, last_pts: %llu", __LINE__, mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts, new_pcr, p_sys_priv->last_pts);
				tmp_mpu_fragment->i_pts = mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts;
			}

			es_out_Send( p_obj->out, p_track->p_es, tmp_mpu_fragment);

			if(mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts) {
				p_sys_priv->last_pts = mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts;
			}

		} else {
			msg_Err(p_obj, "%d:process_packet - dropping fragmented audio!", __LINE__);
		}
	}

#ifdef __SINGLE_MFU_PUSH
	if(mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator == 0x00) {
		//TODO - use traf/tfdt for actual sample decoding time based upon mvhd.timescale (p_sys->i_timescale)
		//for now, use the rational 1001 * uS / 60000 * uS ~ 16000us

		if(mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts) {
			msg_Info(p_obj, "%d: setting tmp_mpu_fragment.pts = %llu, pcr: %llu, last_pts: %llu", __LINE__, mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts, new_pcr, p_sys_priv->last_pts);
			tmp_mpu_fragment->i_pts = mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts;
		}

		if( isobmff_parameters->track[i_track].fmt.i_cat == VIDEO_ES ) {
			tmp_mpu_fragment->i_length = 16683; //1001 * uS / 60000 * uS;

		    //  entry 0000 = sample_duration:16683, sample_size:89965, sample_flags:2000000, sample_composition_time_offset:50050
		} else {
			//audio samples should be at
			//entry 0000 = sample_duration:21333, sample_size:512, sample_flags:2000000, sample_composition_time_offset:0
			//entry 0001 = sample_duration:21333, sample_size:513, sample_flags:10000, sample_composition_time_offset:0
			tmp_mpu_fragment->i_length = 21333;

		}

		// p_track->p_es,
		//isobmff_parameters->mpu_fragments_p_root_box,
		//block_ChainLastAppend(&reassembled_mpu_final, tmp_mpu_fragment);
	//	es_out_Send( p_obj->out, p_track->p_es, tmp_mpu_fragment);

		if(mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts) {
			p_sys_priv->last_pts = mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts;
		}

		__LOG_MPU_REASSEMBLY(p_obj, "%d:SENDING SINGLE:      track: %d, mmtp_packet_id: %u, mpu_sequence_number: %u, size: %d, pts: %llu, sample: %u, offset: %u, mpu_fragment_type: %hu, mpu_fragmentation_indication: %u, tmp_mpu_fragment: %p",
				__LINE__,
				p_track->i_track_ID,
				mpu_type_packet->mmtp_mpu_type_packet_header.mmtp_packet_id,
				mpu_type_packet->mmtp_mpu_type_packet_header.mpu_sequence_number,

				tmp_mpu_fragment->i_buffer, t/1000000,
				mpu_type_packet->mpu_data_unit_payload_fragments_timed.sample_number,
				mpu_type_packet->mpu_data_unit_payload_fragments_timed.offset,
				mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type,
				mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator,
				(void*) tmp_mpu_fragment);
	}

#endif

	if(mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator == 0x01 || mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator == 0x02) {

		//we should already be pushed into
		//mpu_type_packet->mmtp_mpu_type_packet_header.mmtp_sub_flow->mpu_fragments
		//pull from mmtp_sub_flow accessors
		//	block_ChainAppend(&mmtp_sub_flow->p_mpu_block, block_Duplicate(tmp_mpu_fragment));

	}

	__LOG_MPU_REASSEMBLY(p_obj, "%d; track: %d, mmtp_packet_id: %u, mpu_sequence_number: %u, sample: %u, offset: %u, mpu_fragment_type: %u, mpu_fragmentation_indication: %u, payload size: %d",
				__LINE__,
				p_track->i_track_ID,
				mpu_type_packet->mmtp_mpu_type_packet_header.mmtp_packet_id,
				mpu_type_packet->mmtp_mpu_type_packet_header.mpu_sequence_number,
				mpu_type_packet->mpu_data_unit_payload_fragments_timed.sample_number,
				mpu_type_packet->mpu_data_unit_payload_fragments_timed.offset,
				mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type,
				mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator,
				mpu_type_packet->mpu_data_unit_payload_fragments_timed.mpu_data_unit_payload->i_buffer);

	//assume mpu_fragmentation_indicator == 0x03 is robust our signal to push to the decoder
	//and few if any out-of-order fragments will show up
	if(mpu_type_packet->mpu_data_unit_payload_fragments_timed.sample_number == 60 &&
			(mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator == 0x03 || mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator == 0x00)) {

		//combine with mmtp_sub_flow->mpu_fragments->media_fragment_unit_vector mpu_data_unit_payload_fragments_vector_t
		//where mpu_sequence_number == mpu_type_packet->mmtp_mpu_type_packet_header.mpu_sequence_number

		//raise(SIGABRT);

		mmtp_sub_flow_t* packet_subflow = mpu_type_packet->mmtp_packet_header.mmtp_sub_flow;
		__LOG_MPU_REASSEMBLY(p_obj, "%d:processMpuPacket - reassemble", __LINE__);

		mpu_data_unit_payload_fragments_t *data_unit_payload_types = mpu_data_unit_payload_fragments_find_mpu_sequence_number(&packet_subflow->mpu_fragments->media_fragment_unit_vector, mpu_type_packet->mmtp_mpu_type_packet_header.mpu_sequence_number);
		if(!data_unit_payload_types) {
			msg_Warn(p_obj, "%d:processMpuPacket - reassemble - data_unit_payload_types is null, returning", __LINE__);

			return;
		}

		mpu_data_unit_payload_fragments_timed_vector_t *data_unit_payload_fragments = &data_unit_payload_types->timed_fragments_vector;
		//todo - vectorize and add in mpu_sequence_number
		int total_fragments = data_unit_payload_fragments->size;
		__LOG_MPU_REASSEMBLY(p_obj, "%d:processMpuPacket - total_fragments: %d", __LINE__, total_fragments);

		int pre_alloc_size = total_fragments * UPPER_BOUND_MPU_FRAGMENT_SIZE;
		if( pre_alloc_size > MPU_REASSEMBLE_MAX_BUFFER) {
			msg_Warn(p_obj, "%d:processMpuPacket - estimated pre_alloc_size of: %d (fragment count: #d) is greater than %d, truncating", __LINE__, pre_alloc_size, total_fragments, MPU_REASSEMBLE_MAX_BUFFER);
			total_fragments = __MIN(total_fragments, (MPU_REASSEMBLE_MAX_BUFFER / UPPER_BOUND_MPU_FRAGMENT_SIZE));
		}

		__LOG_MPU_REASSEMBLY(p_obj, "%d:processMpuPacket - reassembly, total size before filtering is: %d", __LINE__, total_fragments);

		//todo - add in HRBD support for how large of a buffer we should keep around
		//each packet
		//todo - sort by fragmentation counter DESC
		block_t *first = calloc(1, sizeof(block_t));
		block_t **reassembled_mpu = &first;
		int first_fragment_counter = -1;
		int last_fragment_counter = -1;
		int started_with_first_fragment_of_du = 0;
		int ended_with_last_fragment_of_du = 0;
		int total_sample_count = 0;

		for(int i=0; i < total_fragments; i++) {
			mmtp_payload_fragments_union_t* packet = data_unit_payload_fragments->data[i];

			//only pass thru MFU fragment types for re-assembly, mpu metadat and movie fragment metadata will be prepended later
			if(packet->mpu_data_unit_payload_fragments_timed.mpu_fragment_type == 0x02) { // && packet->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_indicator != 0x00)  {
				__LOG_MPU_REASSEMBLY(p_obj, "%d:processMpuPacket:reassembly - appending, mpu_sequence_number: %d, mpu_fragment_type:%d, mpu_fragmentation_indicator: %d, sample_number: %d, fragment_counter: %d, offset: %d, payload size: %d (%p)",
									__LINE__,
									packet->mpu_data_unit_payload_fragments_timed.mpu_sequence_number,
									packet->mpu_data_unit_payload_fragments_timed.mpu_fragment_type,
									packet->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_indicator,
									packet->mpu_data_unit_payload_fragments_timed.sample_number,
									packet->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_counter,
									packet->mpu_data_unit_payload_fragments_timed.offset,
									packet->mpu_data_unit_payload_fragments_timed.mpu_data_unit_payload->i_buffer,
									packet->mpu_data_unit_payload_fragments_timed.mpu_data_unit_payload);

				block_ChainLastAppend(&reassembled_mpu, packet->mpu_data_unit_payload_fragments_timed.mpu_data_unit_payload);

				//capture some aggregate metrics here
				if(first_fragment_counter == -1) {
					first_fragment_counter = packet->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_counter;
					started_with_first_fragment_of_du = (packet->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_indicator == 0x01);
				}
				last_fragment_counter = packet->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_counter;
				ended_with_last_fragment_of_du = (packet->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_indicator == 0x03);
				total_sample_count++;

			} else {
				__LOG_MPU_REASSEMBLY(p_obj, "%d:processMpuPacket:reassembly - omitting,  mpu_sequence_number: %d, mpu_fragment_type:%d, mpu_fragmentation_indicator: %d, sample_number: %d, fragment_counter: %d, payload size: %d (%p)",
									__LINE__,
									packet->mpu_data_unit_payload_fragments_timed.mpu_sequence_number,
									packet->mpu_data_unit_payload_fragments_timed.mpu_fragment_type,
									packet->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_indicator,
									packet->mpu_data_unit_payload_fragments_timed.sample_number,
									packet->mpu_data_unit_payload_fragments_timed.mpu_fragmentation_counter,
									packet->mpu_data_unit_payload_fragments_timed.offset,
									packet->mpu_data_unit_payload_fragments_timed.mpu_data_unit_payload->i_buffer,
									packet->mpu_data_unit_payload_fragments_timed.mpu_data_unit_payload);
			}
		}



		//borrowed from es.c

		block_t *p_block_out = first;


		while( p_block_out )
		{
			block_t *p_next = p_block_out->p_next;

			/* Correct timestamp */
//			if( p_sys->p_packetizer->fmt_out.i_cat == VIDEO_ES )
//			{
//				if( p_block_out->i_pts == VLC_TICK_INVALID &&
//					p_block_out->i_dts == VLC_TICK_INVALID )
//					p_block_out->i_dts = VLC_TICK_0 + p_sys->i_pts + VLC_TICK_FROM_SEC(1) / p_sys->f_fps;
//				if( p_block_out->i_dts != VLC_TICK_INVALID )
//					p_sys->i_pts = p_block_out->i_dts - VLC_TICK_0;
//			}
//			else
//			{
//				p_sys->i_pts = p_block_out->i_pts - VLC_TICK_0;
//			}
//
//			if( p_block_out->i_pts != VLC_TICK_INVALID )
//			{
//				p_block_out->i_pts += p_sys->i_time_offset;
//			}
//			if( p_block_out->i_dts != VLC_TICK_INVALID )
//			{
//				p_block_out->i_dts += p_sys->i_time_offset;
//				es_out_SetPCR( p_demux->out, p_block_out->i_dts );
//			}
			/* Re-estimate bitrate */
//			if( p_sys->b_estimate_bitrate && p_sys->i_pts > VLC_TICK_FROM_MS(500) )
//				p_sys->i_bitrate_avg = 8 * CLOCK_FREQ * p_sys->i_bytes
//									   / (p_sys->i_pts - 1);
//			p_sys->i_bytes += p_block_out->i_buffer;

			block_t* p_block_es_out = block_Duplicate(p_block_out);
			p_block_es_out->p_next = NULL;

			__LOG_INFO(p_obj, "%d:es_out_send with block: pts: %llu, length: %llu, size: %d", __LINE__, p_block_es_out->i_pts, p_block_es_out->i_length, p_block_es_out->i_buffer);
			es_out_Send( p_obj->out, p_track->p_es, p_block_es_out);
//			es_out_Send( p_demux->out, p_sys->p_es, p_block_out );

//			if(mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts) {
//				msg_Info(p_obj, "%d: setting tmp_mpu_fragment.pts = %llu, pcr: %llu, last_pts: %llu", __LINE__, mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts, new_pcr, p_sys_priv->last_pts);
//
//				//reassembled_mpu_final->i_pts = mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts;
//			}
			//reassembled_mpu_final->i_length = 16683 * 60; //1001 * uS / 60000 * uS;

			p_block_out = p_next;
		}









		//todo, re-sequence these by fragmentation_counter DESC,
		block_t* reassembled_mpu_final = block_ChainGather(block_Duplicate(first));

		char myFilePathName[128];
		snprintf(myFilePathName, 128, "mmtp.packetid.%d.mpu_sequence_number.%d.mpu_sample_number%d", mpu_type_packet->mmtp_mpu_type_packet_header.mmtp_packet_id,
				mpu_type_packet->mmtp_mpu_type_packet_header.mpu_sequence_number,			mpu_type_packet->mpu_data_unit_payload_fragments_timed.sample_number);

		//concat wtih header box...
		FILE *f = fopen(myFilePathName, "w");
		if(!f) {
			msg_Err(p_obj, "::dumpMpu ******* UNABLE TO OPEN FILE %s", myFilePathName);
			return;
		}

		for(int i=0; i < isobmff_parameters->mp4_movie_fragment_block_t->i_buffer; i++) {
			fputc(isobmff_parameters->mp4_movie_fragment_block_t->p_buffer[i], f);
		}

		for(int i=0; i < reassembled_mpu_final->i_buffer; i++) {
			fputc(reassembled_mpu_final->p_buffer[i], f);
		}
		fclose(f);

	//	block_t* reassembled_mpu_final = first;
	//	block_ChainLastAppend(&reassembled_mpu_final, reassembled_mpu);

		int samples_missing =  first_fragment_counter - last_fragment_counter - total_sample_count + 1;

		msg_Info(p_obj, "%d:REASSEMBLE METRICS: samples present count: %d, starting w/ first fragment: %c, start fragment #: %d, ending w/ last fragment: %c, end fragment #: %d, missing: %d",
					__LINE__,
					total_sample_count,
					started_with_first_fragment_of_du ? 'T':'F', first_fragment_counter,
					ended_with_last_fragment_of_du ? 'T' : 'F', last_fragment_counter,
					samples_missing);

//		if(!started_with_first_fragment_of_du || !ended_with_last_fragment_of_du || samples_missing > 5) {
//			reassembled_mpu_final->i_flags |= BLOCK_FLAG_CORRUPTED;
//		} else {
//			reassembled_mpu_final->i_flags &= ~BLOCK_FLAG_CORRUPTED;
//		}


		msg_Info(p_obj, "%d:SENDING REASSEMBLED: track: %d, mmtp_packet_id: %u, mpu_sequence_number: %u, size: %d, pts: %llu, sample: %u, offset: %u, mpu_fragment_type: %hu, mpu_fragmentation_indication: %u, tmp_mpu_fragment: %p",
			__LINE__,
			p_track->i_track_ID,

			mpu_type_packet->mmtp_mpu_type_packet_header.mmtp_packet_id,
			mpu_type_packet->mmtp_mpu_type_packet_header.mpu_sequence_number,

			reassembled_mpu_final->i_buffer,
			reassembled_mpu_final->i_pts,
			mpu_type_packet->mpu_data_unit_payload_fragments_timed.sample_number,
			mpu_type_packet->mpu_data_unit_payload_fragments_timed.offset,
			mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type,
			mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragmentation_indicator,
			(void*) reassembled_mpu_final);



		if(mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts) {
			p_sys_priv->last_pts = mpu_type_packet->mpu_data_unit_payload_fragments_timed.pts;
		}

		block_Release(reassembled_mpu_final);

		vlc_vector_clear(data_unit_payload_fragments);
	}

	__LOG_TRACE(p_obj, "%d:processMpuPacket - return - mpu_fragment_type=0x%x, p_root_box: %p", __LINE__,
			mpu_type_packet->mmtp_mpu_type_packet_header.mpu_fragment_type,
			isobmff_parameters->mpu_fragments_p_root_box );

}



void createTracksFromMpuMetadata(demux_t *p_obj, mmtp_sub_flow_t* mmtp_sub_flow) {

    bool      b_enabled_es = true;
    const MP4_Box_t *p_mvhd = NULL;

    mpu_isobmff_fragment_parameters_t *isobmff_parameters = &mmtp_sub_flow->mpu_fragments->mpu_isobmff_fragment_parameters;

    __LOG_DEBUG(p_obj, "%d:createTracksFromMpuMetadata", __LINE__);

    p_mvhd = MP4_BoxGet( isobmff_parameters->mpu_fragments_p_moov, "mvhd" );

	if( p_mvhd && BOXDATA(p_mvhd) && BOXDATA(p_mvhd)->i_timescale )
	{
		isobmff_parameters->i_timescale = BOXDATA(p_mvhd)->i_timescale;
		isobmff_parameters->i_moov_duration = isobmff_parameters->i_duration = BOXDATA(p_mvhd)->i_duration;
		isobmff_parameters->i_cumulated_duration = BOXDATA(p_mvhd)->i_duration;
	} else {
		msg_Warn( p_obj, "No valid mvhd found" );
		//set some defaults
		isobmff_parameters->i_timescale = 1000000;
		isobmff_parameters->i_moov_duration = 0;
		isobmff_parameters->i_cumulated_duration = 0;
	}

	const unsigned i_tracks = MP4_BoxCount( isobmff_parameters->mpu_fragments_p_root_box, "/moov/trak" );
	if( i_tracks < 1 )
	{
		msg_Err( p_obj, "%d:createTracksFromMpuMetadata cannot find any /moov/trak", __LINE__);
		goto error;
	}
	__LOG_DEBUG( p_obj, "%d:createTracksFromMpuMetadata, found %u track%c", __LINE__, i_tracks, i_tracks ? 's':' ' );

	if( CreateTracks( isobmff_parameters, i_tracks ) != VLC_SUCCESS )
		goto error;

	for( unsigned i = 0; i < isobmff_parameters->i_tracks; i++ ) {
		MP4_Box_t *p_trak = MP4_BoxGet( isobmff_parameters->mpu_fragments_p_root_box, "/moov/trak[%u]", i );

	    __LOG_INFO(p_obj, "%d:createTracksFromMpuMetadata, track: %u, handler_type: %c%c%c%c", __LINE__, i,
	    		(p_trak->i_handler >>24)&0xFF ,
				(p_trak->i_handler >>16)&0xFF,
				(p_trak->i_handler >>8)&0xFF,
				(p_trak->i_handler    )&0xFF);

	    if(i>0)
	    	continue;

		MP4_TrackSetup( p_obj, isobmff_parameters, &isobmff_parameters->track[i], p_trak, true, !b_enabled_es );

		if( isobmff_parameters->track[i].b_ok && !isobmff_parameters->track[i].b_chapters_source )
		{
			const char *psz_cat;
			switch( isobmff_parameters->track[i].fmt.i_cat )
			{
				case( VIDEO_ES ):
					psz_cat = "video";
					break;
				case( AUDIO_ES ):
					psz_cat = "audio";
					break;
				case( SPU_ES ):
					psz_cat = "subtitle";
					break;

				default:
					psz_cat = "unknown";
					break;
			}

			__LOG_DEBUG( p_obj, "adding track[Id 0x%x] %s (%s) language %s",
					isobmff_parameters->track[i].i_track_ID, psz_cat,
					isobmff_parameters->track[i].b_enable ? "enable":"disable",
					isobmff_parameters->track[i].fmt.psz_language ?	isobmff_parameters->track[i].fmt.psz_language : "undef" );
		} else if( isobmff_parameters->track[i].b_ok && isobmff_parameters->track[i].b_chapters_source ) {
			__LOG_DEBUG( p_obj, "using track[Id 0x%x] for chapter language %s",
					isobmff_parameters->track[i].i_track_ID,
					isobmff_parameters->track[i].fmt.psz_language ?isobmff_parameters->track[i].fmt.psz_language : "undef" );
		} else {
			__LOG_DEBUG( p_obj, "ignoring track[Id 0x%x]", isobmff_parameters->track[i].i_track_ID );
		}
	}

	const MP4_Box_t *p_mvex = NULL;

	p_mvex = MP4_BoxGet( isobmff_parameters->mpu_fragments_p_moov, "mvex" );
	if( p_mvex != NULL )
	{
		const MP4_Box_t *p_mehd = MP4_BoxGet( p_mvex, "mehd");
		if ( p_mehd && BOXDATA(p_mehd) )
		{
			if( BOXDATA(p_mehd)->i_fragment_duration > isobmff_parameters->i_duration )
			{
				isobmff_parameters->b_fragmented = true;
				isobmff_parameters->i_duration = BOXDATA(p_mehd)->i_fragment_duration;
			}
		}

		const MP4_Box_t *p_sidx = MP4_BoxGet( isobmff_parameters->mpu_fragments_p_root_box, "sidx");
		if( p_sidx )
			isobmff_parameters->b_fragmented = true;

		if ( isobmff_parameters->b_seekable )
		{
			if( !isobmff_parameters->b_fragmented /* as unknown */ )
			{
				/* Probe remaining to check if there's really fragments
				   or if that file is just ready to append fragments */
				ProbeFragments( p_obj, isobmff_parameters, (isobmff_parameters->i_duration == 0), &isobmff_parameters->b_fragmented );
			}

			if( vlc_stream_Seek( isobmff_parameters->s_frag, isobmff_parameters->mpu_fragments_p_root_box->i_pos ) != VLC_SUCCESS )
				goto error;
		}
		else /* Handle as fragmented by default as we can't see moof */
		{
			isobmff_parameters->context.p_fragment_atom = isobmff_parameters->mpu_fragments_p_moov;
			isobmff_parameters->context.i_current_box_type = ATOM_moov;
			isobmff_parameters->b_fragmented = true;
		}
	}

	error:
		return;
}


//TODO - fix file naming to use snprintf
void dumpReassembeled(demux_t *p_demux, block_t *mpu, uint32_t mpu_sequence_number, uint32_t mpu_sample_number) {

	demux_sys_t *p_sys = p_demux->p_sys;

//	__LOG_INFO(p_demux, "::dumpMpu ******* file dump counter_id is: %d", __MPU_COUNTER);
	//dumping block_t mpu->i_buffer is: %zu, p_buffer[0] is:\n%c", mpu->i_buffer, mpu->p_buffer[0]);
#ifdef __MMTP_DUMP_REASSEMBLE_ENABLED

		char *myFilePathName = malloc(sizeof(char)*20);
		memset(myFilePathName, 0, 20);
		int pos = 0;

		strncat(myFilePathName, "mfu/", 4);
		pos = strlen(myFilePathName);
		itoa(mpu_sequence_number, myFilePathName+pos, 10);
		pos = strlen(myFilePathName);

		myFilePathName[pos] = '-';
		myFilePathName[pos+1] = '\0';
		pos = strlen(myFilePathName);
		itoa(mpu_sample_number, myFilePathName+pos, 10);

	//	__LOG_INFO(p_demux, "::dumpMfu ******* file dump __MPU_COUNTER is: %d, file: %s", __MPU_COUNTER-1, myFilePathName);

		FILE *f = fopen(myFilePathName, "w");
		if(!f) {
			msg_Err(p_demux, "::dumpMpu ******* UNABLE TO OPEN FILE %s", myFilePathName);
			return;
		}

		for(int i=0; i < mpu->i_buffer; i++) {
			fputc(mpu->p_buffer[i], f);
		}
		fclose(f);
#endif
}

void dumpMpu(demux_t *p_demux, block_t *mpu) {

	demux_sys_t *p_sys = p_demux->p_sys;

//	__LOG_INFO(p_demux, "::dumpMpu ******* file dump counter_id is: %d", __MPU_COUNTER);
	//dumping block_t mpu->i_buffer is: %zu, p_buffer[0] is:\n%c", mpu->i_buffer, mpu->p_buffer[0]);
	#ifdef __MMTP_DUMP_REASSEMBLE_ENABLED
		char *myFilePathName = malloc(sizeof(char)*20);
		memset(myFilePathName, 0, 20);
		int pos=0;

		strncat(myFilePathName, "mpu/", 4);
		pos = strlen(myFilePathName);
		itoa(p_sys->last_mpu_sequence_number, myFilePathName+pos, 10);

	//	__LOG_INFO(p_demux, "::dumpMfu ******* file dump __MPU_COUNTER is: %d, file: %s", __MPU_COUNTER-1, myFilePathName);

		FILE *f = fopen(myFilePathName, "w");
		if(!f) {
			msg_Err(p_demux, "::dumpMpu ******* UNABLE TO OPEN FILE %s", myFilePathName);
			return;
		}

		for(int i=0; i < mpu->i_buffer; i++) {
			fputc(mpu->p_buffer[i], f);
		}
		fclose(f);
	}
#endif

	if(false) {
		char buffer[mpu->i_buffer * 5+1]; //0x00 |
										//12345
		for(int i=0; i < mpu->i_buffer; i++) {
			if(i>0 && (i+1)%32 == 0) {
				snprintf(buffer + (i*3), 4, "%02X\n ", mpu->p_buffer[i]);
			} else if(i>0 && (i+1)%8 == 0) {
				snprintf(buffer + (i*3), 4, "%02X\t ", mpu->p_buffer[i]);
			} else {
				snprintf(buffer + (i*3), 4, "%02X ", mpu->p_buffer[i]);
			}
		//	__LOG_INFO(mp4_demux, "%02X ", mpu->p_buffer[i]);
		}
//		__LOG_INFO(p_demux, "::dumpMpu ******* dumping block_t mpu->i_buffer is: %zu, p_buffer is:\n%s", mpu->i_buffer, buffer);

	}
}



/** todo:
 * change this to proper samples
 */
void dumpMfu(demux_t *p_demux, block_t *mpu) {
	demux_sys_t *p_sys = p_demux->p_sys;

	//dumping block_t mpu->i_buffer is: %zu, p_buffer[0] is:\n%c", mpu->i_buffer, mpu->p_buffer[0]);
#ifdef __MMTP_DUMP_REASSEMBLE_ENABLED
		char *myFilePathName = malloc(sizeof(char)*20);
		memset(myFilePathName, 0, 20);
		int pos = 0;

		strncat(myFilePathName, "mfu/", 4);
		pos = strlen(myFilePathName);
		itoa(p_sys->last_mpu_sequence_number, myFilePathName+pos, 10);
		pos = strlen(myFilePathName);

		myFilePathName[pos] = '-';
		myFilePathName[pos+1] = '\0';
		pos = strlen(myFilePathName);
		itoa(__MFU_COUNTER++, myFilePathName+pos, 10);

//		__LOG_INFO(p_demux, "::dumpMfu ******* file dump __MPU_COUNTER is: %d, __MFU_COUNTER is: %d, file: %s", __MPU_COUNTER, __MFU_COUNTER-1, myFilePathName);

		FILE *f = fopen(myFilePathName, "w");
		if(!f) {
			msg_Err(p_demux, "::dumpMfu ******* UNABLE TO OPEN FILE %s", myFilePathName);
			return;
		}

		for(int i=0; i < mpu->i_buffer; i++) {
			fputc(mpu->p_buffer[i], f);
		}
		fclose(f);
	}
#endif

	if(false) {
		__LOG_INFO(p_demux, "::dumpMfu ******* file dump counter_id is: %d", __MFU_COUNTER);

		char buffer[mpu->i_buffer * 5+1]; //0x00 |
										//12345
		for(int i=0; i < mpu->i_buffer; i++) {
			if(i>0 && (i+1)%32 == 0) {
				snprintf(buffer + (i*3), 4, "%02X\n ", mpu->p_buffer[i]);
			} else if(i>0 && (i+1)%8 == 0) {
				snprintf(buffer + (i*3), 4, "%02X\t ", mpu->p_buffer[i]);
			} else {
				snprintf(buffer + (i*3), 4, "%02X ", mpu->p_buffer[i]);
			}
		//	__LOG_INFO(mp4_demux, "%02X ", mpu->p_buffer[i]);
		}
		__LOG_INFO(p_demux, "::dumpMpu ******* dumping block_t mpu->i_buffer is: %zu, p_buffer is:\n%s", mpu->i_buffer, buffer);

	}
}



/*** copy paste warning from libmp4/mp4.c
 *
 *
 */







/* Helpers */

static int64_t MP4_rescale( int64_t i_value, uint32_t i_timescale, uint32_t i_newscale )
{
    if( i_timescale == i_newscale )
        return i_value;

    if( i_value <= INT64_MAX / i_newscale )
        return i_value * i_newscale / i_timescale;

    /* overflow */
    int64_t q = i_value / i_timescale;
    int64_t r = i_value % i_timescale;
    return q * i_newscale + r * i_newscale / i_timescale;
}

static vlc_tick_t MP4_rescale_mtime( int64_t i_value, uint32_t i_timescale )
{
    return MP4_rescale(i_value, i_timescale, CLOCK_FREQ);
}

static int64_t MP4_rescale_qtime( vlc_tick_t i_value, uint32_t i_timescale )
{
    return MP4_rescale(i_value, CLOCK_FREQ, i_timescale);
}


static MP4_Box_t * MP4_GetTrexByTrackID( MP4_Box_t *p_moov, const uint32_t i_id )
{
    if(!p_moov)
        return NULL;
    MP4_Box_t *p_trex = MP4_BoxGet( p_moov, "mvex/trex" );
    while( p_trex )
    {
        if ( p_trex->i_type == ATOM_trex &&
             BOXDATA(p_trex) && BOXDATA(p_trex)->i_track_ID == i_id )
                break;
        else
            p_trex = p_trex->p_next;
    }
    return p_trex;
}

static MP4_Box_t * MP4_GetTrakByTrackID( MP4_Box_t *p_moov, const uint32_t i_id )
{
    MP4_Box_t *p_trak = MP4_BoxGet( p_moov, "trak" );
    MP4_Box_t *p_tkhd;
    while( p_trak )
    {
        if( p_trak->i_type == ATOM_trak &&
            (p_tkhd = MP4_BoxGet( p_trak, "tkhd" )) && BOXDATA(p_tkhd) &&
            BOXDATA(p_tkhd)->i_track_ID == i_id )
                break;
        else
            p_trak = p_trak->p_next;
    }
    return p_trak;
}

static MP4_Box_t * MP4_GetTrafByTrackID( MP4_Box_t *p_moof, const uint32_t i_id )
{
    MP4_Box_t *p_traf = MP4_BoxGet( p_moof, "traf" );
    MP4_Box_t *p_tfhd;
    while( p_traf )
    {
        if( p_traf->i_type == ATOM_traf &&
            (p_tfhd = MP4_BoxGet( p_traf, "tfhd" )) && BOXDATA(p_tfhd) &&
            BOXDATA(p_tfhd)->i_track_ID == i_id )
                break;
        else
            p_traf = p_traf->p_next;
    }
    return p_traf;
}

static es_out_id_t * MP4_AddTrackES( es_out_t *out, mp4_track_t *p_track )
{
    es_out_id_t *p_es = es_out_Add( out, &p_track->fmt );
    /* Force SPU which isn't selected/defaulted */
    if( p_track->fmt.i_cat == SPU_ES && p_es && p_track->b_forced_spu )
        es_out_Control( out, ES_OUT_SET_ES_DEFAULT, p_es );

    return p_es;
}
//
///* Return time in microsecond of a track */
//static inline vlc_tick_t MP4_TrackGetDTS( demux_t *p_demux, mp4_track_t *p_track )
//{
//    demux_sys_t *p_sys = p_demux->p_sys;
//    const mp4_chunk_t *p_chunk = &p_track->chunk[p_track->i_chunk];
//
//    unsigned int i_index = 0;
//    unsigned int i_sample = p_track->i_sample - p_chunk->i_sample_first;
//    int64_t sdts = p_chunk->i_first_dts;
//
//    while( i_sample > 0 && i_index < p_chunk->i_entries_dts )
//    {
//        if( i_sample > p_chunk->p_sample_count_dts[i_index] )
//        {
//            sdts += p_chunk->p_sample_count_dts[i_index] *
//                p_chunk->p_sample_delta_dts[i_index];
//            i_sample -= p_chunk->p_sample_count_dts[i_index];
//            i_index++;
//        }
//        else
//        {
//            sdts += i_sample * p_chunk->p_sample_delta_dts[i_index];
//            break;
//        }
//    }
//
//    vlc_tick_t i_dts = MP4_rescale_mtime( sdts, p_track->i_timescale );
//
//    /* now handle elst */
//    if( p_track->p_elst && p_track->BOXDATA(p_elst)->i_entry_count )
//    {
//        MP4_Box_data_elst_t *elst = p_track->BOXDATA(p_elst);
//
//        /* convert to offset */
//        if( ( elst->i_media_rate_integer[p_track->i_elst] > 0 ||
//              elst->i_media_rate_fraction[p_track->i_elst] > 0 ) &&
//            elst->i_media_time[p_track->i_elst] > 0 )
//        {
//            i_dts -= MP4_rescale_mtime( elst->i_media_time[p_track->i_elst], p_track->i_timescale );
//        }
//
//        /* add i_elst_time */
//        i_dts += MP4_rescale_mtime( p_track->i_elst_time, p_sys->i_timescale );
//
//        if( i_dts < 0 ) i_dts = 0;
//    }
//
//    return i_dts;
//}



//create default empty/unconfigured tracks
static int CreateTracks( mpu_isobmff_fragment_parameters_t *isobmff_parameters, unsigned i_tracks )
{
    if( SIZE_MAX / i_tracks < sizeof(mp4_track_t) )
        return VLC_EGENERIC;

    isobmff_parameters->track = vlc_alloc( i_tracks, sizeof(mp4_track_t)  );
    if( isobmff_parameters->track == NULL )
        return VLC_ENOMEM;
    isobmff_parameters->i_tracks = i_tracks;

    //set es format as UNKNOWN_ES
    for( unsigned i=0; i<i_tracks; i++ )
        MP4_TrackInit( &isobmff_parameters->track[i] );

    return VLC_SUCCESS;
}

//TODO
static block_t * MP4_EIA608_Convert( block_t * p_block )
{
    /* Rebuild codec data from encap */
    size_t i_copied = 0;
    size_t i_remaining = __MIN(p_block->i_buffer, INT64_MAX / 3);
    uint32_t i_bytes = 0;
    block_t *p_newblock;

    /* always need at least 10 bytes (atom size+header+1pair)*/
    if ( i_remaining < 10 ||
         !(i_bytes = GetDWBE(p_block->p_buffer)) ||
         (i_bytes > i_remaining) ||
         memcmp("cdat", &p_block->p_buffer[4], 4) ||
         !(p_newblock = block_Alloc( i_remaining * 3 - 8 )) )
    {
        p_block->i_buffer = 0;
        return p_block;
    }

    uint8_t *p_write = p_newblock->p_buffer;
    uint8_t *p_read = &p_block->p_buffer[8];
    i_bytes -= 8;
    i_remaining -= 8;

    do
    {
        p_write[i_copied++] = CC_PKT_BYTE0(0); /* cc1 == field 0 */
        p_write[i_copied++] = p_read[0];
        p_write[i_copied++] = p_read[1];
        p_read += 2;
        i_bytes -= 2;
        i_remaining -= 2;
    } while( i_bytes >= 2 );

    /* cdt2 is optional */
    if ( i_remaining >= 10 &&
         (i_bytes = GetDWBE(p_read)) &&
         (i_bytes <= i_remaining) &&
         !memcmp("cdt2", &p_read[4], 4) )
    {
        p_read += 8;
        i_bytes -= 8;
        i_remaining -= 8;
        do
        {
            p_write[i_copied++] = CC_PKT_BYTE0(0); /* cc1 == field 0 */
            p_write[i_copied++] = p_read[0];
            p_write[i_copied++] = p_read[1];
            p_read += 2;
            i_bytes -= 2;
        } while( i_bytes >= 2 );
    }

    p_newblock->i_pts = p_block->i_dts;
    p_newblock->i_buffer = i_copied;
    p_newblock->i_flags = BLOCK_FLAG_TYPE_P;
    block_Release( p_block );

    return p_newblock;
}



const unsigned int SAMPLEHEADERSIZE = 4;
const unsigned int RTPPACKETSIZE = 12;
const unsigned int CONSTRUCTORSIZE = 16;

/**
 * It computes the sample rate for a video track using the given sample
 * description index
 */
static void TrackGetESSampleRate( demux_t *p_demux, mpu_isobmff_fragment_parameters_t* isobmff_parameters,
                                  unsigned *pi_num, unsigned *pi_den,
                                  const mp4_track_t *p_track,
                                  unsigned i_sd_index,
                                  unsigned i_chunk )
{
    demux_sys_t *p_sys = p_demux->p_sys;
    *pi_num = 0;
    *pi_den = 0;

    __LOG_INFO(p_demux, "%d:TrackGetESSampleRate, TrackGetESSampleRate - entry",__LINE__);

    MP4_Box_t *p_trak = MP4_GetTrakByTrackID( MP4_BoxGet( isobmff_parameters->mpu_fragments_p_root_box,
                                                          "/moov" ),
                                              p_track->i_track_ID );
    MP4_Box_t *p_mdhd = MP4_BoxGet( p_trak, "mdia/mdhd" );
    if ( p_mdhd && BOXDATA(p_mdhd) )
    {
        __LOG_INFO(p_demux, "%d:TrackGetESSampleRate, using p_mdhd",__LINE__);

        vlc_ureduce( pi_num, pi_den,
                     (uint64_t) BOXDATA(p_mdhd)->i_timescale * p_track->i_sample_count,
                     (uint64_t) BOXDATA(p_mdhd)->i_duration,
                     UINT16_MAX );
        return;
    }

    if( p_track->i_chunk_count == 0 ) {
        __LOG_INFO(p_demux, "%d:TrackGetESSampleRate, i_chunk_count=0",__LINE__);

        return;
    }

    /* */
    const mp4_chunk_t *p_chunk = &p_track->chunk[i_chunk];
    while( p_chunk > &p_track->chunk[0] &&
           p_chunk[-1].i_sample_description_index == i_sd_index )
    {
        p_chunk--;
    }

    uint64_t i_sample = 0;
    uint64_t i_total_duration = 0;
    do
    {
        i_sample += p_chunk->i_sample_count;
        i_total_duration += p_chunk->i_duration;
        p_chunk++;
    }
    while( p_chunk < &p_track->chunk[p_track->i_chunk_count] &&
           p_chunk->i_sample_description_index == i_sd_index );

    if( i_sample > 0 && i_total_duration ) {
        vlc_ureduce( pi_num, pi_den,
                     i_sample * p_track->i_timescale,
                     i_total_duration,
                     UINT16_MAX);
        __LOG_INFO(p_demux, "%d:TrackGetESSampleRate, vlc_ureduce",__LINE__);

    } else {
        __LOG_INFO(p_demux, "%d:TrackGetESSampleRate, i_chunk_count=0",__LINE__);

    }
}

/*
 * TrackCreateES:
 * Create ES and PES to init decoder if needed, for a track starting at i_chunk
 */
static int TrackCreateES( demux_t *p_demux, mmtp_sub_flow_t* mmtp_sub_flow, mp4_track_t *p_track,
                          unsigned int i_chunk, es_out_id_t **pp_es )
{
    demux_sys_t *p_sys = p_demux->p_sys;
    unsigned int i_sample_description_index;

    if( p_sys->b_fragmented || p_track->i_chunk_count == 0 )
        i_sample_description_index = 1; /* XXX */
    else
        i_sample_description_index =
                p_track->chunk[i_chunk].i_sample_description_index;

    if( pp_es )
        *pp_es = NULL;

    __LOG_INFO(p_demux, "%d:TrackCreateES - entry",__LINE__);

    if( !i_sample_description_index )
    {
        msg_Warn( p_demux, "invalid SampleEntry index (track[Id 0x%x])",
                  p_track->i_track_ID );
        return VLC_EGENERIC;
    }


    MP4_Box_t *p_sample = MP4_BoxGet(  p_track->p_stsd, "[%d]",
                            i_sample_description_index - 1 );

    if( !p_sample ||
        ( !p_sample->data.p_payload && p_track->fmt.i_cat != SPU_ES ) )
    {
        msg_Warn( p_demux, "cannot find SampleEntry (track[Id 0x%x])",
                  p_track->i_track_ID );
        return VLC_EGENERIC;
    }

    p_track->p_sample = p_sample;

    MP4_Box_t   *p_frma;
    if( ( p_frma = MP4_BoxGet( p_track->p_sample, "sinf/frma" ) ) && p_frma->data.p_frma )
    {
        msg_Warn( p_demux, "Original Format Box: %4.4s", (char *)&p_frma->data.p_frma->i_type );

        p_sample->i_type = p_frma->data.p_frma->i_type;
    }

    /* */
    switch( p_track->fmt.i_cat )
    {
		case VIDEO_ES:
			if ( p_sample->i_handler != ATOM_vide ||
				 !SetupVideoES( p_demux, p_track, p_sample ) ) {
			    __LOG_INFO(p_demux, "%d:MP4_TrackSetup, !SetupVideoES ",__LINE__);

				return VLC_EGENERIC;
			}

			/* Set frame rate */
			TrackGetESSampleRate( p_demux, mmtp_sub_flow,
								  &p_track->fmt.video.i_frame_rate,
								  &p_track->fmt.video.i_frame_rate_base,
								  p_track, i_sample_description_index, i_chunk );

			p_sys->f_fps = (float)p_track->fmt.video.i_frame_rate /
						   (float)p_track->fmt.video.i_frame_rate_base;
			//set to 59.94 rational
			if(!p_sys->f_fps) {
				p_sys->f_fps = 60000.0/1001.0;
			}


	        __LOG_INFO(p_demux, "%d:MP4_TrackSetup, framerate is: %f",__LINE__, p_sys->f_fps);

			break;

		case AUDIO_ES:
			if ( p_sample->i_handler != ATOM_soun ||
				 !SetupAudioES( p_demux, p_track, p_sample ) )
				return VLC_EGENERIC;
			if( p_sys->p_meta )
			{
				audio_replay_gain_t *p_arg = &p_track->fmt.audio_replay_gain;
				const char *psz_meta = vlc_meta_GetExtra( p_sys->p_meta, "replaygain_track_gain" );
				if( psz_meta )
				{
					double f_gain = us_atof( psz_meta );
					p_arg->pf_gain[AUDIO_REPLAY_GAIN_TRACK] = f_gain;
					p_arg->pb_gain[AUDIO_REPLAY_GAIN_TRACK] = f_gain != 0;
				}
				psz_meta = vlc_meta_GetExtra( p_sys->p_meta, "replaygain_track_peak" );
				if( psz_meta )
				{
					double f_gain = us_atof( psz_meta );
					p_arg->pf_peak[AUDIO_REPLAY_GAIN_TRACK] = f_gain;
					p_arg->pb_peak[AUDIO_REPLAY_GAIN_TRACK] = f_gain > 0;
				}
			}
			break;

		case SPU_ES:
			if ( ( p_sample->i_handler != ATOM_text &&
				   p_sample->i_handler != ATOM_subt &&
				   p_sample->i_handler != ATOM_sbtl ) ||
				 !SetupSpuES( p_demux, p_track, p_sample ) )
			   return VLC_EGENERIC;
			break;

		default:
			break;
    }

    if( pp_es ) {
        __LOG_INFO(p_demux, "%d:TrackCreateES - pp_es is: %p",__LINE__, pp_es);

        *pp_es = MP4_AddTrackES( p_demux->out, p_track );
    } else {
        __LOG_INFO(p_demux, "%d:TrackCreateES - pp_es is null",__LINE__);
    }

    return ( !pp_es || *pp_es ) ? VLC_SUCCESS : VLC_EGENERIC;
}


/****************************************************************************
 * MP4_TrackSetup:
 ****************************************************************************
 * Parse track information and create all needed data to run a track
 * If it succeed b_ok is set to 1 else to 0
 ****************************************************************************/
static void MP4_TrackSetup( demux_t *p_demux, mpu_isobmff_fragment_parameters_t *isobmff_parameters,
							mp4_track_t *p_track,
                            MP4_Box_t *p_box_trak,
                            bool b_create_es, bool b_force_enable )
{
    demux_sys_t *p_sys = p_demux->p_sys;

    p_track->p_track = p_box_trak;

    char language[4] = { '\0' };
    char sdp_media_type[8] = { '\0' };

    const MP4_Box_t *p_tkhd = MP4_BoxGet( p_box_trak, "tkhd" );
    if( !p_tkhd )
    {
    	__LOG_DEBUG( p_demux, "%d:MP4_TrackSetup, missing /moov/trak/tkhd", __LINE__);
        return;
    }

    /* do we launch this track by default ? */
    p_track->b_enable =
        ( ( BOXDATA(p_tkhd)->i_flags&MP4_TRACK_ENABLED ) != 0 );

    p_track->i_track_ID = BOXDATA(p_tkhd)->i_track_ID;

    p_track->i_width = BOXDATA(p_tkhd)->i_width / BLOCK16x16;
    p_track->i_height = BOXDATA(p_tkhd)->i_height / BLOCK16x16;
    p_track->f_rotation = BOXDATA(p_tkhd)->f_rotation;

    /* FIXME: unhandled box: tref */

    const MP4_Box_t *p_mdhd = MP4_BoxGet( p_box_trak, "mdia/mdhd" );
    const MP4_Box_t *p_hdlr = MP4_BoxGet( p_box_trak, "mdia/hdlr" );

    if( ( !p_mdhd )||( !p_hdlr ) )
    {
    	__LOG_DEBUG( p_demux, "%d:MP4_TrackSetup, missing mdia/mdhd or mdia/hdlr", __LINE__);

        return;
    }

    if( BOXDATA(p_mdhd)->i_timescale == 0 )
    {
        msg_Warn( p_demux, "%d:MP4_TrackSetup, Invalid track timescale ", __LINE__);
        return;
    }
    p_track->i_timescale = BOXDATA(p_mdhd)->i_timescale;

    memcpy( &language, BOXDATA(p_mdhd)->rgs_language, 3 );
    p_track->b_mac_encoding = BOXDATA(p_mdhd)->b_mac_encoding;

    __LOG_INFO(p_demux, "%d:MP4_TrackSetup, handler_type: %c%c%c%c", __LINE__,
    		(p_hdlr->data.p_hdlr->i_handler_type >>24)&0xFF ,
			(p_hdlr->data.p_hdlr->i_handler_type >>16)&0xFF,
			(p_hdlr->data.p_hdlr->i_handler_type >>8)&0xFF,
			(p_hdlr->data.p_hdlr->i_handler_type    )&0xFF);

    switch( p_hdlr->data.p_hdlr->i_handler_type )
    {
        case( ATOM_soun ):
            if( !MP4_BoxGet( p_box_trak, "mdia/minf/smhd" ) )
            {
                return;
            }
            es_format_Change( &p_track->fmt, AUDIO_ES, 0 );
            break;

        case( ATOM_pict ): /* heif */
            es_format_Change( &p_track->fmt, VIDEO_ES, 0 );
            break;

        case( ATOM_vide ):
            if( !MP4_BoxGet( p_box_trak, "mdia/minf/vmhd") )
            {
                return;
            }
            es_format_Change( &p_track->fmt, VIDEO_ES, 0 );
            break;

        case( ATOM_hint ):
            /* RTP Reception Hint tracks */
            if( !MP4_BoxGet( p_box_trak, "mdia/minf/hmhd" ) ||
                !MP4_BoxGet( p_box_trak, "mdia/minf/stbl/stsd/rrtp" ) )
            {
                break;
            }
            MP4_Box_t *p_sdp;

            /* parse the sdp message to find out whether the RTP stream contained audio or video */
            if( !( p_sdp  = MP4_BoxGet( p_box_trak, "udta/hnti/sdp " ) ) )
            {
                msg_Warn( p_demux, "Didn't find sdp box to determine stream type" );
                return;
            }

            memcpy( sdp_media_type, BOXDATA(p_sdp)->psz_text, 7 );
            if( !strcmp(sdp_media_type, "m=audio") )
            {
                __LOG_DEBUG( p_demux, "Found audio Rtp: %s", sdp_media_type );
                es_format_Change( &p_track->fmt, AUDIO_ES, 0 );
            }
            else if( !strcmp(sdp_media_type, "m=video") )
            {
                __LOG_DEBUG( p_demux, "Found video Rtp: %s", sdp_media_type );
                es_format_Change( &p_track->fmt, VIDEO_ES, 0 );
            }
            else
            {
                msg_Warn( p_demux, "Malformed track SDP message: %s", sdp_media_type );
                return;
            }
            p_track->p_sdp = p_sdp;
            break;

        case( ATOM_tx3g ):
        case( ATOM_text ):
        case( ATOM_subp ):
        case( ATOM_subt ): /* ttml */
        case( ATOM_sbtl ):
        case( ATOM_clcp ): /* closed captions */
            es_format_Change( &p_track->fmt, SPU_ES, 0 );
            break;

        default:
            return;
    }

    p_track->asfinfo.i_cat = p_track->fmt.i_cat;

    const MP4_Box_t *p_elst;
    p_track->i_elst = 0;
    p_track->i_elst_time = 0;
    if( ( p_track->p_elst = p_elst = MP4_BoxGet( p_box_trak, "edts/elst" ) ) )
    {
        MP4_Box_data_elst_t *elst = BOXDATA(p_elst);
        unsigned int i;

        msg_Warn( p_demux, "elst box found" );
        for( i = 0; i < elst->i_entry_count; i++ )
        {
            __LOG_DEBUG( p_demux, "   - [%d] duration=%"PRId64"ms media time=%"PRId64
                     "ms) rate=%d.%d", i,
                     MP4_rescale( elst->i_segment_duration[i],
                    		isobmff_parameters->i_timescale, 1000 ),
                     elst->i_media_time[i] >= 0 ?
                        MP4_rescale( elst->i_media_time[i],
                        	isobmff_parameters->i_timescale, 1000 ) :
                        INT64_C(-1),
                     elst->i_media_rate_integer[i],
                     elst->i_media_rate_fraction[i] );
        }
    }


/*  TODO
    add support for:
    p_dinf = MP4_BoxGet( p_minf, "dinf" );
*/
    if( !( p_track->p_stbl = MP4_BoxGet( p_box_trak,"mdia/minf/stbl" ) ) ||
        !( p_track->p_stsd = MP4_BoxGet( p_box_trak,"mdia/minf/stbl/stsd") ) )
    {
        return;
    }

    /* Set language */
    if( *language && strcmp( language, "```" ) && strcmp( language, "und" ) )
    {
        p_track->fmt.psz_language = strdup( language );
    }

    const MP4_Box_t *p_udta = MP4_BoxGet( p_box_trak, "udta" );
    if( p_udta )
    {
        const MP4_Box_t *p_box_iter;
        for( p_box_iter = p_udta->p_first; p_box_iter != NULL;
                 p_box_iter = p_box_iter->p_next )
        {
            switch( p_box_iter->i_type )
            {
                case ATOM_0xa9nam:
                case ATOM_name:
                    p_track->fmt.psz_description =
                        strndup( p_box_iter->data.p_binary->p_blob,
                                 p_box_iter->data.p_binary->i_blob );
                default:
                    break;
            }
        }
    }

    /* Create chunk index table and sample index table */
//    if( TrackCreateChunksIndex( p_demux,p_track  ) ||
//        TrackCreateSamplesIndex( p_demux, p_track ) )
//    {
//        msg_Err( p_demux, "cannot create chunks index" );
//        return; /* cannot create chunks index */
//    }

    p_track->i_chunk  = 0;
    p_track->i_sample = 0;

//    /* Mark chapter only track */
//    if(mmtp_sub_flow->p_tref_chap )
//    {
//        MP4_Box_data_tref_generic_t *p_chap = mmtp_sub_flow->p_tref_chap->data.p_tref_generic;
//        unsigned int i;
//
//        for( i = 0; i < p_chap->i_entry_count; i++ )
//        {
//            if( p_track->i_track_ID == p_chap->i_track_ID[i] &&
//                p_track->fmt.i_cat == UNKNOWN_ES )
//            {
//                p_track->b_chapters_source = true;
//                p_track->b_enable = false;
//                break;
//            }
//        }
//    }

    const MP4_Box_t *p_tsel;
    /* now create es */
    if( b_force_enable &&
        ( p_track->fmt.i_cat == VIDEO_ES || p_track->fmt.i_cat == AUDIO_ES ) )
    {
        msg_Warn( p_demux, "Enabling track[Id 0x%x] (buggy file without enabled track)",
                  p_track->i_track_ID );
        p_track->b_enable = true;
        p_track->b_selected = true;
        p_track->fmt.i_priority = ES_PRIORITY_SELECTABLE_MIN;
    }
    else if ( (p_tsel = MP4_BoxGet( p_box_trak, "udta/tsel" )) )
    {
        if ( BOXDATA(p_tsel) && BOXDATA(p_tsel)->i_switch_group )
        {
            p_track->i_switch_group = BOXDATA(p_tsel)->i_switch_group;
            int i_priority = ES_PRIORITY_SELECTABLE_MIN;
            for ( unsigned int i = 0; i < isobmff_parameters->i_tracks; i++ )
            {
                const mp4_track_t *p_other = &isobmff_parameters->track[i];
                if( p_other && p_other != p_track &&
                    p_other->fmt.i_cat == p_track->fmt.i_cat &&
                    p_track->i_switch_group == p_other->i_switch_group )
                        i_priority = __MAX( i_priority, p_other->fmt.i_priority + 1 );
            }
            /* VLC only support ES priority for AUDIO_ES and SPU_ES.
               If there's another VIDEO_ES in the same group, we need to unselect it then */
            if ( p_track->fmt.i_cat == VIDEO_ES && i_priority > ES_PRIORITY_SELECTABLE_MIN )
                p_track->fmt.i_priority = ES_PRIORITY_NOT_DEFAULTABLE;
            else
                p_track->fmt.i_priority = i_priority;
        }
    }
    /* If there's no tsel, try to enable the track coming first in edit list */
    else if ( p_track->p_elst && p_track->fmt.i_priority == ES_PRIORITY_SELECTABLE_MIN )
    {
#define MAX_SELECTABLE (INT_MAX - ES_PRIORITY_SELECTABLE_MIN)
        for ( uint32_t i=0; i<p_track->BOXDATA(p_elst)->i_entry_count; i++ )
        {
            if ( p_track->BOXDATA(p_elst)->i_media_time[i] >= 0 &&
                 p_track->BOXDATA(p_elst)->i_segment_duration[i] )
            {
                /* We do selection by inverting start time into priority.
                   The track with earliest edit will have the highest prio */
                const int i_time = __MIN( MAX_SELECTABLE, p_track->BOXDATA(p_elst)->i_media_time[i] );
                p_track->fmt.i_priority = ES_PRIORITY_SELECTABLE_MIN + MAX_SELECTABLE - i_time;
                break;
            }
        }
    }

//    if( mmtp_sub_flow->hacks.es_cat_filters && (mmtp_sub_flow->hacks.es_cat_filters & p_track->fmt.i_cat) == 0 )
//    {
//        p_track->fmt.i_priority = ES_PRIORITY_NOT_DEFAULTABLE;
//    }

    if( !p_track->b_enable )
        p_track->fmt.i_priority = ES_PRIORITY_NOT_DEFAULTABLE;

    if( TrackCreateES( p_demux, isobmff_parameters,
                       p_track, p_track->i_chunk,
                      (p_track->b_chapters_source || !b_create_es) ? NULL : &p_track->p_es ) )
    {
        msg_Err( p_demux, "cannot create es for track[Id 0x%x]",
                 p_track->i_track_ID );
        return;
    }

    __LOG_INFO(p_demux, "%d:MP4_TrackSetup, Completed with track_es: %p",__LINE__, p_track->p_es);

    p_track->b_ok = true;
}

static void MP4_TrackInit( mp4_track_t *p_track )
{
    memset( p_track, 0, sizeof(mp4_track_t) );
    es_format_Init( &p_track->fmt, UNKNOWN_ES, 0 );
    p_track->i_timescale = 1;
}

static stime_t GetCumulatedDuration( demux_t *p_demux )
{
    demux_sys_t *p_sys = p_demux->p_sys;
    stime_t i_max_duration = 0;

    for ( unsigned int i=0; i<p_sys->i_tracks; i++ )
    {
        stime_t i_track_duration = 0;
        MP4_Box_t *p_trak = MP4_GetTrakByTrackID( p_sys->p_moov, p_sys->track[i].i_track_ID );
        const MP4_Box_t *p_stsz;
        const MP4_Box_t *p_tkhd;
        if ( (p_tkhd = MP4_BoxGet( p_trak, "tkhd" )) &&
             (p_stsz = MP4_BoxGet( p_trak, "mdia/minf/stbl/stsz" )) &&
             /* duration might be wrong an be set to whole duration :/ */
             BOXDATA(p_stsz)->i_sample_count > 0 )
        {
            i_max_duration = __MAX( (uint64_t)i_max_duration, BOXDATA(p_tkhd)->i_duration );
        }

        if( p_sys->p_fragsindex )
        {
            i_track_duration += MP4_Fragment_Index_GetTrackDuration( p_sys->p_fragsindex, i );
        }

        i_max_duration = __MAX( i_max_duration, i_track_duration );
    }

    return i_max_duration;
}

static stime_t GetMoovTrackDuration( demux_sys_t *p_sys, unsigned i_track_ID )
{
    MP4_Box_t *p_trak = MP4_GetTrakByTrackID( p_sys->p_moov, i_track_ID );
    const MP4_Box_t *p_stsz;
    const MP4_Box_t *p_tkhd;
    if ( (p_tkhd = MP4_BoxGet( p_trak, "tkhd" )) &&
         (p_stsz = MP4_BoxGet( p_trak, "mdia/minf/stbl/stsz" )) &&
         /* duration might be wrong an be set to whole duration :/ */
         BOXDATA(p_stsz)->i_sample_count > 0 )
    {
        if( BOXDATA(p_tkhd)->i_duration <= p_sys->i_moov_duration )
            return BOXDATA(p_tkhd)->i_duration; /* In movie / mvhd scale */
        else
            return p_sys->i_moov_duration;
    }
    return 0;
}

static bool GetMoofTrackDuration( MP4_Box_t *p_moov, MP4_Box_t *p_moof,
                                  unsigned i_track_ID, stime_t *p_duration )
{
    if ( !p_moof || !p_moov )
        return false;

    MP4_Box_t *p_traf = MP4_BoxGet( p_moof, "traf" );
    while ( p_traf )
    {
        if ( p_traf->i_type != ATOM_traf )
        {
           p_traf = p_traf->p_next;
           continue;
        }

        const MP4_Box_t *p_tfhd = MP4_BoxGet( p_traf, "tfhd" );
        const MP4_Box_t *p_trun = MP4_BoxGet( p_traf, "trun" );
        if ( !p_tfhd || !p_trun || i_track_ID != BOXDATA(p_tfhd)->i_track_ID )
        {
           p_traf = p_traf->p_next;
           continue;
        }

        uint32_t i_track_timescale = 0;
        uint32_t i_track_defaultsampleduration = 0;

        /* set trex for defaults */
        MP4_Box_t *p_trex = MP4_GetTrexByTrackID( p_moov, BOXDATA(p_tfhd)->i_track_ID );
        if ( p_trex )
        {
            i_track_defaultsampleduration = BOXDATA(p_trex)->i_default_sample_duration;
        }

        MP4_Box_t *p_trak = MP4_GetTrakByTrackID( p_moov, BOXDATA(p_tfhd)->i_track_ID );
        if ( p_trak )
        {
            MP4_Box_t *p_mdhd = MP4_BoxGet( p_trak, "mdia/mdhd" );
            if ( p_mdhd )
                i_track_timescale = BOXDATA(p_mdhd)->i_timescale;
        }

        if ( !i_track_timescale )
        {
           p_traf = p_traf->p_next;
           continue;
        }

        uint64_t i_traf_duration = 0;
        while ( p_trun && p_tfhd )
        {
            if ( p_trun->i_type != ATOM_trun )
            {
               p_trun = p_trun->p_next;
               continue;
            }
            const MP4_Box_data_trun_t *p_trundata = p_trun->data.p_trun;

            /* Sum total time */
            if ( p_trundata->i_flags & MP4_TRUN_SAMPLE_DURATION )
            {
                for( uint32_t i=0; i< p_trundata->i_sample_count; i++ )
                    i_traf_duration += p_trundata->p_samples[i].i_duration;
            }
            else if ( BOXDATA(p_tfhd)->i_flags & MP4_TFHD_DFLT_SAMPLE_DURATION )
            {
                i_traf_duration += p_trundata->i_sample_count *
                        BOXDATA(p_tfhd)->i_default_sample_duration;
            }
            else
            {
                i_traf_duration += p_trundata->i_sample_count *
                        i_track_defaultsampleduration;
            }

            p_trun = p_trun->p_next;
        }

        *p_duration = i_traf_duration;
        break;
    }

    return true;
}

static int ProbeFragments( demux_t *p_demux, mpu_isobmff_fragment_parameters_t* isobmff_parameters, bool b_force, bool *pb_fragmented )
{
    demux_sys_t *p_sys = p_demux->p_sys;

    __LOG_DEBUG( p_demux, "probing fragments from %"PRId64, vlc_stream_Tell( isobmff_parameters->s_frag ) );

    assert( isobmff_parameters->mpu_fragments_p_root_box );

    MP4_Box_t *p_vroot = MP4_BoxNew(ATOM_root);
    if( !p_vroot )
        return VLC_EGENERIC;

    if( p_sys->b_seekable && (p_sys->b_fastseekable || b_force) )
    {
        MP4_ReadBoxContainerChildren( isobmff_parameters->s_frag, p_vroot, NULL ); /* Get the rest of the file */
        p_sys->b_fragments_probed = true;

        const unsigned i_moof = MP4_BoxCount( p_vroot, "/moof" );
        if( i_moof )
        {
            *pb_fragmented = true;
            p_sys->p_fragsindex = MP4_Fragments_Index_New( p_sys->i_tracks, i_moof );
            if( !p_sys->p_fragsindex )
            {
                MP4_BoxFree( p_vroot );
                return VLC_EGENERIC;
            }

            stime_t *pi_track_times = calloc( p_sys->i_tracks, sizeof(*pi_track_times) );
            if( !pi_track_times )
            {
                MP4_Fragments_Index_Delete( p_sys->p_fragsindex );
                p_sys->p_fragsindex = NULL;
                MP4_BoxFree( p_vroot );
                return VLC_EGENERIC;
            }

            unsigned index = 0;

            for( MP4_Box_t *p_moof = p_vroot->p_first; p_moof; p_moof = p_moof->p_next )
            {
                if( p_moof->i_type != ATOM_moof )
                    continue;

                for( unsigned i=0; i<p_sys->i_tracks; i++ )
                {
                    MP4_Box_t *p_tfdt = NULL;
                    MP4_Box_t *p_traf = MP4_GetTrafByTrackID( p_moof, p_sys->track[i].i_track_ID );
                    if( p_traf )
                        p_tfdt = MP4_BoxGet( p_traf, "tfdt" );

                    if( p_tfdt && BOXDATA(p_tfdt) )
                    {
                        pi_track_times[i] = p_tfdt->data.p_tfdt->i_base_media_decode_time;
                    }
                    else if( index == 0 ) /* Set first fragment time offset from moov */
                    {
                        stime_t i_duration = GetMoovTrackDuration( p_sys, p_sys->track[i].i_track_ID );
                        pi_track_times[i] = MP4_rescale( i_duration, p_sys->i_timescale, p_sys->track[i].i_timescale );
                    }

                    stime_t i_movietime = MP4_rescale( pi_track_times[i], p_sys->track[i].i_timescale, p_sys->i_timescale );
                    p_sys->p_fragsindex->p_times[index * p_sys->i_tracks + i] = i_movietime;

                    stime_t i_duration = 0;
                    if( GetMoofTrackDuration( p_sys->p_moov, p_moof, p_sys->track[i].i_track_ID, &i_duration ) )
                        pi_track_times[i] += i_duration;
                }

                p_sys->p_fragsindex->pi_pos[index++] = p_moof->i_pos;
            }

            for( unsigned i=0; i<p_sys->i_tracks; i++ )
            {
                stime_t i_movietime = MP4_rescale( pi_track_times[i], p_sys->track[i].i_timescale, p_sys->i_timescale );
                if( p_sys->p_fragsindex->i_last_time < i_movietime )
                    p_sys->p_fragsindex->i_last_time = i_movietime;
            }

            free( pi_track_times );
#ifdef MP4_VERBOSE
            MP4_Fragments_Index_Dump( VLC_OBJECT(p_demux), p_sys->p_fragsindex, p_sys->i_timescale );
#endif
        }
    }
    else
    {
        /* We stop at first moof, which validates our fragmentation condition
         * and we'll find others while reading. */
        const uint32_t excllist[] = { ATOM_moof, 0 };
        MP4_ReadBoxContainerRestricted( isobmff_parameters->s_frag, p_vroot, NULL, excllist );
        /* Peek since we stopped before restriction */
        const uint8_t *p_peek;
        if ( vlc_stream_Peek( isobmff_parameters->s_frag, &p_peek, 8 ) == 8 )
            *pb_fragmented = (VLC_FOURCC( p_peek[4], p_peek[5], p_peek[6], p_peek[7] ) == ATOM_moof);
        else
            *pb_fragmented = false;
    }

    MP4_BoxFree( p_vroot );

    MP4_Box_t *p_mehd = MP4_BoxGet( p_sys->p_moov, "mvex/mehd");
    if ( !p_mehd )
           p_sys->i_cumulated_duration = GetCumulatedDuration( p_demux );

    return VLC_SUCCESS;
}

