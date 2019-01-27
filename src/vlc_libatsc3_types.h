/*
 * vlc_libatsc3_types.h
 *
 *  Created on: Jan 21, 2019
 *      Author: jjustman
 */

#ifndef MODULES_DEMUX_MMT_VLC_LIBATSC3_TYPES_H_
#define MODULES_DEMUX_MMT_VLC_LIBATSC3_TYPES_H_

#ifndef LIBATSC3_MPU_ISOBMFF_FRAGMENT_PARAMETERS_T_
#define LIBATSC3_MPU_ISOBMFF_FRAGMENT_PARAMETERS_T_

typedef struct {
	mp4_track_t*	mpu_demux_track;
	block_t*		p_mpu_block;
	uint32_t     	i_timescale;          /* movie time scale */
	uint64_t     	i_moov_duration;
	uint64_t     	i_cumulated_duration; /* Same as above, but not from probing, (movie time scale) */
	uint64_t     	i_duration;           /* Declared fragmented duration (movie time scale) */
	unsigned int 	i_tracks;       /* number of tracks */
	mp4_track_t  	*track;         /* array of track */
	bool        	b_fragmented;   /* fMP4 */
	bool         	b_seekable;
	stream_t 		*s_frag;


	block_t* 		tmp_mpu_fragment_block_t;
	//todo - free stream when box is removed - 			vlc_stream_Delete(tmp_mpu_fragment_stream);

	block_t* 		mpu_fragment_block_t;  //capture our MPU Metadat box

	MP4_Box_t*		mpu_fragments_p_root_box;
	MP4_Box_t*		mpu_fragments_p_moov;

	//reconstitue per movie fragment as needed
	block_t* 		mp4_movie_fragment_block_t;
	MP4_Box_t*		mpu_fragments_p_moof;


	struct
	{
		 uint32_t        i_current_box_type;
		 MP4_Box_t      *p_fragment_atom;
		 uint64_t        i_post_mdat_offset;
		 uint32_t        i_lastseqnumber;
	} context;
} mpu_isobmff_fragment_parameters_t;

#endif


typedef struct
{
	vlc_object_t *obj;
	//hack for cross-parsing
	uint8_t *raw_buf;
	uint8_t *buf;

	//reconsititue mfu's into a p_out_muxed fifo

	block_t *p_mpu_block;

	//everthing below here is from libmp4

    MP4_Box_t    *p_root;      /* container for the whole file */
    MP4_Box_t	 *p_moov;

    vlc_tick_t   i_pcr;

    uint64_t     i_moov_duration;
    uint64_t     i_duration;           /* Declared fragmented duration (movie time scale) */
    uint64_t     i_cumulated_duration; /* Same as above, but not from probing, (movie time scale) */
    uint32_t     i_timescale;          /* movie time scale */
    vlc_tick_t   i_nztime;             /* time position of the presentation (CLOCK_FREQ timescale) */
    unsigned int i_tracks;       /* number of tracks */
    mp4_track_t  *track;         /* array of track */
    float        f_fps;          /* number of frame per seconds */

    bool         b_fragmented;   /* fMP4 */
    bool         b_seekable;
    bool         b_fastseekable;
    bool         b_error;        /* unrecoverable */

    bool            b_index_probed;     /* mFra sync points index */
    bool            b_fragments_probed; /* moof segments index created */


    struct
    {
        uint32_t        i_current_box_type;
        MP4_Box_t      *p_fragment_atom;
        uint64_t        i_post_mdat_offset;
        uint32_t        i_lastseqnumber;
    } context;

    /* */
    MP4_Box_t    *p_tref_chap;

    /* */
    bool seekpoint_changed;
    int          i_seekpoint;
    vlc_meta_t    *p_meta;

    /* ASF in MP4 */
    asf_packet_sys_t asfpacketsys;
    vlc_tick_t i_preroll;       /* foobar */
    vlc_tick_t i_preroll_start;

    struct
    {
        int es_cat_filters;
    } hacks;

    mp4_fragments_index_t *p_fragsindex;

    sig_atomic_t has_processed_ftype_moov;

    /** temp hacks until we have a map of mpu_sequence_numbers, use -1 for default values (0 is valid in mmtp spec)**/
    sig_atomic_t last_mpu_sequence_number;
    sig_atomic_t last_mpu_fragment_type;

    mmtp_sub_flow_vector_t mmtp_sub_flow_vector;

    bool has_set_ntp_to_pts_offset;
    uint64_t ntp_to_pts_offset_us;

    bool has_set_first_pcr;
    uint64_t first_pcr;

    bool has_set_first_pts;
    uint64_t first_pts;
    uint64_t last_pts;
} demux_sys_t;


int mmtp_packet_header_parse_from_raw_packet(mmtp_payload_fragments_union_t *mmtp_packet, demux_t *p_demux ) {

	demux_sys_t *p_sys = p_demux->p_sys;

	//hack for joint parsing.....
	p_sys->raw_buf = malloc( MAX_MMTP_SIZE );
	p_sys->buf = p_sys->raw_buf; //use buf to walk thru bytes in extract method without touching rawBuf

	uint8_t *raw_buf = p_sys->raw_buf;
	uint8_t *buf = p_sys->buf;

	block_ChainExtract(mmtp_packet->mmtp_packet_header.raw_packet, raw_buf, MAX_MMTP_SIZE);

	//	block_ChainExtract(mmtp_packet->mmtp_packet_header.raw_packet, raw_buf, MAX_MMTP_SIZE);



	...

	p_sys->raw_buf = raw_buf;
	p_sys->buf =  buf;

	return VLC_DEMUXER_SUCCESS;

error:

	return VLC_DEMUXER_EGENERIC;



}


#endif /* MODULES_DEMUX_MMT_VLC_LIBATSC3_TYPES_H_ */
