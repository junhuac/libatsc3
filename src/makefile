all: intermediate_mmt intermediate_alc libatsc3_core unit_tests listener_tests
clean:
	rm -f *.o
	
intermediate_mmt: xml.o  atsc3_lls.o atsc3_mmtp_parser.o atsc3_mmt_mpu_parser.o atsc3_mmt_signaling_message.o atsc3_mmtp_ntp32_to_pts.o atsc3_utils.o fixups_timespec_get.o
intermediate_alc:alc_rx.c alc_session.c fec.c null_fec.c rs_fec.c xor_fec.c
libatsc3_core: libatsc3.o
unit_tests: atsc3_lmt_test atsc3_lls_slt_parser_test atsc3_lls_test atsc3_lls_SystemTime_test atsc3_mmt_signaling_message_test
listener_tests: atsc3_alc_listener_test atsc3_lls_listener_test atsc3_mmt_listener_test atsc3_listener_test atsc3_listener_metrics_test 


#intermediate_mmt object gen

xml.o: xml.c xml.h
	cc -g -c xml.c 

atsc3_lls.o: atsc3_utils.h atsc3_lls.h atsc3_lls.c
	cc -g -c atsc3_lls.c

atsc3_mmtp_parser.o: atsc3_mmtp_types.h atsc3_mmtp_parser.h atsc3_mmtp_parser.c 
	cc -g -c atsc3_mmtp_parser.c
	
atsc3_mmt_mpu_parser.o: atsc3_mmtp_types.h atsc3_mmtp_parser.h atsc3_mmt_mpu_parser.c
	cc -g -c atsc3_mmt_mpu_parser.c

atsc3_mmt_signaling_message.o: atsc3_mmt_signaling_message.c atsc3_mmt_signaling_message.h
	cc -g -c atsc3_mmt_signaling_message.c

atsc3_mmtp_ntp32_to_pts.o: atsc3_mmtp_ntp32_to_pts.c atsc3_mmtp_ntp32_to_pts.h
	cc -g -c atsc3_mmtp_ntp32_to_pts.c

atsc3_utils.o: atsc3_utils.h atsc3_utils.c  
	cc -g -c atsc3_utils.c
	
fixups_timespec_get.o:  fixups.h fixups_timespec_get.c
	cc -g -c fixups_timespec_get.c

alc_rx.o:  alc_rx.h alc_rx.c
	cc -g -c alc_rx.c

	
	
#core libatsc3 library gen

libatsc3.o: atsc3_lls.o atsc3_mmtp_parser.o atsc3_mmtp_ntp32_to_pts.o atsc3_utils.o fixups_timespec_get.o atsc3_mmt_signaling_message.o atsc3_mmt_mpu_parser.o alc_channel.o alc_list.o alc_rx.o alc_session.o fec.o null_fec.o rs_fec.o xor_fec.o mad.o mad_rlc.o transport.o
	ld -o libatsc3.o -r xml.o atsc3_lls.o atsc3_mmtp_parser.o atsc3_mmtp_ntp32_to_pts.o atsc3_utils.o fixups_timespec_get.o atsc3_mmt_signaling_message.o atsc3_mmt_mpu_parser.o alc_channel.o alc_list.o alc_rx.o alc_session.o fec.o null_fec.o rs_fec.o xor_fec.o mad.o mad_rlc.o transport.o

#unit test generation

atsc3_lmt_test: atsc3_lmt_test.c libatsc3.o
	cc -g atsc3_lmt_test.c libatsc3.o -lz -o atsc3_lmt_test
			  
atsc3_lls_test: atsc3_lls_test.c libatsc3.o
	cc -g atsc3_lls_test.c libatsc3.o -lz -o atsc3_lls_test
		   		   
atsc3_lls_slt_parser_test: atsc3_lls_slt_parser_test.c libatsc3.o
	cc -g atsc3_lls_slt_parser_test.c libatsc3.o -lz -o atsc3_lls_slt_parser_test 

atsc3_lls_SystemTime_test: atsc3_lls_SystemTime_test.c libatsc3.o
	cc -g atsc3_lls_SystemTime_test.c libatsc3.o -lz -o atsc3_lls_SystemTime_test 

atsc3_mmt_signaling_message_test: atsc3_mmt_signaling_message_test.c libatsc3.o
	cc -g atsc3_mmt_signaling_message_test.c libatsc3.o -lz -o atsc3_mmt_signaling_message_test

#integration tests

atsc3_alc_listener_test: atsc3_alc_listener_test.c libatsc3.o
	cc -g atsc3_alc_listener_test.c libatsc3.o -lz -lpcap -o atsc3_alc_listener_test
atsc3_lls_listener_test: atsc3_lls_listener_test.c libatsc3.o
	cc -g atsc3_lls_listener_test.c libatsc3.o -lz -lpcap -o atsc3_lls_listener_test
	
	
atsc3_mmt_listener_test: atsc3_mmt_listener_test.c libatsc3.o
	cc -g atsc3_mmt_listener_test.c libatsc3.o -lz -lpcap -o atsc3_mmt_listener_test
	
	
atsc3_listener_test: atsc3_listener_test.c libatsc3.o
	cc -g atsc3_listener_test.c libatsc3.o -lz -lpcap -o atsc3_listener_test
	
atsc3_listener_metrics_test: atsc3_listener_metrics_test.c libatsc3.o
	cc -g atsc3_listener_metrics_test.c libatsc3.o -lz -lpcap -o atsc3_listener_metrics_test
	
