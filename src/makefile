all: intermediate libatsc3_core unit_tests listener_tests
clean:
	rm -f *.o
	
intermediate: xml.o  atsc3_lls.o atsc3_mmtp_parser.o atsc3_mmt_mpu_parser.o atsc3_mmt_signaling_message.o atsc3_mmtp_ntp32_to_pts.o atsc3_utils.o fixups_timespec_get.o
libatsc3_core: libatsc3.o
unit_tests: atsc3_lmt_test atsc3_lls_slt_parser_test atsc3_lls_test atsc3_lls_SystemTime_test atsc3_mmt_signaling_message_test
listener_tests: atsc3_lls_listener_test atsc3_mmt_listener_test

#intermediate object gen

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

	
#core libatsc3 library gen

libatsc3.o: atsc3_lls.o atsc3_mmtp_parser.o atsc3_mmtp_ntp32_to_pts.o atsc3_utils.o fixups_timespec_get.o atsc3_mmt_signaling_message.o atsc3_mmt_mpu_parser.o
	ld -o libatsc3.o -r xml.o atsc3_lls.o atsc3_mmtp_parser.o atsc3_mmtp_ntp32_to_pts.o atsc3_utils.o fixups_timespec_get.o atsc3_mmt_signaling_message.o atsc3_mmt_mpu_parser.o

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

atsc3_lls_listener_test: atsc3_lls_listener_test.c libatsc3.o
	cc -g atsc3_lls_listener_test.c libatsc3.o -lz -lpcap -o atsc3_lls_listener_test
	
	
atsc3_mmt_listener_test: atsc3_mmt_listener_test.c libatsc3.o
	cc -g atsc3_mmt_listener_test.c libatsc3.o -lz -lpcap -o atsc3_mmt_listener_test
	
