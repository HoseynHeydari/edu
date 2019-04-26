/*
 *  libfindrtp
 *  Dustin D. Trammell <dtrammell@tippingpoint.com>
 *  12/2006
 *
 *  This library provides RTP based tools a method to auto-identify
 *  an RTP session's endpoint addresses and UDP ports.  It does this
 *  by watching the network for signaling and extracting the negotiated
 *  RTP ports from the signaling messages.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <pcap.h>
#include "libfindrtp.h"

unsigned int libfindrtp_debug;
rtp_pair lfr_rp;


rtp_pair *libfindrtp_find_rtp( char *interface, unsigned int promisc, char *host_a, char *host_b ) {
	rtp_pair *rp;

	memset( &lfr_rp, 0, sizeof(lfr_rp) );

	if( host_a ) {
		if( inet_pton( AF_INET, host_a, &lfr_rp.ip_a_n ) <= 0 ) {
			if(libfindrtp_debug) fprintf( stderr, "libfindrtp_find_rtp() ERROR: %s is not a valid IP address\n", host_a );
			return NULL;
		}
		if(lfr_rp.ip_a_n) {
			lfr_rp.ip_a = ntohl( lfr_rp.ip_a_n );
			sprintf( lfr_rp.ip_a_a, "%s", inet_ntoa( *((struct in_addr *)&lfr_rp.ip_a_n)) );
		}
	}

	if( host_b ) {
		if( inet_pton( AF_INET, host_b, &lfr_rp.ip_b_n ) <= 0 ) {
			if(libfindrtp_debug) fprintf( stderr, "libfindrtp_find_rtp() ERROR: %s is not a valid IP address\n", host_b );
			return NULL;
		}
		if(lfr_rp.ip_b_n) {
			lfr_rp.ip_b = ntohl( lfr_rp.ip_b_n );
			sprintf( lfr_rp.ip_b_a, "%s", inet_ntoa( *((struct in_addr *)&lfr_rp.ip_b_n)) );
		}
	}

	/* network interface */
	if(!interface)
		interface = LIBFINDRTP_IF;
	if(libfindrtp_debug) printf( "Targeting interface %s\n", interface );

	pcap_t *pcap;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];

	pcap = pcap_open_live( interface, 4096, promisc, 0, pcap_errbuf );
	if(!pcap) {
		if(libfindrtp_debug) fprintf( stderr, "libfindrtp ERROR: couldn't open %s in promiscuous mode\n", interface );
		if(libfindrtp_debug) fprintf( stderr, "libfindrtp ERROR: pcap says: %s\n", pcap_errbuf );
		return NULL;
	}

	bpf_u_int32 dev_net;
	bpf_u_int32 dev_mask;
	if( pcap_lookupnet( interface, &dev_net, &dev_mask, pcap_errbuf )) {
		if(libfindrtp_debug) fprintf( stderr, "libfindrtp ERROR: couldn't lookup %s's IP and netmask\n", interface );
		if(libfindrtp_debug) fprintf( stderr, "libfindrtp_find_rtp() ERROR: pcap says: %s\n", pcap_errbuf );
		return NULL;
	}

	char filterbuf[1024];
	if( host_a && host_b ) sprintf( filterbuf, "(host %s or host %s) and ip", host_a, host_b );
	else if( host_a && !host_b ) sprintf( filterbuf, "host %s and ip", host_a );
	else if( host_b && !host_a ) sprintf( filterbuf, "host %s and ip", host_b );
	else sprintf( filterbuf, "ip" );
	if(libfindrtp_debug) printf( "libfindrtp_find_rtp(): using pcap filter \"%s\".\n", filterbuf );

	struct bpf_program pfilter;
	if( pcap_compile( pcap, &pfilter, filterbuf, 1, dev_mask ) ) {
		if(libfindrtp_debug) fprintf( stderr, "libfindrtp_find_rtp() ERROR: couldn't compile pcap filter:\n  \"%s\"", filterbuf );
		return NULL;
	}
	if( pcap_setfilter( pcap, &pfilter ) ) {
		if(libfindrtp_debug) fprintf( stderr, "ERROR: couldn't set this filter:\n  \"%s\"", filterbuf );
		return NULL;
	}

	int pcnt;
	while( !lfr_rp.ip_a || !lfr_rp.port_a || !lfr_rp.ip_b || !lfr_rp.port_b ) {
		pcnt = pcap_dispatch( pcap, 1, _libfindrtp_packet_handler, NULL );
		if(libfindrtp_debug>=2) printf( "State: ip_a == %s | port_a == %d | ip_b == %s | port_b == %d\n", lfr_rp.ip_a_a, lfr_rp.port_a, lfr_rp.ip_b_a, lfr_rp.port_b );
		if( pcnt < 0 ) {
			if(libfindrtp_debug) fprintf( stderr, "libfindrtp_find_rtp() ERROR: during pcap\n");
			return NULL;
		}
	}

	pcap_freecode(&pfilter);

	rp = malloc( sizeof(rtp_pair) );
	memcpy( rp, &lfr_rp, sizeof(rtp_pair) );

	return rp;
}

