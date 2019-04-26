#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <pcap.h>
#include "libfindrtp.h"


void _libfindrtp_packet_handler( u_char *null, const struct pcap_pkthdr *h, const u_char *p ) {
	extern unsigned int libfindrtp_debug;
	extern rtp_pair lfr_rp;
	addr_port_pair *addr_port = NULL;
	u_int16_t port = 0;

	/* reject non-IP packets */
	if( (p[12] != 0x08) || (p[13] != 0x00) ) return;

	/* Cisco Skinny (SCCP) */
   port = htons(LIBFINDRTP_SCCP_PORT);
   if( p[23] == 0x06 &&                             // TCP
	    ( (!memcmp( &port, &p[34], 2 )) ||          // Src port is SCCP (or)
         (!memcmp( &port, &p[36], 2 )) ) ) {       // Dst port is SCCP

		if(libfindrtp_debug) printf( "libfindrtp_find_rtp(): Got a SCCP packet, looking for RTP port numbers...\n");

		addr_port = _libfindrtp_parse_sccp_packet( p, h->caplen );

		if( addr_port ) {
			if(libfindrtp_debug) printf( "libfindrtp_find_rtp(): Found RTP port number.\n");

			/* OpenReceiveChannelAck packet */
			if( p[62] == 0x22 ) {
				/* Fill-in side A */
				memcpy( &lfr_rp.ip_a_n, &addr_port->addr, 4 );
				lfr_rp.ip_a = ntohl(lfr_rp.ip_a_n);
				sprintf( lfr_rp.ip_a_a, "%s", inet_ntoa( *((struct in_addr *)&lfr_rp.ip_a_n)) );
				/* Null side B */
				lfr_rp.ip_b_n = lfr_rp.ip_b = 0;
				memset( &lfr_rp.ip_a_a, 0, 16 );
			}

			/* StartMediaTransmission packet */
			if( p[62] == 0x0a ) {
				/* If destination address of packet is same as first side of session */
				if( !memcmp( &lfr_rp.ip_a_n, &p[30], 4) ) {
					/* Fill in side B */
					memcpy( &lfr_rp.ip_b_n, &addr_port->addr, 4 );
					lfr_rp.ip_b = ntohl(lfr_rp.ip_b_n);
					sprintf( lfr_rp.ip_b_a, "%s", inet_ntoa( *((struct in_addr *)&lfr_rp.ip_b_n)) );
				}
			}
		}
	}

	/* SIP */
	port = htons(LIBFINDRTP_SIP_PORT);
	if( p[23] == 0x11 &&                             // UDP
       ( (!memcmp( &port, &p[34], 2 )) ||          // Src port is SIP (or)
	      (!memcmp( &port, &p[36], 2 )) )  ) {      // Dst port is SIP

		if(libfindrtp_debug) printf( "libfindrtp_find_rtp(): Got a SIP packet, looking for SDP/RTP port numbers...\n");

		addr_port = _libfindrtp_parse_sip_packet( p, h->caplen );

		if( addr_port ) {
			if(libfindrtp_debug) printf( "libfindrtp_find_rtp(): Found RTP port number.\n");

			/* struct has no addresses yet */
			if( !lfr_rp.ip_a && !lfr_rp.ip_b ) {
				if(libfindrtp_debug) printf( "No addresses in struct yet...\n" );
				memcpy( &lfr_rp.ip_a_n, &addr_port->addr, 4 );
				lfr_rp.ip_a = ntohl(lfr_rp.ip_a_n);
				sprintf( lfr_rp.ip_a_a, "%s", inet_ntoa( *((struct in_addr *)&lfr_rp.ip_a_n)) );
				memcpy( &lfr_rp.ip_b_n, &p[30], 4 );
				lfr_rp.ip_b = ntohl(lfr_rp.ip_b_n);
				sprintf( lfr_rp.ip_b_a, "%s", inet_ntoa( *((struct in_addr *)&lfr_rp.ip_b_n)) );
			} else
			/* struct has only address a */
			if( !lfr_rp.ip_b ) {
				if(libfindrtp_debug) printf( "Address A still missing in struct...\n" );
				if( !memcmp( &lfr_rp.ip_a_n, &addr_port->addr, 4 ) ) { 
					memcpy( &lfr_rp.ip_b_n, &p[30], 4 );
					lfr_rp.ip_b = ntohl(lfr_rp.ip_b_n);
					sprintf( lfr_rp.ip_b_a, "%s", inet_ntoa( *((struct in_addr *)&lfr_rp.ip_b_n)) );
				} else
				if( !memcmp( &lfr_rp.ip_a_n, &p[30], 4 ) ) {
					memcpy( &lfr_rp.ip_b_n, &addr_port->addr, 4 ); 
					lfr_rp.ip_b = ntohl(lfr_rp.ip_b_n);
					sprintf( lfr_rp.ip_b_a, "%s", inet_ntoa( *((struct in_addr *)&lfr_rp.ip_b_n)) );
				}
			} else 
			/* struct has only address b */
			if( !lfr_rp.ip_a ) {
				if(libfindrtp_debug) printf( "Address B still missing in struct...\n" );
				if( !memcmp( &lfr_rp.ip_b_n, &addr_port->addr, 4 ) ) { 
					memcpy( &lfr_rp.ip_a_n, &p[30], 4 );
					lfr_rp.ip_a = ntohl(lfr_rp.ip_a_n);
					sprintf( lfr_rp.ip_a_a, "%s", inet_ntoa( *((struct in_addr *)&lfr_rp.ip_a_n)) );
				} else
				if( !memcmp( &lfr_rp.ip_b_n, &p[30], 4 ) ) {
					memcpy( &lfr_rp.ip_a_n, &addr_port->addr, 4 ); 
					lfr_rp.ip_a = ntohl(lfr_rp.ip_a_n);
					sprintf( lfr_rp.ip_a_a, "%s", inet_ntoa( *((struct in_addr *)&lfr_rp.ip_a_n)) );
				}
			} 
			
			/* check for IP addresses match in struct for a and b */
			if( !memcmp( &lfr_rp.ip_a_n, &addr_port->addr, 4 ) && !lfr_rp.port_a ) {
				if(libfindrtp_debug) printf( "Found address match for IP A, writing port\n" );
				if( lfr_rp.ip_a_n == lfr_rp.ip_b_n && lfr_rp.port_b_n == addr_port->port ) {
					/* Already have this side of the local connection */
				} else {
					lfr_rp.port_a_n = addr_port->port;
					lfr_rp.port_a = ntohs(addr_port->port);
				}
			}
			if( !memcmp( &lfr_rp.ip_b_n, &addr_port->addr, 4 ) && !lfr_rp.port_b ) {
				if(libfindrtp_debug) printf( "Found address match for IP B, writing port\n" );
				if( lfr_rp.ip_a_n == lfr_rp.ip_b_n && lfr_rp.port_a_n == addr_port->port ) {
					/* Already have this side of the local connection */
				} else {
					lfr_rp.port_b_n = addr_port->port;
					lfr_rp.port_b = ntohs(addr_port->port);
				}
			}
			free(addr_port);
		}
	}

	return;
}

