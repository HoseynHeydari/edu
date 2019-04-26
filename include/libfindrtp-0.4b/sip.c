#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include "libfindrtp.h"


addr_port_pair *_libfindrtp_parse_sip_packet( const u_char *p, int plen ) {
	int port = 0;
	int ret;
	unsigned char sip[4096];
	unsigned char *pport;
	unsigned char sdp_media_audio[]="\r\nm=audio ";
	addr_port_pair *addr_port;
	extern unsigned int libfindrtp_debug;

	if( plen <= 42 ) return NULL;

	addr_port = malloc(sizeof(addr_port_pair));
	addr_port->addr = 0;
	addr_port->port = 0;

	memcpy( sip, &p[42], plen - 42 );
	sip[plen - 42] = 0;

	pport = (unsigned char *)strstr( (char *)sip, (char *)sdp_media_audio );
	if(!pport) {
		free(addr_port);
		return NULL;
	}

	pport += strlen( (char *)sdp_media_audio );
	ret = sscanf( (const char *)pport, "%d%*[ ]RTP%*s", &port );
	if(!ret) {
		free(addr_port);
		return NULL;
	}

	if(libfindrtp_debug) printf( "RTP port=%d\n", port );

	/* Using src Address from IP header */
	memcpy( &addr_port->addr, &p[26], 4 );
	addr_port->port = htons(port);

	return addr_port;
}

