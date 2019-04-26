#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libfindrtp.h"


addr_port_pair *_libfindrtp_parse_sccp_packet( const u_char *p, int plen ) {
	addr_port_pair *addr_port;
	extern unsigned int libfindrtp_debug;

// TODO: find minimum packet size for sccp
	if( plen <= 42 ) return 0;

	switch( p[62] ) {
		case 0x8a: // StartMediaTransmission
			addr_port = malloc(sizeof(addr_port_pair));
			memcpy( &addr_port->addr, &p[74], 4 );
			memcpy( &addr_port->port, &p[78], 2 );
			break;
		case 0x22: // OpenReceiveChannelAck
			addr_port = malloc(sizeof(addr_port_pair));
			memcpy( &addr_port->addr, &p[70], 4 );
			memcpy( &addr_port->port, &p[74], 2 );
			break;
		default:
			return NULL;
	}

	if(libfindrtp_debug) printf( "RTP port=%d\n", addr_port->port );

	return addr_port;
}

