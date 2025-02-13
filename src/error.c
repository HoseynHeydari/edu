/*
 *  steganRTP: error.c
 *
 *    error functions
 *
 *  Copyright (C) 2006  Dustin D. Trammell
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Author:
 *    04/2007 - I)ruid <druid@caughq.org>
 *
 */

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "steganrtp.h"


void nfq_error() {
	extern context ctx;
	extern int verbosity;

	if(verbosity) ipq_perror("libipq");
	if(ctx.qh) ipq_destroy_handle( ctx.qh );
}

void nfq_fatal() {
	nfq_error();
	steganrtp_exit( -1, NULL );
}
