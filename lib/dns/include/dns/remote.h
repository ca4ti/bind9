/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

/*! \file dns/remote.h */

#include <stdbool.h>

#include <isc/lang.h>
#include <isc/mem.h>

#include <dns/types.h>

ISC_LANG_BEGINDECLS

struct dns_remote {
	isc_mem_t      *mctx;
	isc_sockaddr_t *addresses;
	isc_sockaddr_t *sources;
	isc_dscp_t     *dscps;
	dns_name_t    **keynames;
	dns_name_t    **tlsnames;
	bool	       *ok;
	unsigned int	addrcnt;
	unsigned int	curraddr;
};

isc_sockaddr_t *
dns_remote_addresses(dns_remote_t *remote);
/*%<
 *	Return the addresses of the remote server.
 *
 *	Requires:
 *		'remote' is not NULL.
 */

isc_sockaddr_t *
dns_remote_sources(dns_remote_t *remote);
/*%<
 *	Return the source addresses to be used for the remote server.
 *
 *	Requires:
 *		'remote' is not NULL.
 */

unsigned int
dns_remote_count(dns_remote_t *remote);
/*%<
 *	Return the number of addresses of the remote server.
 *
 *	Requires:
 *		'remote' is not NULL.
 */

dns_name_t **
dns_remote_keynames(dns_remote_t *remote);
/*%<
 *	Return the keynames of the remote server.
 *
 *	Requires:
 *		'remote' is not NULL.
 */

dns_name_t **
dns_remote_tlsnames(dns_remote_t *remote);
/*%<
 *	Return the tlsnames of the remote server.
 *
 *	Requires:
 *		'remote' is not NULL.
 */

void
dns_remote_init(dns_remote_t *remote, unsigned int count,
		const isc_sockaddr_t *addrs, const isc_sockaddr_t *srcs,
		const isc_dscp_t *dscp, dns_name_t **keynames,
		dns_name_t **tlsnames, bool mark, isc_mem_t *mctx);

/*%<
 *	Initialize a remote server. Set the provided addresses (addrs),
 *	source addresses (srcs), dscp's (dscp), key names (keynames) and
 *	tls names (tlsnames). Use the provided memory context (mctx) for
 *	allocations. If 'mark' is 'true', set up a list of boolean values to
 *	mark the server bad or good.
 *
 *	Requires:
 *		'remote' is not NULL.
 *		'mctx' is not NULL.
 *		'addrs' is not NULL, or 'count' equals zero.
 *		'keynames' and 'tlsnames' are not NULL, then 'count > 0'.
 */

void
dns_remote_clear(dns_remote_t *remote);
/*%<
 *	Clear remote server 'remote', free memory.
 *
 *	Requires:
 *		'remote' is not NULL.
 */

bool
dns_remote_equal(dns_remote_t *a, dns_remote_t *b);
/*%<
 *	Compare two remote servers 'a' and 'b'. Check if the address
 *	count, the addresses, the dscps, the key names and the tls names are
 *	the same. Return 'true' if so, 'false' otherwise.
 *
 *	Requires:
 *		'a' is not NULL and 'b' is not NULL.
 */

void
dns_remote_reset(dns_remote_t *remote, bool clear_ok);
/*%<
 *	Reset the remote server, set the current address back to the
 *	first. If 'clear_ok' is 'true', clear any servers marked ok.
 *
 *	Requires:
 *		'remote' is not NULL.
 */

void
dns_remote_next(dns_remote_t *remote, bool skip_good);
/*%<
 *	Skip to the next address. If 'skip_good' is 'true', skip over
 *	already addresses already considered good, whatever good means in the
 *	context of this remote server.
 *
 *	Requires:
 *		'remote' is not NULL.
 */

isc_sockaddr_t
dns_remote_curraddr(dns_remote_t *remote);
/*%<
 *	Return the currently used address for this remote server.
 *
 *	Requires:
 *		'remote' is not NULL.
 *		'remote->addresses' is not NULL.
 */

isc_sockaddr_t
dns_remote_sourceaddr(dns_remote_t *remote);
/*%<
 *	Return the current source address.
 *
 *	Requires:
 *		'remote' is not NULL.
 *		'remote->sources' is not NULL.
 */

isc_sockaddr_t
dns_remote_addr(dns_remote_t *remote, unsigned int i);
/*%<
 *	Return the address at index 'i'.
 *
 *	Requires:
 *		'remote' is not NULL.
 *		'remote->addresses' is not NULL.
 */

isc_dscp_t
dns_remote_dscp(dns_remote_t *remote);
/*%<
 *	Return the current dscp. Returns -1 if we have iterated over all
 *	addresses already, or if dscps are not used.
 *
 *	Requires:
 *		'remote' is not NULL.
 */

dns_name_t *
dns_remote_keyname(dns_remote_t *remote);
/*%<
 *	Return the current key name. Returns NULL if we have iterated
 *	over all addresses already, or if keynames are not used.
 *
 *	Requires:
 *		'remote' is not NULL.
 */

dns_name_t *
dns_remote_tlsname(dns_remote_t *remote);
/*%<
 *	Return the current tls name. Returns NULL if we have iterated
 *	over all addresses already, or if tlsnames are not used.
 *
 *	Requires:
 *		'remote' is not NULL.
 */

void
dns_remote_mark(dns_remote_t *remote, bool good);
/*%<
 *	Mark the current address 'good' (or not good if 'good' is
 *	'false').
 *
 *	Requires:
 *		'remote' is not NULL.
 *		The current address index is lower than the address count.
 */

bool
dns_remote_done(dns_remote_t *remote);
/*%<
 *	Return 'true' if we iterated over all addresses, 'false' otherwise.
 *
 *	Requires:
 *		'remote' is not NULL.
 */

ISC_LANG_ENDDECLS
