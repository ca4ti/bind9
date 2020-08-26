/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/types.h>

#include <openssl/ssl.h>

/*
 * Replacement for isc_sockettype_t provided by socket.h.
 */
typedef enum {
	isc_socktype_tcp = 1,
	isc_socktype_udp = 2,
	isc_socktype_unix = 3,
	isc_socktype_raw = 4
} isc_socktype_t;

typedef void (*isc_nm_recv_cb_t)(isc_nmhandle_t *handle, isc_result_t eresult,
				 isc_region_t *region, void *cbarg);
/*%<
 * Callback function to be used when receiving a packet.
 *
 * 'handle' the handle that can be used to send back the answer.
 * 'eresult' the result of the event.
 * 'region' contains the received data, if any. It will be freed
 *          after return by caller.
 * 'cbarg'  the callback argument passed to isc_nm_listenudp(),
 *          isc_nm_listentcpdns(), or isc_nm_read().
 */
typedef isc_result_t (*isc_nm_accept_cb_t)(isc_nmhandle_t *handle,
					   isc_result_t result, void *cbarg);
/*%<
 * Callback function to be used when accepting a connection. (This differs
 * from isc_nm_cb_t below in that it returns a result code.)
 *
 * 'handle' the handle that can be used to send back the answer.
 * 'eresult' the result of the event.
 * 'cbarg'  the callback argument passed to isc_nm_listentcp() or
 * isc_nm_listentcpdns().
 */

typedef void (*isc_nm_cb_t)(isc_nmhandle_t *handle, isc_result_t result,
			    void *cbarg);
/*%<
 * Callback function for other network completion events (send, connect).
 *
 * 'handle' the handle on which the event took place.
 * 'eresult' the result of the event.
 * 'cbarg'  the callback argument passed to isc_nm_send(),
 *          isc_nm_tcp_connect(), or isc_nm_listentcp()
 */

typedef void (*isc_nm_opaquecb_t)(void *arg);
/*%<
 * Opaque callback function, used for isc_nmhandle 'reset' and 'free'
 * callbacks.
 */

isc_nm_t *
isc_nm_start(isc_mem_t *mctx, uint32_t workers);
/*%<
 * Creates a new network manager with 'workers' worker threads,
 * and starts it running.
 */

void
isc_nm_attach(isc_nm_t *mgr, isc_nm_t **dst);
void
isc_nm_detach(isc_nm_t **mgr0);
void
isc_nm_destroy(isc_nm_t **mgr0);
/*%<
 * Attach/detach a network manager. When all references have been
 * released, the network manager is shut down, freeing all resources.
 * Destroy is working the same way as detach, but it actively waits
 * for all other references to be gone.
 */

void
isc_nm_closedown(isc_nm_t *mgr);
/*%<
 * Close down all active connections, freeing associated resources;
 * prevent new connections from being established. This can optionally
 * be called prior to shutting down the netmgr, to stop all processing
 * before shutting down the task manager.
 */

/* Return thread ID of current thread, or ISC_NETMGR_TID_UNKNOWN */
int
isc_nm_tid(void);

void
isc_nmsocket_close(isc_nmsocket_t **sockp);
/*%<
 * isc_nmsocket_close() detaches a listening socket that was
 * created by isc_nm_listenudp(), isc_nm_listentcp(), or
 * isc_nm_listentcpdns(). Once there are no remaining child
 * sockets with active handles, the socket will be closed.
 */

void
isc_nmhandle_attach(isc_nmhandle_t *handle, isc_nmhandle_t **dest);
void
isc_nmhandle_detach(isc_nmhandle_t **handlep);
/*%<
 * Increment/decrement the reference counter in a netmgr handle,
 * but (unlike the attach/detach functions) do not change the pointer
 * value. If reference counters drop to zero, the handle can be
 * marked inactive, possibly triggering deletion of its associated
 * socket.
 *
 * (This will be used to prevent a client from being cleaned up when
 * it's passed to an isc_task event handler. The libuv code would not
 * otherwise know that the handle was in use and might free it, along
 * with the client.)
 */

void *
isc_nmhandle_getdata(isc_nmhandle_t *handle);

void *
isc_nmhandle_getextra(isc_nmhandle_t *handle);

bool
isc_nmhandle_is_stream(isc_nmhandle_t *handle);

/*
 * isc_nmhandle_t has a void * opaque field (usually - ns_client_t).
 * We reuse handle and `opaque` can also be reused between calls.
 * This function sets this field and two callbacks:
 * - doreset resets the `opaque` to initial state
 * - dofree frees everything associated with `opaque`
 */
void
isc_nmhandle_setdata(isc_nmhandle_t *handle, void *arg,
		     isc_nm_opaquecb_t doreset, isc_nm_opaquecb_t dofree);

isc_sockaddr_t
isc_nmhandle_peeraddr(isc_nmhandle_t *handle);
/*%<
 * Return the peer address for the given handle.
 */
isc_sockaddr_t
isc_nmhandle_localaddr(isc_nmhandle_t *handle);
/*%<
 * Return the local address for the given handle.
 */

isc_nm_t *
isc_nmhandle_netmgr(isc_nmhandle_t *handle);
/*%<
 * Return a pointer to the netmgr object for the given handle.
 */

isc_result_t
isc_nm_listenudp(isc_nm_t *mgr, isc_nmiface_t *iface, isc_nm_recv_cb_t cb,
		 void *cbarg, size_t extrasize, isc_nmsocket_t **sockp);
/*%<
 * Start listening for UDP packets on interface 'iface' using net manager
 * 'mgr'.
 *
 * On success, 'sockp' will be updated to contain a new listening UDP socket.
 *
 * When a packet is received on the socket, 'cb' will be called with 'cbarg'
 * as its argument.
 *
 * When handles are allocated for the socket, 'extrasize' additional bytes
 * can be allocated along with the handle for an associated object, which
 * can then be freed automatically when the handle is destroyed.
 */

isc_result_t
isc_nm_udpconnect(isc_nm_t *mgr, isc_nmiface_t *local, isc_nmiface_t *peer,
		  isc_nm_cb_t cb, void *cbarg, size_t extrahandlesize);
/*%<
 * Open a UDP socket, bind to 'local' and connect to 'peer', and
 * immediately call 'cb' with a handle so that the caller can begin
 * sending packets over UDP.
 *
 * When handles are allocated for the socket, 'extrasize' additional bytes
 * can be allocated along with the handle for an associated object, which
 * can then be freed automatically when the handle is destroyed.
 */

void
isc_nm_stoplistening(isc_nmsocket_t *sock);
/*%<
 * Stop listening on socket 'sock'.
 */

void
isc_nm_pause(isc_nm_t *mgr);
/*%<
 * Pause all processing, equivalent to taskmgr exclusive tasks.
 * It won't return until all workers have been paused.
 */

void
isc_nm_resume(isc_nm_t *mgr);
/*%<
 * Resume paused processing. It will return immediately after signalling
 * workers to resume.
 */

isc_result_t
isc_nm_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg);
/*
 * Begin (or continue) reading on the socket associated with 'handle', and
 * update its recv callback to 'cb', which will be called as soon as there
 * is data to process.
 */

isc_result_t
isc_nm_pauseread(isc_nmhandle_t *handle);
/*%<
 * Pause reading on this handle's socket, but remember the callback.
 *
 * Requires:
 * \li	'handle' is a valid netmgr handle.
 */

bool
isc_nm_cancelread(isc_nmhandle_t *handle);
/*%<
 * Cancel reading on a connected socket. Calls the read/recv callback on
 * active handles with a result code of ISC_R_CANCELED. Returns true if
 * the callback was called
 *
 * Requires:
 * \li	'sock' is a valid netmgr socket
 * \li	...for which a read/recv callback has been defined.
 */

isc_result_t
isc_nm_resumeread(isc_nmhandle_t *handle);
/*%<
 * Resume reading on the handle's socket.
 *
 * Requires:
 * \li	'handle' is a valid netmgr handle.
 * \li	...for a socket with a defined read/recv callback.
 */

isc_result_t
isc_nm_send(isc_nmhandle_t *handle, isc_region_t *region, isc_nm_cb_t cb,
	    void *cbarg);
/*%<
 * Send the data in 'region' via 'handle'. Afterward, the callback 'cb' is
 * called with the argument 'cbarg'.
 *
 * 'region' is not copied; it has to be allocated beforehand and freed
 * in 'cb'.
 */

isc_result_t
isc_nm_listentcp(isc_nm_t *mgr, isc_nmiface_t *iface,
		 isc_nm_accept_cb_t accept_cb, void *accept_cbarg,
		 size_t extrahandlesize, int backlog, isc_quota_t *quota,
		 isc_nmsocket_t **sockp);
/*%<
 * Start listening for raw messages over the TCP interface 'iface', using
 * net manager 'mgr'.
 *
 * On success, 'sockp' will be updated to contain a new listening TCP
 * socket.
 *
 * When connection is accepted on the socket, 'accept_cb' will be called with
 * 'accept_cbarg' as its argument. The callback is expected to start a read.
 *
 * When handles are allocated for the socket, 'extrasize' additional bytes
 * will be allocated along with the handle for an associated object.
 *
 * If 'quota' is not NULL, then the socket is attached to the specified
 * quota. This allows us to enforce TCP client quota limits.
 *
 * NOTE: This is currently only called inside isc_nm_listentcpdns(), which
 * creates a 'wrapper' socket that sends and receives DNS messages
 * prepended with a two-byte length field, and handles buffering.
 */

isc_result_t
isc_nm_tcpconnect(isc_nm_t *mgr, isc_nmiface_t *local, isc_nmiface_t *peer,
		  isc_nm_cb_t cb, void *cbarg, size_t extrahandlesize);
/*%<
 * Create a socket using netmgr 'mgr', bind it to the address 'local',
 * and connect it to the address 'peer'.
 *
 * When the connection is complete, call 'cb' with argument 'cbarg'.
 * Allocate 'extrahandlesize' additional bytes along with the handle to use
 * for an associated object.
 *
 * The connected socket can only be accessed via the handle passed to
 * 'cb'.
 */

isc_result_t
isc_nm_listentcpdns(isc_nm_t *mgr, isc_nmiface_t *iface, isc_nm_recv_cb_t cb,
		    void *cbarg, isc_nm_accept_cb_t accept_cb,
		    void *accept_cbarg, size_t extrahandlesize, int backlog,
		    isc_quota_t *quota, SSL_CTX *sslctx,
		    isc_nmsocket_t **sockp);
/*%<
 * Start listening for DNS messages over the TCP interface 'iface', using
 * net manager 'mgr'.
 *
 * On success, 'sockp' will be updated to contain a new listening TCPDNS
 * socket. This is a wrapper around a raw TCP socket, which sends and
 * receives DNS messages via that socket. It handles message buffering
 * and pipelining, and automatically prepends messages with a two-byte
 * length field.
 *
 * When a complete DNS message is received on the socket, 'cb' will be
 * called with 'cbarg' as its argument.
 *
 * When a new TCPDNS connection is accepted, 'accept_cb' will be called
 * with 'accept_cbarg' as its argument.
 *
 * When handles are allocated for the socket, 'extrasize' additional bytes
 * will be allocated along with the handle for an associated object
 * (typically ns_client).
 *
 * 'quota' is passed to isc_nm_listentcp() when opening the raw TCP socket.
 */

void
isc_nm_tcpdns_sequential(isc_nmhandle_t *handle);
/*%<
 * Disable pipelining on this connection. Each DNS packet will be only
 * processed after the previous completes.
 *
 * The socket must be unpaused after the query is processed.  This is done
 * the response is sent, or if we're dropping the query, it will be done
 * when a handle is fully dereferenced by calling the socket's
 * closehandle_cb callback.
 *
 * Note: This can only be run while a message is being processed; if it is
 * run before any messages are read, no messages will be read.
 *
 * Also note: once this has been set, it cannot be reversed for a given
 * connection.
 */

void
isc_nm_tcpdns_keepalive(isc_nmhandle_t *handle);
/*%<
 * Enable keepalive on this connection.
 *
 * When keepalive is active, we switch to using the keepalive timeout
 * to determine when to close a connection, rather than the idle timeout.
 */

void
isc_nm_tcp_settimeouts(isc_nm_t *mgr, uint32_t init, uint32_t idle,
		       uint32_t keepalive, uint32_t advertised);
/*%<
 * Sets the initial, idle, and keepalive timeout values to use for
 * TCP connections, and the timeout value to advertise in responses using
 * the EDNS TCP Keepalive option (which should ordinarily be the same
 * as 'keepalive'), in tenths of seconds.
 *
 * Requires:
 * \li	'mgr' is a valid netmgr.
 */

void
isc_nm_tcp_gettimeouts(isc_nm_t *mgr, uint32_t *initial, uint32_t *idle,
		       uint32_t *keepalive, uint32_t *advertised);
/*%<
 * Gets the initial, idle, keepalive, or advertised timeout values,
 * in tenths of seconds.
 *
 * Any integer pointer parameter not set to NULL will be updated to
 * contain the corresponding timeout value.
 *
 * Requires:
 * \li	'mgr' is a valid netmgr.
 */

isc_result_t
isc_nm_listentls(isc_nm_t *mgr, isc_nmiface_t *iface,
		 isc_nm_accept_cb_t accept_cb, void *accept_cbarg,
		 size_t extrahandlesize, int backlog, isc_quota_t *quota,
		 SSL_CTX *sslctx, isc_nmsocket_t **sockp);

isc_result_t
isc_nm_tlsconnect(isc_nm_t *mgr, isc_nmiface_t *local, isc_nmiface_t *peer,
		  isc_nm_cb_t cb, void *cbarg, SSL_CTX *ctx,
		  size_t extrahandlesize);

void
isc_nm_maxudp(isc_nm_t *mgr, uint32_t maxudp);
/*%<
 * Simulate a broken firewall that blocks UDP messages larger than a given
 * size.
 */

void
isc_nm_setstats(isc_nm_t *mgr, isc_stats_t *stats);
/*%<
 * Set a socket statistics counter set 'stats' for 'mgr'.
 *
 * Requires:
 *\li	'mgr' is valid and doesn't have stats already set.
 *
 *\li	stats is a valid set of statistics counters supporting the
 *	full range of socket-related stats counter numbers.
 */

isc_result_t
isc_nm_tcpdnsconnect(isc_nm_t *mgr, isc_nmiface_t *local, isc_nmiface_t *peer,
		     isc_nm_cb_t cb, void *cbarg, size_t extrahandlesize);

isc_result_t
isc_nm_tlsdnsconnect(isc_nm_t *mgr, isc_nmiface_t *local, isc_nmiface_t *peer,
		     isc_nm_cb_t cb, void *cbarg, size_t extrahandlesize);
/*%<
 * Establish a DNS client connection over either a TCP or a TLS socket.
 */

isc_result_t

isc_nm_doh_request(isc_nm_t *mgr, const char *uri, isc_region_t *message,
		   isc_nm_recv_cb_t cb, void *cbarg, SSL_CTX *ctx);
/*%<
 * Perform a DoH request on the uri provided. message is the DNS message
 * that will be POSTed to URI, cb is called with a NULL handle,
 * ctx can be NULL (it will be created).
 */
