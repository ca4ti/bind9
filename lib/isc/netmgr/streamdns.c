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

#include <limits.h>
#include <unistd.h>

#include <isc/atomic.h>
#include <isc/result.h>
#include <isc/thread.h>

#include "netmgr-int.h"

typedef struct streamdns_send_req {
	isc_nm_cb_t cb;
	void *cbarg;
	isc_nmhandle_t *dnshandle;
	isc_dnsbuffer_t data;
} streamdns_send_req_t;

static streamdns_send_req_t *
streamdns_get_send_req(isc_nmsocket_t *sock, isc_mem_t *mctx,
		       isc__nm_uvreq_t *req, isc_region_t *data);

static void
streamdns_put_send_req(isc_mem_t *mctx, streamdns_send_req_t *send_req,
		       const bool force_destroy);

static void
streamdns_readcb(isc_nmhandle_t *handle, isc_result_t result,
		 isc_region_t *region, void *cbarg);

static void
streamdns_failed_read_cb(isc_nmsocket_t *sock, const isc_result_t result);

static void
streamdns_try_close_unused(isc_nmsocket_t *sock);

static bool
streamdns_closing(isc_nmsocket_t *sock);

static bool
inactive(isc_nmsocket_t *sock);

static bool
streamdns_no_more_data(const isc_nmsocket_t *sock) {
	const isc_result_t result =
		isc_dnsstream_assembler_result(sock->streamdns.input);
	return (result == ISC_R_NOMORE || result == ISC_R_UNSET ||
		isc_dnsstream_assembler_remaininglength(
			sock->streamdns.input) == 0);
}

static bool
streamdns_startread(isc_nmsocket_t *sock) {
	if (sock->streamdns.reading) {
		return (false);
	}

	sock->streamdns.reading = true;
	isc_nm_read(sock->outerhandle, streamdns_readcb, (void *)sock);

	return (true);
}

static void
streamdns_resumeread(isc_nmsocket_t *sock, isc_nmhandle_t *transphandle) {
	if (!sock->streamdns.reading) {
		sock->streamdns.reading = true;
		isc_nm_read(transphandle, streamdns_readcb, (void *)sock);
	}
}

static void
streamdns_readmore(isc_nmsocket_t *sock, isc_nmhandle_t *transphandle) {
	if (atomic_load(&sock->ah) == 1) {
		isc__nmsocket_timer_start(sock);
	}
	streamdns_resumeread(sock, transphandle);
}

static bool
streamdns_on_dnsmessage_data_cb(isc_dnsstream_assembler_t *dnsasm,
				const isc_result_t result,
				isc_region_t *restrict region, void *cbarg,
				void *userarg) {
	isc_nmsocket_t *sock = (isc_nmsocket_t *)cbarg;
	isc_nmhandle_t *transphandle = (isc_nmhandle_t *)userarg;

	UNUSED(dnsasm);

	switch (result) {
	case ISC_R_SUCCESS: {
		/*
		 * A complete DNS message has been assembled from the incoming
		 * data. Let's process it.
		 */
		const bool client = atomic_load(&sock->client);
		const bool last_datum = isc_dnsstream_assembler_remaininglength(
						dnsasm) == region->length;
		bool stop = false;

		sock->recv_read = false;
		if (sock->recv_cb != NULL) {
			if (!client) {
				/*
				 * We must allocate a new handle object, as we
				 * need to ensure that after processing of this
				 * message has been completed and the handle
				 * gets destroyed, 'nsock->closehandle_cb'
				 * (streamdns_resume_processing()) is invoked.
				 * That is required for pipelining support.
				 */
				isc_nmhandle_t *handle = isc__nmhandle_get(
					sock, &sock->peer, &sock->iface);
				sock->recv_cb(handle, ISC_R_SUCCESS, region,
					      sock->recv_cbarg);
				isc_nmhandle_detach(&handle);
			} else {
				/*
				 * As on the client side we are supposed to stop
				 * reading/processing after receiving one
				 * message, we can use the 'sock->recv_handle'
				 * from which we would need to detach before
				 * calling the read callback anyway.
				 */
				isc_nmhandle_t *recv_handle = sock->recv_handle;
				sock->recv_handle = NULL;
				sock->recv_cb(recv_handle, ISC_R_SUCCESS,
					      region, sock->recv_cbarg);
				isc_nmhandle_detach(&recv_handle);
				/*
				 * Stop after one message if a client
				 * connection.
				 */
				stop = true;
			}

			if (streamdns_closing(sock)) {
				stop = true;
			}
		} else {
			stop = true;
		}

		isc__nmsocket_timer_stop(sock);
		if (!stop && last_datum) {
			/*
			 * We have processed all data, need to read more.
			 */
			streamdns_resumeread(sock, transphandle);
		}

		return (!stop);
	} break;
	case ISC_R_FAILURE:
		/*
		 * It seems that someone attempts to send us some binary junk
		 * over the socket, as the beginning of the next message tells
		 * us the there is an empty (0-sized) DNS message to receive.
		 * We should treat it as a hard error.
		 */
		streamdns_failed_read_cb(sock, result);
		return (false);
	case ISC_R_NOMORE:
		/*
		 * We do not have enough data to process the next message and
		 * thus we need to resume reading from the socket.
		 */
		if (sock->recv_handle != NULL) {
			streamdns_readmore(sock, transphandle);
		}
		return (false);
	default:
		UNREACHABLE();
		break;
	};

	UNREACHABLE();

	return (true);
}

static void
streamdns_handle_incoming_data(isc_nmsocket_t *sock,
			       isc_nmhandle_t *transphandle,
			       void *restrict data, size_t len) {
	isc_dnsstream_assembler_t *dnsasm = sock->streamdns.input;

	isc_dnsstream_assembler_incoming(dnsasm, transphandle, data, len);
	streamdns_try_close_unused(sock);
}

static isc_nmsocket_t *
streamdns_sock_new(isc__networker_t *worker, const isc_nmsocket_type_t type,
		   isc_sockaddr_t *addr, const bool is_server) {
	isc_nmsocket_t *sock;
	INSIST(type == isc_nm_streamdnssocket ||
	       type == isc_nm_streamdnslistener);

	sock = isc_mem_get(worker->mctx, sizeof(*sock));
	isc__nmsocket_init(sock, worker, type, addr);
	sock->result = ISC_R_UNSET;
	if (type == isc_nm_streamdnssocket) {
		uint32_t initial = 0;
		isc_nm_gettimeouts(worker->netmgr, &initial, NULL, NULL, NULL);
		sock->read_timeout = initial;
		atomic_init(&sock->client, !is_server);
		atomic_init(&sock->connecting, !is_server);
		sock->streamdns.input = isc_dnsstream_assembler_new(
			sock->worker->mctx, streamdns_on_dnsmessage_data_cb,
			sock);
	}

	return (sock);
}

static void
streamdns_call_connect_cb(isc_nmsocket_t *sock, isc_nmhandle_t *handle,
			  const isc_result_t result) {
	atomic_store(&sock->connecting, false);
	if (sock->connect_cb == NULL) {
		return;
	}
	sock->connect_cb(handle, result, sock->connect_cbarg);
	if (result != ISC_R_SUCCESS) {
		isc__nmsocket_clearcb(handle->sock);
	} else {
		atomic_store(&sock->connected, true);
	}
	streamdns_try_close_unused(sock);
}

static void
streamdns_save_alpn_status(isc_nmsocket_t *dnssock,
			   isc_nmhandle_t *transp_handle) {
	const unsigned char *alpn = NULL;
	unsigned int alpnlen = 0;

	isc__nmhandle_get_selected_alpn(transp_handle, &alpn, &alpnlen);
	if (alpn != NULL && alpnlen == ISC_TLS_DOT_PROTO_ALPN_ID_LEN &&
	    memcmp(ISC_TLS_DOT_PROTO_ALPN_ID, alpn,
		   ISC_TLS_DOT_PROTO_ALPN_ID_LEN) == 0)
	{
		dnssock->streamdns.dot_alpn_negotiated = true;
	}
}

static void
streamdns_transport_connected(isc_nmhandle_t *handle, isc_result_t result,
			      void *cbarg) {
	isc_nmsocket_t *sock = (isc_nmsocket_t *)cbarg;
	isc_nmhandle_t *streamhandle = NULL;

	REQUIRE(VALID_NMSOCK(sock));

	sock->tid = isc_tid();
	if (result == ISC_R_EOF) {
		/*
		 * The transport layer (probably TLS) has returned EOF during
		 * connection establishment. That means that connection has
		 * been "cancelled" (for compatibility with old transport
		 * behaviour).
		 */
		result = ISC_R_CANCELED;
		goto error;
	} else if (result == ISC_R_TLSERROR) {
		/*
		 * In some of the cases when the old code would return
		 * ISC_R_CANCELLED, the new code could return generic
		 * ISC_R_TLSERROR code. However, the old code does not expect
		 * that.
		 */
		result = ISC_R_CANCELED;
		goto error;
	} else if (result != ISC_R_SUCCESS) {
		goto error;
	}

	INSIST(VALID_NMHANDLE(handle));

	sock->iface = isc_nmhandle_localaddr(handle);
	sock->peer = isc_nmhandle_peeraddr(handle);
	if (isc__nmsocket_closing(handle->sock)) {
		result = ISC_R_SHUTTINGDOWN;
		goto error;
	}

	isc_nmhandle_attach(handle, &sock->outerhandle);
	atomic_store(&sock->active, true);

	handle->sock->streamdns.sock = sock;

	streamdns_save_alpn_status(sock, handle);
	isc__nmhandle_set_manual_timer(sock->outerhandle, true);
	streamhandle = isc__nmhandle_get(sock, &sock->peer, &sock->iface);
	(void)isc_nmhandle_set_tcp_nodelay(sock->outerhandle, true);
	streamdns_call_connect_cb(sock, streamhandle, result);
	isc_nmhandle_detach(&streamhandle);

	return;
error:
	streamhandle = isc__nmhandle_get(sock, NULL, NULL);
	atomic_store(&sock->closed, true);
	streamdns_call_connect_cb(sock, streamhandle, result);
	isc_nmhandle_detach(&streamhandle);
	isc__nmsocket_detach(&sock);
}

void
isc_nm_streamdnsconnect(isc_nm_t *mgr, isc_sockaddr_t *local,
			isc_sockaddr_t *peer, isc_nm_cb_t cb, void *cbarg,
			unsigned int timeout, isc_tlsctx_t *ctx,
			isc_tlsctx_client_session_cache_t *client_sess_cache) {
	isc_nmsocket_t *nsock = NULL;
	isc__networker_t *worker = &mgr->workers[isc_tid()];

	REQUIRE(VALID_NM(mgr));

	if (isc__nm_closing(worker)) {
		cb(NULL, ISC_R_SHUTTINGDOWN, cbarg);
		return;
	}

	nsock = streamdns_sock_new(worker, isc_nm_streamdnssocket, local,
				   false);
	nsock->connect_cb = cb;
	nsock->connect_cbarg = cbarg;
	nsock->connect_timeout = timeout;

	if (ctx == NULL) {
		INSIST(client_sess_cache == NULL);
		isc_nm_tcpconnect(mgr, local, peer,
				  streamdns_transport_connected, nsock,
				  nsock->connect_timeout);
	} else {
		isc_nm_tlsconnect(mgr, local, peer,
				  streamdns_transport_connected, nsock, ctx,
				  client_sess_cache, nsock->connect_timeout);
	}
}

static bool
streamdns_waiting_for_msg(isc_nmsocket_t *sock) {
	return (sock->recv_read);
}

bool
isc__nmsocket_streamdns_timer_running(isc_nmsocket_t *sock) {
	isc_nmsocket_t *transp_sock;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_streamdnssocket);

	if (sock->outerhandle == NULL) {
		return (false);
	}

	INSIST(VALID_NMHANDLE(sock->outerhandle));
	transp_sock = sock->outerhandle->sock;
	INSIST(VALID_NMSOCK(transp_sock));

	return (isc__nmsocket_timer_running(transp_sock));
}

void
isc__nmsocket_streamdns_timer_stop(isc_nmsocket_t *sock) {
	isc_nmsocket_t *transp_sock;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_streamdnssocket);

	if (sock->outerhandle == NULL) {
		return;
	}

	INSIST(VALID_NMHANDLE(sock->outerhandle));
	transp_sock = sock->outerhandle->sock;
	INSIST(VALID_NMSOCK(transp_sock));

	isc__nmsocket_timer_stop(transp_sock);
}

void
isc__nmsocket_streamdns_timer_restart(isc_nmsocket_t *sock) {
	isc_nmsocket_t *transp_sock;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_streamdnssocket);

	if (sock->outerhandle == NULL) {
		return;
	}

	INSIST(VALID_NMHANDLE(sock->outerhandle));
	transp_sock = sock->outerhandle->sock;
	INSIST(VALID_NMSOCK(transp_sock));

	isc__nmsocket_timer_restart(transp_sock);
}

static void
streamdns_failed_read_cb(isc_nmsocket_t *sock, const isc_result_t result) {
	bool destroy = true;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(result != ISC_R_SUCCESS);

	if (sock->recv_cb != NULL && sock->recv_handle != NULL &&
	    (streamdns_waiting_for_msg(sock) || result == ISC_R_TIMEDOUT))
	{
		isc_nm_recv_cb_t recv_cb;
		void *recv_cbarg;
		isc_region_t empty_region = { 0, 0 };
		INSIST(VALID_NMHANDLE(sock->recv_handle));
		recv_cb = sock->recv_cb;
		recv_cbarg = sock->recv_cbarg;
		if (result != ISC_R_TIMEDOUT) {
			sock->recv_read = false;
			isc_dnsstream_assembler_clear(sock->streamdns.input);
			isc__nmsocket_clearcb(sock);
		}
		recv_cb(sock->recv_handle, result, &empty_region, recv_cbarg);
		if (result == ISC_R_TIMEDOUT &&
		    (sock->outerhandle == NULL ||
		     isc__nmsocket_streamdns_timer_running(sock)))
		{
			destroy = false;
		}
	}

	if (destroy) {
		isc__nmsocket_prep_destroy(sock);
	}
}

void
isc__nm_streamdns_failed_read_cb(isc_nmsocket_t *sock, isc_result_t result) {
	REQUIRE(result != ISC_R_SUCCESS);
	REQUIRE(sock->type == isc_nm_streamdnssocket);
	sock->streamdns.reading = false;
	streamdns_failed_read_cb(sock, result);
}

static void
streamdns_readcb(isc_nmhandle_t *handle, isc_result_t result,
		 isc_region_t *region, void *cbarg) {
	isc_nmsocket_t *sock = (isc_nmsocket_t *)cbarg;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());

	if (result != ISC_R_SUCCESS) {
		streamdns_failed_read_cb(sock, result);
		return;
	} else if (streamdns_closing(sock)) {
		streamdns_failed_read_cb(sock, ISC_R_CANCELED);
		return;
	}

	sock->streamdns.reading = false;
	streamdns_handle_incoming_data(sock, handle, region->base,
				       region->length);
}

static void
streamdns_try_close_unused(isc_nmsocket_t *sock) {
	if (sock->recv_handle == NULL && sock->streamdns.nsending == 0) {
		/*
		 * The socket is unused after calling the callback. Let's close
		 * the underlying connection.
		 */
		isc__nmsocket_prep_destroy(sock);
	}
}

static streamdns_send_req_t *
streamdns_get_send_req(isc_nmsocket_t *sock, isc_mem_t *mctx,
		       isc__nm_uvreq_t *req, isc_region_t *data) {
	streamdns_send_req_t *send_req;

	if (sock->streamdns.send_req != NULL) {
		send_req = (streamdns_send_req_t *)sock->streamdns.send_req;
		sock->streamdns.send_req = NULL;
	} else {
		send_req = isc_mem_get(mctx, sizeof(*send_req));
		*send_req = (streamdns_send_req_t){ 0 };
		isc_dnsbuffer_init(&send_req->data, mctx);
	}

	send_req->cb = req->cb.send;
	send_req->cbarg = req->cbarg;
	isc_nmhandle_attach(req->handle, &send_req->dnshandle);
	isc_dnsbuffer_putmem_uint16be(&send_req->data,
				      (uint16_t)req->uvbuf.len);
	isc_dnsbuffer_putmem(&send_req->data, req->uvbuf.base, req->uvbuf.len);
	isc_dnsbuffer_remainingregion(&send_req->data, data);

	sock->streamdns.nsending++;

	return (send_req);
}

static void
streamdns_put_send_req(isc_mem_t *mctx, streamdns_send_req_t *send_req,
		       const bool force_destroy) {
	if (!force_destroy) {
		isc_nmsocket_t *sock = send_req->dnshandle->sock;
		send_req->dnshandle->sock->streamdns.nsending--;
		isc_nmhandle_detach(&send_req->dnshandle);
		if (sock->streamdns.send_req == NULL) {
			isc_dnsbuffer_clear(&send_req->data);
			sock->streamdns.send_req = send_req;
			/*
			 * An object has been recycled,
			 * if not - we are going to destroy it.
			 */
			return;
		}
	}

	isc_dnsbuffer_uninit(&send_req->data);
	isc_mem_put(mctx, send_req, sizeof(*send_req));
}

static void
streamdns_writecb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	streamdns_send_req_t *send_req = (streamdns_send_req_t *)cbarg;
	isc_mem_t *mctx;
	isc_nm_cb_t cb;
	void *send_cbarg;
	isc_nmhandle_t *dnshandle = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMHANDLE(send_req->dnshandle));
	REQUIRE(VALID_NMSOCK(send_req->dnshandle->sock));
	REQUIRE(send_req->dnshandle->sock->tid == isc_tid());

	mctx = send_req->dnshandle->sock->worker->mctx;
	cb = send_req->cb;
	send_cbarg = send_req->cbarg;

	isc_nmhandle_attach(send_req->dnshandle, &dnshandle);
	/* try to keep the send request object for reuse */
	streamdns_put_send_req(mctx, send_req, false);
	cb(dnshandle, result, send_cbarg);
	streamdns_try_close_unused(dnshandle->sock);
	isc_nmhandle_detach(&dnshandle);
}

static bool
inactive(isc_nmsocket_t *sock) {
	return (!isc__nmsocket_active(sock) || streamdns_closing(sock) ||
		isc__nm_closing(sock->worker));
}

static bool
streamdns_closing(isc_nmsocket_t *sock) {
	return (isc__nmsocket_closing(sock) || sock->outerhandle == NULL ||
		(sock->outerhandle != NULL &&
		 isc__nmsocket_closing(sock->outerhandle->sock)));
}

static void
streamdns_resume_processing(void *arg) {
	isc_nmsocket_t *sock = (isc_nmsocket_t *)arg;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(!atomic_load(&sock->client));

	if (streamdns_closing(sock)) {
		return;
	}

	streamdns_handle_incoming_data(sock, sock->outerhandle, NULL, 0);
}

static isc_result_t
streamdns_accept_cb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	isc_nmsocket_t *listensock = (isc_nmsocket_t *)cbarg;
	isc_nmsocket_t *nsock;
	isc_sockaddr_t iface;
	int tid;
	uint32_t initial = 0;

	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	INSIST(VALID_NMHANDLE(handle));
	INSIST(VALID_NMSOCK(handle->sock));
	INSIST(VALID_NMSOCK(listensock));
	INSIST(listensock->type == isc_nm_streamdnslistener);

	if (isc__nm_closing(listensock->worker) ||
	    isc__nmsocket_closing(listensock) ||
	    atomic_load(&listensock->closed))
	{
		return (ISC_R_SHUTTINGDOWN);
	}

	tid = isc_tid();
	iface = isc_nmhandle_localaddr(handle);
	nsock = streamdns_sock_new(handle->sock->worker, isc_nm_streamdnssocket,
				   &iface, true);
	nsock->recv_cb = listensock->recv_cb;
	nsock->recv_cbarg = listensock->recv_cbarg;

	nsock->peer = isc_nmhandle_peeraddr(handle);
	nsock->tid = tid;
	isc_nm_gettimeouts(handle->sock->worker->netmgr, &initial, NULL, NULL,
			   NULL);
	nsock->read_timeout = initial;
	atomic_init(&nsock->accepting, true);
	atomic_store(&nsock->active, true);

	isc__nmsocket_attach(listensock, &nsock->listener);
	isc_nmhandle_attach(handle, &nsock->outerhandle);
	handle->sock->streamdns.sock = nsock;

	streamdns_save_alpn_status(nsock, handle);

	nsock->recv_handle = isc__nmhandle_get(nsock, NULL, &iface);
	INSIST(listensock->accept_cb != NULL);
	result = listensock->accept_cb(nsock->recv_handle, result,
				       listensock->accept_cbarg);
	if (result != ISC_R_SUCCESS) {
		isc_nmhandle_detach(&nsock->recv_handle);
		isc__nmsocket_detach(&nsock->listener);
		isc_nmhandle_detach(&nsock->outerhandle);
		atomic_store(&nsock->closed, true);
		goto exit;
	}

	nsock->closehandle_cb = streamdns_resume_processing;
	isc__nmhandle_set_manual_timer(nsock->outerhandle, true);
	isc_nm_gettimeouts(nsock->worker->netmgr, &initial, NULL, NULL, NULL);
	/* settimeout restarts the timer */
	isc_nmhandle_settimeout(nsock->outerhandle, initial);
	(void)isc_nmhandle_set_tcp_nodelay(nsock->outerhandle, true);
	RUNTIME_CHECK(streamdns_startread(nsock) == true);

exit:
	atomic_store(&nsock->accepting, false);

	return (result);
}

isc_result_t
isc_nm_listenstreamdns(isc_nm_t *mgr, uint32_t workers, isc_sockaddr_t *iface,
		       isc_nm_recv_cb_t recv_cb, void *recv_cbarg,
		       isc_nm_accept_cb_t accept_cb, void *accept_cbarg,
		       int backlog, isc_quota_t *quota, isc_tlsctx_t *sslctx,
		       isc_nmsocket_t **sockp) {
	isc_result_t result;
	isc_nmsocket_t *listener = NULL;
	isc__networker_t *worker = &mgr->workers[isc_tid()];

	REQUIRE(VALID_NM(mgr));
	REQUIRE(isc_tid() == 0);

	if (isc__nm_closing(worker)) {
		return (ISC_R_SHUTTINGDOWN);
	}

	listener = streamdns_sock_new(worker, isc_nm_streamdnslistener, iface,
				      true);
	listener->accept_cb = accept_cb;
	listener->accept_cbarg = accept_cbarg;
	listener->recv_cb = recv_cb;
	listener->recv_cbarg = recv_cbarg;

	if (sslctx == NULL) {
		result = isc_nm_listentcp(mgr, workers, iface,
					  streamdns_accept_cb, listener,
					  backlog, quota, &listener->outer);
	} else {
		result = isc_nm_listentls(
			mgr, workers, iface, streamdns_accept_cb, listener,
			backlog, quota, sslctx, &listener->outer);
	}
	if (result != ISC_R_SUCCESS) {
		atomic_store(&listener->closed, true);
		isc__nmsocket_detach(&listener);
		return (result);
	}

	listener->result = result;
	atomic_store(&listener->active, true);
	atomic_store(&listener->listening, true);
	INSIST(listener->outer->streamdns.listener == NULL);
	isc__nmsocket_attach(listener, &listener->outer->streamdns.listener);

	*sockp = listener;

	return (result);
}

void
isc__nm_streamdns_cleanup_data(isc_nmsocket_t *sock) {
	switch (sock->type) {
	case isc_nm_streamdnssocket:
		isc_dnsstream_assembler_free(&sock->streamdns.input);
		INSIST(sock->streamdns.nsending == 0);
		if (sock->streamdns.send_req != NULL) {
			isc_mem_t *mctx = sock->worker->mctx;
			streamdns_put_send_req(mctx,
					       (streamdns_send_req_t *)
						       sock->streamdns.send_req,
					       true);
		}
		break;
	case isc_nm_streamdnslistener:
		if (sock->outer) {
			isc__nmsocket_detach(&sock->outer);
		}
		break;
	case isc_nm_tlslistener:
	case isc_nm_tcplistener:
		if (sock->streamdns.listener != NULL) {
			isc__nmsocket_detach(&sock->streamdns.listener);
		}
		break;
	case isc_nm_tlssocket:
	case isc_nm_tcpsocket:
		if (sock->streamdns.sock != NULL) {
			isc__nmsocket_detach(&sock->streamdns.sock);
		}
		break;
	default:
		return;
	}
}

void
isc__nm_async_streamdnsread(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_streamdnsread_t *ievent =
		(isc__netievent_streamdnsread_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	REQUIRE(sock->tid == isc_tid());
	UNUSED(worker);

	if (inactive(sock)) {
		streamdns_failed_read_cb(sock, ISC_R_CANCELED);
		return;
	}

	INSIST(VALID_NMHANDLE(sock->outerhandle));
	if (streamdns_startread(sock)) {
		isc__nmsocket_timer_start(sock);
		return;
	}

	if (streamdns_no_more_data(sock)) {
		streamdns_readmore(sock, sock->outerhandle);
	} else {
		/*
		 * Try to process unprocessed data and resume reading.
		 */
		streamdns_handle_incoming_data(sock, sock->outerhandle, NULL,
					       0);
	}
}

void
isc__nm_streamdns_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb,
		       void *cbarg) {
	isc__netievent_streamdnsread_t *ievent = NULL;
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	sock = handle->sock;
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_streamdnssocket);
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(sock->recv_handle == NULL);

	sock->recv_cb = cb;
	sock->recv_cbarg = cbarg;
	sock->recv_read = true;
	isc_nmhandle_attach(handle, &sock->recv_handle);

	ievent = isc__nm_get_netievent_streamdnsread(sock->worker, sock);
	isc__nm_enqueue_ievent(sock->worker, (isc__netievent_t *)ievent);
}

void
isc__nm_async_streamdnssend(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_streamdnssend_t *ievent =
		(isc__netievent_streamdnssend_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	isc__nm_uvreq_t *req = ievent->req;
	streamdns_send_req_t *send_req;
	isc_mem_t *mctx;
	isc_region_t data = { 0 };

	REQUIRE(VALID_UVREQ(req));
	REQUIRE(sock->tid == isc_tid());

	UNUSED(worker);

	ievent->req = NULL;

	if (inactive(sock)) {
		req->cb.send(req->handle, ISC_R_CANCELED, req->cbarg);
		goto done;
	}

	mctx = sock->worker->mctx;

	send_req = streamdns_get_send_req(sock, mctx, req, &data);
	isc_nm_send(sock->outerhandle, &data, streamdns_writecb,
		    (void *)send_req);
done:
	isc__nm_uvreq_put(&req, sock);
	return;
}

void
isc__nm_streamdns_send(isc_nmhandle_t *handle, const isc_region_t *region,
		       isc_nm_cb_t cb, void *cbarg) {
	isc__nm_uvreq_t *uvreq = NULL;
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(region->length <= UINT16_MAX);

	sock = handle->sock;

	REQUIRE(sock->type == isc_nm_streamdnssocket);

	uvreq = isc__nm_uvreq_get(sock->worker, sock);
	isc_nmhandle_attach(handle, &uvreq->handle);
	uvreq->cb.send = cb;
	uvreq->cbarg = cbarg;
	uvreq->uvbuf.base = (char *)region->base;
	uvreq->uvbuf.len = region->length;

	if (sock->tid == isc_tid()) {
		isc__netievent_streamdnssend_t event = { .sock = sock,
							 .req = uvreq };
		isc__nm_async_streamdnssend(sock->worker,
					    (isc__netievent_t *)&event);
	} else {
		isc__netievent_streamdnssend_t *ievent =
			isc__nm_get_netievent_streamdnssend(sock->worker, sock,
							    uvreq);
		isc__nm_enqueue_ievent(sock->worker,
				       (isc__netievent_t *)ievent);
	}
}

static void
streamdns_close_direct(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());

	if (sock->outerhandle != NULL) {
		sock->streamdns.reading = false;
		isc__nmsocket_timer_stop(sock);
		isc_nm_read_stop(sock->outerhandle);
		isc_nmhandle_close(sock->outerhandle);
		isc_nmhandle_detach(&sock->outerhandle);
	}

	if (sock->listener != NULL) {
		isc__nmsocket_detach(&sock->listener);
	}

	if (sock->recv_handle != NULL) {
		isc_nmhandle_detach(&sock->recv_handle);
	}

	/* Further cleanup performed in isc__nm_streamdns_cleanup_data() */
	isc_dnsstream_assembler_clear(sock->streamdns.input);
	atomic_store(&sock->closed, true);
	atomic_store(&sock->active, false);
}

void
isc__nm_async_streamdnsclose(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_streamdnsclose_t *ievent =
		(isc__netievent_streamdnsclose_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	UNUSED(worker);

	streamdns_close_direct(sock);
}

void
isc__nm_streamdns_close(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_streamdnssocket);

	if (!atomic_compare_exchange_strong(&sock->closing, &(bool){ false },
					    true)) {
		return;
	}

	if (sock->tid == isc_tid()) {
		streamdns_close_direct(sock);
	} else {
		isc__netievent_streamdnsclose_t *ievent =
			isc__nm_get_netievent_streamdnsclose(sock->worker,
							     sock);
		isc__nm_enqueue_ievent(sock->worker,
				       (isc__netievent_t *)ievent);
	}
}

void
isc__nm_async_streamdnsstop(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_streamdnsstop_t *ievent =
		(isc__netievent_streamdnsstop_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	UNUSED(worker);

	atomic_store(&sock->listening, false);
	atomic_store(&sock->closed, true);

	if (sock->outer != NULL) {
		isc_nm_stoplistening(sock->outer);
		isc__nmsocket_detach(&sock->outer);
	}
}

void
isc__nm_streamdns_stoplistening(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_streamdnslistener);

	if (!atomic_compare_exchange_strong(&sock->closing, &(bool){ false },
					    true)) {
		UNREACHABLE();
	}

	if (isc_tid() == sock->tid) {
		isc__netievent_streamdnsstop_t ievent = { .sock = sock };
		isc__nm_async_streamdnsstop(sock->worker,
					    (isc__netievent_t *)&ievent);
	} else {
		isc__netievent_streamdnsstop_t *ievent =
			isc__nm_get_netievent_streamdnsstop(sock->worker, sock);
		isc__nm_enqueue_ievent(sock->worker,
				       (isc__netievent_t *)ievent);
	}
}

void
isc__nm_streamdns_cancelread(isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->type == isc_nm_streamdnssocket);

	sock = handle->sock;

	isc__netievent_streamdnscancel_t *ievent =
		isc__nm_get_netievent_streamdnscancel(sock->worker,
						      handle->sock, handle);
	isc__nm_enqueue_ievent(sock->worker, (isc__netievent_t *)ievent);
}

void
isc__nm_async_streamdnscancel(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_streamdnscancel_t *ievent =
		(isc__netievent_streamdnscancel_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	UNUSED(worker);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());

	streamdns_failed_read_cb(sock, ISC_R_EOF);
}

void
isc__nmhandle_streamdns_cleartimeout(isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->type == isc_nm_streamdnssocket);

	sock = handle->sock;
	if (sock->outerhandle != NULL) {
		INSIST(VALID_NMHANDLE(sock->outerhandle));
		isc_nmhandle_cleartimeout(sock->outerhandle);
	}
}

void
isc__nmhandle_streamdns_settimeout(isc_nmhandle_t *handle, uint32_t timeout) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->type == isc_nm_streamdnssocket);

	sock = handle->sock;
	if (sock->outerhandle != NULL) {
		INSIST(VALID_NMHANDLE(sock->outerhandle));
		isc_nmhandle_settimeout(sock->outerhandle, timeout);
	}
}

void
isc__nmhandle_streamdns_keepalive(isc_nmhandle_t *handle, bool value) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->type == isc_nm_streamdnssocket);

	sock = handle->sock;
	if (sock->outerhandle != NULL) {
		INSIST(VALID_NMHANDLE(sock->outerhandle));
		isc_nmhandle_keepalive(sock->outerhandle, value);
	}
}

void
isc__nmhandle_streamdns_setwritetimeout(isc_nmhandle_t *handle,
					uint32_t timeout) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->type == isc_nm_streamdnssocket);

	sock = handle->sock;
	if (sock->outerhandle != NULL) {
		INSIST(VALID_NMHANDLE(sock->outerhandle));
		isc_nmhandle_setwritetimeout(sock->outerhandle, timeout);
	}
}

bool
isc__nm_streamdns_has_encryption(const isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->type == isc_nm_streamdnssocket);

	sock = handle->sock;
	if (sock->outerhandle != NULL) {
		INSIST(VALID_NMHANDLE(sock->outerhandle));
		return (isc_nm_has_encryption(sock->outerhandle));
	}

	return (false);
}

const char *
isc__nm_streamdns_verify_tls_peer_result_string(const isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->type == isc_nm_streamdnssocket);

	sock = handle->sock;
	if (sock->outerhandle != NULL) {
		INSIST(VALID_NMHANDLE(sock->outerhandle));
		return (isc_nm_verify_tls_peer_result_string(
			sock->outerhandle));
	}

	return (false);
}

void
isc__nm_streamdns_set_tlsctx(isc_nmsocket_t *listener, isc_tlsctx_t *tlsctx) {
	REQUIRE(VALID_NMSOCK(listener));
	REQUIRE(listener->type == isc_nm_streamdnslistener);

	if (listener->outer != NULL) {
		INSIST(VALID_NMSOCK(listener->outer));
		isc_nmsocket_set_tlsctx(listener->outer, tlsctx);
	}
}

bool
isc__nm_streamdns_xfr_allowed(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_streamdnssocket);

	if (sock->outerhandle == NULL) {
		return (false);
	} else if (!isc_nm_has_encryption(sock->outerhandle)) {
		return (true);
	}

	return (sock->streamdns.dot_alpn_negotiated);
}

void
isc__nmsocket_streamdns_reset(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_streamdnssocket);

	if (sock->outerhandle == NULL) {
		return;
	}

	INSIST(VALID_NMHANDLE(sock->outerhandle));
	isc__nmsocket_reset(sock->outerhandle->sock);
}
