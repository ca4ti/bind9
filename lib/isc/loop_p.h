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

#include <inttypes.h>

#include <isc/barrier.h>
#include <isc/lang.h>
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/thread.h>
#include <isc/types.h>

/*
 * Per-thread loop
 */
#define LOOP_MAGIC    ISC_MAGIC('L', 'O', 'O', 'P')
#define VALID_LOOP(t) ISC_MAGIC_VALID(t, LOOP_MAGIC)

struct isc_signal {
	uv_signal_t signal;
	isc_mem_t *mctx;
	isc_signal_cb cb;
	void *cbarg;
	int signum;
};

struct isc_job {
	isc_mem_t *mctx;
	uv_idle_t idle;
	isc_job_cb cb;
	void *cbarg;
	LINK(isc_job_t) link;
};

struct isc_work {
	uv_work_t work;
	isc_loop_t *loop;
	isc_work_cb work_cb;
	isc_after_work_cb after_work_cb;
	isc_job_t *cancel_job;
	void *cbarg;
};

struct isc_loop {
	int magic;
	isc_refcount_t references;
	isc_thread_t thread;

	isc_loopmgr_t *loopmgr;

	uv_loop_t loop;
	uint32_t tid;

	isc_mem_t *mctx;

	/* states */
	bool paused;
	bool finished;
	bool shuttingdown;

	/* Pause */
	uv_async_t pause;

	/* Shutdown */
	uv_async_t shutdown;
	ISC_LIST(isc_job_t) setup_jobs;
	ISC_LIST(isc_job_t) teardown_jobs;
};

/*
 * Loop Manager
 */
#define LOOPMGR_MAGIC	 ISC_MAGIC('L', 'o', 'o', 'M')
#define VALID_LOOPMGR(t) ISC_MAGIC_VALID(t, LOOPMGR_MAGIC)

struct isc_loopmgr {
	int magic;
	isc_refcount_t references;
	isc_mem_t *mctx;

	uint_fast32_t nloops;

	atomic_bool shuttingdown;
	atomic_bool running;
	atomic_bool paused;

	/* signal handling */
	isc_signal_t *sigint;
	isc_signal_t *sigterm;

	/* pause/resume */
	isc_barrier_t pausing;
	isc_barrier_t resuming;

	/* per-thread objects */
	isc_loop_t *loops;
};
