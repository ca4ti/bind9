/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include <isc/atomic.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/print.h>
#include <isc/strerr.h>
#include <isc/string.h>
#include <isc/util.h>

#include "mutex_p.h"

static pthread_mutexattr_t attr;
static isc_once_t init_once = ISC_ONCE_INIT;
static isc_once_t shut_once = ISC_ONCE_INIT;

static atomic_uint_fast32_t mutex_active = ATOMIC_VAR_INIT(0);

static void
mutex_initialize(void) {
	RUNTIME_CHECK(pthread_mutexattr_init(&attr) == 0);
#if defined(ISC_MUTEX_DEBUG) && defined(PTHREAD_MUTEX_ERRORCHECK)
	RUNTIME_CHECK(pthread_mutexattr_settype(&attr,
						PTHREAD_MUTEX_ERRORCHECK) == 0);
#elif defined(HAVE_PTHREAD_MUTEX_ADAPTIVE_NP)
	RUNTIME_CHECK(pthread_mutexattr_settype(
			      &attr, PTHREAD_MUTEX_ADAPTIVE_NP) == 0);
#endif /* HAVE_PTHREAD_MUTEX_ADAPTIVE_NP */
}

void
isc__mutex_initialize(void) {
	RUNTIME_CHECK(isc_once_do(&init_once, mutex_initialize) ==
		      ISC_R_SUCCESS);
}

static void
mutex_shutdown(void) {
	REQUIRE(atomic_load_acquire(&mutex_active) == 0);
}

void
isc__mutex_shutdown(void) {
	RUNTIME_CHECK(isc_once_do(&shut_once, mutex_shutdown) == ISC_R_SUCCESS);
}

#if ISC_MUTEX_DEBUG

void
isc_mutex_init_debug(isc_mutex_t *mp, const char *func, const char *file,
		     unsigned int line) {
	int err;

	err = pthread_mutex_init(mp, &attr);
	if (err != 0) {
		char strbuf[ISC_STRERRORSIZE];
		strerror_r(err, strbuf, sizeof(strbuf));
		isc_error_fatal(file, line, "pthread_mutex_init failed: %s",
				strbuf);
	}

	fprintf(stderr, "mutex:init %p func %s file %s line %u\n", mp, func,
		file, line);

	atomic_fetch_add_relaxed(&mutex_active, 1);
}

void
isc_mutex_destroy_debug(isc_mutex_t *mp, const char *func, const char *file,
			unsigned int line) {
	atomic_fetch_sub_release(&mutex_active, 1);

	fprintf(stderr, "mutex:destroy %p func %s file %s line %u\n", mp, func,
		file, line);

	pthread_mutex_destroy(mp);
}

#elif ISC_MUTEX_PROFILE

/*@{*/
/*% Operations on timevals; adapted from FreeBSD's sys/time.h */
#define timevalclear(tvp) ((tvp)->tv_sec = (tvp)->tv_usec = 0)
#define timevaladd(vvp, uvp)                       \
	do {                                       \
		(vvp)->tv_sec += (uvp)->tv_sec;    \
		(vvp)->tv_usec += (uvp)->tv_usec;  \
		if ((vvp)->tv_usec >= 1000000) {   \
			(vvp)->tv_sec++;           \
			(vvp)->tv_usec -= 1000000; \
		}                                  \
	} while (0)
#define timevalsub(vvp, uvp)                       \
	do {                                       \
		(vvp)->tv_sec -= (uvp)->tv_sec;    \
		(vvp)->tv_usec -= (uvp)->tv_usec;  \
		if ((vvp)->tv_usec < 0) {          \
			(vvp)->tv_sec--;           \
			(vvp)->tv_usec += 1000000; \
		}                                  \
	} while (0)

/*@}*/

#define ISC_MUTEX_MAX_LOCKERS 32

typedef struct {
	const char *file;
	int line;
	unsigned count;
	struct timeval locked_total;
	struct timeval wait_total;
} isc_mutexlocker_t;

struct isc_mutexstats {
	const char *file; /*%< File mutex was created in. */
	int line;	  /*%< Line mutex was created on. */
	unsigned count;
	struct timeval lock_t;
	struct timeval locked_total;
	struct timeval wait_total;
	isc_mutexlocker_t *cur_locker;
	isc_mutexlocker_t lockers[ISC_MUTEX_MAX_LOCKERS];
};

#ifndef ISC_MUTEX_PROFTABLESIZE
#define ISC_MUTEX_PROFTABLESIZE (1024 * 1024)
#endif /* ifndef ISC_MUTEX_PROFTABLESIZE */
static isc_mutexstats_t stats[ISC_MUTEX_PROFTABLESIZE];
static int stats_next = 0;
static bool stats_init = false;
static pthread_mutex_t statslock = PTHREAD_MUTEX_INITIALIZER;

void
isc_mutex_init_profile(isc_mutex_t *mp, const char *file, int line) {
	int i, err;

	err = pthread_mutex_init(&mp->mutex, &attr);
	if (err != 0) {
		strerror_r(err, strbuf, sizeof(strbuf));
		isc_error_fatal(file, line, "pthread_mutex_init failed: %s",
				strbuf);
	}

	RUNTIME_CHECK(pthread_mutex_lock(&statslock) == 0);

	if (!stats_init) {
		stats_init = true;
	}

	/*
	 * If all statistics entries have been used, give up and trigger an
	 * assertion failure.  There would be no other way to deal with this
	 * because we'd like to keep record of all locks for the purpose of
	 * debugging and the number of necessary locks is unpredictable.
	 * If this failure is triggered while debugging, named should be
	 * rebuilt with an increased ISC_MUTEX_PROFTABLESIZE.
	 */
	RUNTIME_CHECK(stats_next < ISC_MUTEX_PROFTABLESIZE);
	mp->stats = &stats[stats_next++];

	RUNTIME_CHECK(pthread_mutex_unlock(&statslock) == 0);

	mp->stats->file = file;
	mp->stats->line = line;
	mp->stats->count = 0;
	timevalclear(&mp->stats->locked_total);
	timevalclear(&mp->stats->wait_total);
	for (i = 0; i < ISC_MUTEX_MAX_LOCKERS; i++) {
		mp->stats->lockers[i].file = NULL;
		mp->stats->lockers[i].line = 0;
		mp->stats->lockers[i].count = 0;
		timevalclear(&mp->stats->lockers[i].locked_total);
		timevalclear(&mp->stats->lockers[i].wait_total);
	}
}

isc_result_t
isc_mutex_lock_profile(isc_mutex_t *mp, const char *file, int line) {
	struct timeval prelock_t;
	struct timeval postlock_t;
	isc_mutexlocker_t *locker = NULL;
	int i;

	gettimeofday(&prelock_t, NULL);

	if (pthread_mutex_lock(&mp->mutex) != 0) {
		return (ISC_R_UNEXPECTED);
	}

	gettimeofday(&postlock_t, NULL);
	mp->stats->lock_t = postlock_t;

	timevalsub(&postlock_t, &prelock_t);

	mp->stats->count++;
	timevaladd(&mp->stats->wait_total, &postlock_t);

	for (i = 0; i < ISC_MUTEX_MAX_LOCKERS; i++) {
		if (mp->stats->lockers[i].file == NULL) {
			locker = &mp->stats->lockers[i];
			locker->file = file;
			locker->line = line;
			break;
		} else if (mp->stats->lockers[i].file == file &&
			   mp->stats->lockers[i].line == line)
		{
			locker = &mp->stats->lockers[i];
			break;
		}
	}

	if (locker != NULL) {
		locker->count++;
		timevaladd(&locker->wait_total, &postlock_t);
	}

	mp->stats->cur_locker = locker;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_mutex_unlock_profile(isc_mutex_t *mp, const char *file, int line) {
	struct timeval unlock_t;

	UNUSED(file);
	UNUSED(line);

	if (mp->stats->cur_locker != NULL) {
		gettimeofday(&unlock_t, NULL);
		timevalsub(&unlock_t, &mp->stats->lock_t);
		timevaladd(&mp->stats->locked_total, &unlock_t);
		timevaladd(&mp->stats->cur_locker->locked_total, &unlock_t);
		mp->stats->cur_locker = NULL;
	}

	return ((pthread_mutex_unlock((&mp->mutex)) == 0) ? ISC_R_SUCCESS
							  : ISC_R_UNEXPECTED);
}

void
isc_mutex_statsprofile(FILE *fp) {
	isc_mutexlocker_t *locker;
	int i, j;

	fprintf(fp, "Mutex stats (in us)\n");
	for (i = 0; i < stats_next; i++) {
		fprintf(fp, "%-12s %4d: %10u  %lu.%06lu %lu.%06lu %5d\n",
			stats[i].file, stats[i].line, stats[i].count,
			stats[i].locked_total.tv_sec,
			stats[i].locked_total.tv_usec,
			stats[i].wait_total.tv_sec, stats[i].wait_total.tv_usec,
			i);
		for (j = 0; j < ISC_MUTEX_MAX_LOCKERS; j++) {
			locker = &stats[i].lockers[j];
			if (locker->file == NULL) {
				continue;
			}
			fprintf(fp,
				" %-11s %4d: %10u  %lu.%06lu %lu.%06lu %5d\n",
				locker->file, locker->line, locker->count,
				locker->locked_total.tv_sec,
				locker->locked_total.tv_usec,
				locker->wait_total.tv_sec,
				locker->wait_total.tv_usec, i);
		}
	}
}

#else

void
isc__mutex_init(isc_mutex_t *mp, const char *file, unsigned int line) {
	int err;

	err = pthread_mutex_init(mp, &attr);
	if (err != 0) {
		char strbuf[ISC_STRERRORSIZE];
		strerror_r(err, strbuf, sizeof(strbuf));
		isc_error_fatal(file, line, "pthread_mutex_init failed: %s",
				strbuf);
	}
}

#endif
