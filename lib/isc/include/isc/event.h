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

/*! \file isc/event.h */

#include <isc/backtrace.h>
#include <isc/lang.h>
#include <isc/string.h>
#include <isc/types.h>
#include <isc/util.h>

/*****
***** Events.
*****/

typedef void (*isc_eventdestructor_t)(isc_event_t *);

#if TASKMGR_TRACE
#define ISC__EVENT_TRACE_SIZE 8
#define ISC__EVENT_FILELINE   , __func__, __FILE__, __LINE__
#define ISC__EVENT_FLARG      , const char *func, const char *file, unsigned int line

#define ISC_EVENT_COMMON(ltype)                                 \
	size_t		      ev_size;                          \
	unsigned int	      ev_attributes;                    \
	isc_eventtype_t	      ev_type;                          \
	isc_taskaction_t      ev_action;                        \
	void		     *ev_arg;                           \
	void		     *ev_sender;                        \
	isc_eventdestructor_t ev_destroy;                       \
	void		     *ev_destroy_arg;                   \
	void		     *backtrace[ISC__EVENT_TRACE_SIZE]; \
	int		      backtrace_size;                   \
	char		      func[PATH_MAX];                   \
	char		      file[PATH_MAX];                   \
	unsigned int	      line;                             \
	ISC_LINK(ltype) ev_link;                                \
	ISC_LINK(ltype) ev_ratelink

#define ISC_EVENT_INIT(event, sz, at, ty, ac, ar, sn, df, da)            \
	ISC__EVENT_INIT(event, sz, at, ty, ac, ar, sn, df, da, __func__, \
			__FILE__, __LINE__)

#define ISC_EVENT_INIT_PASS(event, sz, at, ty, ac, ar, sn, df, da) \
	ISC__EVENT_INIT(event, sz, at, ty, ac, ar, sn, df, da, func, file, line)

#define ISC__EVENT_INIT(event, sz, at, ty, ac, ar, sn, df, da, fn, fl, ln) \
	{                                                                  \
		(event)->ev_size = (sz);                                   \
		(event)->ev_attributes = (at);                             \
		(event)->ev_type = (ty);                                   \
		(event)->ev_action = (ac);                                 \
		(event)->ev_arg = (ar);                                    \
		(event)->ev_sender = (sn);                                 \
		(event)->ev_destroy = (df);                                \
		(event)->ev_destroy_arg = (da);                            \
		ISC_LINK_INIT((event), ev_link);                           \
		ISC_LINK_INIT((event), ev_ratelink);                       \
		strlcpy((event)->func, fn, sizeof((event)->func));         \
		strlcpy((event)->file, fl, sizeof((event)->file));         \
		(event)->line = ln;                                        \
		(event)->backtrace_size = isc_backtrace(                   \
			(event)->backtrace, ISC__EVENT_TRACE_SIZE);        \
	}

#else
#define ISC__EVENT_FILELINE
#define ISC__EVENT_FLARG
#define ISC__EVENT_FLARG_PASS

#define ISC_EVENT_COMMON(ltype)               \
	size_t		      ev_size;        \
	unsigned int	      ev_attributes;  \
	isc_eventtype_t	      ev_type;        \
	isc_taskaction_t      ev_action;      \
	void		     *ev_arg;         \
	void		     *ev_sender;      \
	isc_eventdestructor_t ev_destroy;     \
	void		     *ev_destroy_arg; \
	ISC_LINK(ltype) ev_link;              \
	ISC_LINK(ltype) ev_ratelink

#define ISC_EVENT_INIT(event, sz, at, ty, ac, ar, sn, df, da) \
	{                                                     \
		(event)->ev_size = (sz);                      \
		(event)->ev_attributes = (at);                \
		(event)->ev_type = (ty);                      \
		(event)->ev_action = (ac);                    \
		(event)->ev_arg = (ar);                       \
		(event)->ev_sender = (sn);                    \
		(event)->ev_destroy = (df);                   \
		(event)->ev_destroy_arg = (da);               \
		ISC_LINK_INIT((event), ev_link);              \
		ISC_LINK_INIT((event), ev_ratelink);          \
	}

#define ISC_EVENT_INIT_PASS ISC_EVENT_INIT

#endif

/*%
 * Attributes matching a mask of 0x000000ff are reserved for the task library's
 * definition.  Attributes of 0xffffff00 may be used by the application
 * or non-ISC libraries.
 */

/*%
 * The ISC_EVENTATTR_CANCELED attribute is intended to indicate
 * that an event is delivered as a result of a canceled operation
 * rather than successful completion, by mutual agreement
 * between the sender and receiver.  It is not set or used by
 * the task system.
 */
#define ISC_EVENTATTR_CANCELED 0x00000002

/*%
 * This structure is public because "subclassing" it may be useful when
 * defining new event types.
 */
struct isc_event {
	ISC_EVENT_COMMON(struct isc_event);
};

#define ISC_EVENT_PTR(p) ((isc_event_t **)(void *)(p))

ISC_LANG_BEGINDECLS

#define isc_event_allocate(mctx, sender, type, action, arg, size) \
	isc__event_allocate(mctx, sender, type, action, arg,      \
			    size ISC__EVENT_FILELINE)

isc_event_t *
isc__event_allocate(isc_mem_t *mctx, void *sender, isc_eventtype_t type,
		    isc_taskaction_t action, void *arg,
		    size_t size ISC__EVENT_FLARG);
/*%<
 * Allocate an event structure.
 *
 * Allocate and initialize in a structure with initial elements
 * defined by:
 *
 * \code
 *	struct {
 *		ISC_EVENT_COMMON(struct isc_event);
 *		...
 *	};
 * \endcode
 *
 * Requires:
 *\li	'size' >= sizeof(struct isc_event)
 *\li	'action' to be non NULL
 *
 * Returns:
 *\li	a pointer to a initialized structure of the requested size.
 *\li	NULL if unable to allocate memory.
 */

void
isc_event_free(isc_event_t **);

ISC_LANG_ENDDECLS
