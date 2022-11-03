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

#ifdef HAVE_STDNORETURN_H
#include <stdnoreturn.h>
#elif HAVE_FUNC_ATTRIBUTE_NORETURN
#define noreturn __attribute__((noreturn))
#else
#define noreturn
#endif

#if HAVE_FUNC_ATTRIBUTE_RETURNS_NONNULL
#define ISC_ATTR_RETURNS_NONNULL __attribute__((returns_nonnull))
#else
#define ISC_ATTR_RETURNS_NONNULL
#endif

#ifdef HAVE_FUNC_ATTRIBUTE_MALLOC
/*
 * Indicates that a function is malloc-like, i.e., that the
 * pointer P returned by the function cannot alias any other
 * pointer valid when the function returns.
 */
#define ISC_ATTR_MALLOC __attribute__((malloc))
#if HAVE_MALLOC_EXT_ATTR
/*
 * Associates deallocator as a suitable deallocation function
 * for pointers returned from the function marked with the attribute.
 */
#define ISC_ATTR_DEALLOCATOR(deallocator) __attribute__((malloc(deallocator)))
/*
 * Similar to ISC_ATTR_DEALLOCATOR, but allows to speficy an index "idx",
 * which denotes the positional argument to which when the pointer is passed
 * in calls to deallocator has the effect of deallocating it.
 */
#define ISC_ATTR_DEALLOCATOR_IDX(deallocator, idx) \
	__attribute__((malloc(deallocator, idx)))
/*
 * Combines both ISC_ATTR_MALLOC and ISC_ATTR_DEALLOCATOR attributes.
 */
#define ISC_ATTR_MALLOC_DEALLOCATOR(deallocator) \
	__attribute__((malloc, malloc(deallocator)))
/*
 * Similar to ISC_ATTR_MALLOC_DEALLOCATOR, but allows to speficy an index "idx",
 * which denotes the positional argument to which when the pointer is passed
 * in calls to deallocator has the effect of deallocating it.
 */
#define ISC_ATTR_MALLOC_DEALLOCATOR_IDX(deallocator, idx) \
	__attribute__((malloc, malloc(deallocator, idx)))
#else /* #ifdef HAVE_MALLOC_EXT_ATTR */
/*
 * There is support for malloc attribute but not for
 * extended attributes, so macros that combine attribute malloc
 * with a deallocator will only expand to malloc attribute.
 */
#define ISC_ATTR_DEALLOCATOR(deallocator)
#define ISC_ATTR_DEALLOCATOR_IDX(deallocator, idx)
#define ISC_ATTR_MALLOC_DEALLOCATOR(deallocator)	  ISC_ATTR_MALLOC
#define ISC_ATTR_MALLOC_DEALLOCATOR_IDX(deallocator, idx) ISC_ATTR_MALLOC
#endif
#else /* #ifdef HAVE_FUNC_ATTRIBUTE_MALLOC */
/*
 * There is no support for malloc attribute.
 */
#define ISC_ATTR_MALLOC
#define ISC_ATTR_DEALLOCATOR(deallocator)
#define ISC_ATTR_DEALLOCATOR_IDX(deallocator, idx)
#define ISC_ATTR_MALLOC_DEALLOCATOR(deallocator)
#define ISC_ATTR_MALLOC_DEALLOCATOR_IDX(deallocator, idx)
#endif /* HAVE_FUNC_ATTRIBUTE_MALLOC */

/*
 * When we are using an inheritance pattern (where several structures
 * share a common prefix) we would like it to be easy to pass any of
 * these subtype structures to functions that only operate on the
 * common prefix, and we would also like it to be type safe.
 *
 * GNU C transparent unions have quiet conversions like void pointers,
 * but only for a specific set of types. So they make it easy to pass
 * just the known subtypes to a function that operates on their common
 * prefix.
 *
 * On compilers without transparent unions we can use void pointers
 * instead; we still benefit from type checking during development.
 */
#ifdef __has_attribute
#if __has_attribute(__transparent_union__)
#define ISC_ATTR_TRANSPARENT __attribute__((__transparent_union__))
#endif
#endif
