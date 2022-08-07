/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0 AND ISC
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*
 * Copyright (C) Network Associates, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC AND NETWORK ASSOCIATES DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE
 * FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <isc/fips.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/mutexblock.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/thread.h>
#include <isc/tls.h>
#include <isc/util.h>

#include <dns/log.h>

#include "dst_internal.h"
#include "dst_openssl.h"

#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
#include <openssl/engine.h>
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */

#include "openssl_shim.h"

#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
static ENGINE *e = NULL;
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */

static void
enable_fips_mode(void) {
#if defined(ENABLE_FIPS_MODE)
	if (isc_fips_mode()) {
		/*
		 * FIPS mode is already enabled.
		 */
		return;
	}

	if (isc_fips_set_mode(1) != ISC_R_SUCCESS) {
		dst__openssl_toresult2("FIPS_mode_set", DST_R_OPENSSLFAILURE);
		exit(1);
	}
#endif
}

isc_result_t
dst__openssl_init(const char *engine) {
	isc_result_t result = ISC_R_SUCCESS;

	enable_fips_mode();

#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
	if (engine != NULL && *engine == '\0') {
		engine = NULL;
	}

	if (engine != NULL) {
		e = ENGINE_by_id(engine);
		if (e == NULL) {
			result = DST_R_NOENGINE;
			goto cleanup_rm;
		}
		if (!ENGINE_init(e)) {
			result = DST_R_NOENGINE;
			goto cleanup_rm;
		}
		/* This will init the engine. */
		if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
			result = DST_R_NOENGINE;
			goto cleanup_init;
		}
	}

	return (ISC_R_SUCCESS);
cleanup_init:
	ENGINE_finish(e);
cleanup_rm:
	if (e != NULL) {
		ENGINE_free(e);
	}
	e = NULL;
#else
	UNUSED(engine);
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
	return (result);
}

void
dst__openssl_destroy(void) {
#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
	if (e != NULL) {
		ENGINE_finish(e);
		ENGINE_free(e);
	}
	e = NULL;
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
}

static isc_result_t
toresult(isc_result_t fallback) {
	isc_result_t result = fallback;
	unsigned long err = ERR_peek_error();
#if defined(ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED)
	int lib = ERR_GET_LIB(err);
#endif /* if defined(ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED) */
	int reason = ERR_GET_REASON(err);

	switch (reason) {
	/*
	 * ERR_* errors are globally unique; others
	 * are unique per sublibrary
	 */
	case ERR_R_MALLOC_FAILURE:
		result = ISC_R_NOMEMORY;
		break;
	default:
#if defined(ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED)
		if (lib == ERR_R_ECDSA_LIB &&
		    reason == ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED) {
			result = ISC_R_NOENTROPY;
			break;
		}
#endif /* if defined(ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED) */
		break;
	}

	return (result);
}

isc_result_t
dst__openssl_toresult(isc_result_t fallback) {
	isc_result_t result;

	result = toresult(fallback);

	ERR_clear_error();
	return (result);
}

isc_result_t
dst___openssl_toresult2(const char *funcname, isc_result_t fallback,
			const char *file, int line) {
	return (dst___openssl_toresult3(DNS_LOGCATEGORY_GENERAL, funcname,
					fallback, file, line));
}

isc_result_t
dst___openssl_toresult3(isc_logcategory_t *category, const char *funcname,
			isc_result_t fallback, const char *file, int line) {
	isc_result_t result;
	unsigned long err;
	const char *func, *data;
	int flags;
	char buf[256];

	result = toresult(fallback);

	isc_log_write(dns_lctx, category, DNS_LOGMODULE_CRYPTO, ISC_LOG_WARNING,
		      "%s (%s:%d) failed (%s)", funcname, file, line,
		      isc_result_totext(result));

	if (result == ISC_R_NOMEMORY) {
		goto done;
	}

	for (;;) {
		err = ERR_get_error_all(&file, &line, &func, &data, &flags);
		if (err == 0U) {
			goto done;
		}
		ERR_error_string_n(err, buf, sizeof(buf));
		isc_log_write(dns_lctx, category, DNS_LOGMODULE_CRYPTO,
			      ISC_LOG_INFO, "%s:%s:%d:%s", buf, file, line,
			      ((flags & ERR_TXT_STRING) != 0) ? data : "");
	}

done:
	ERR_clear_error();
	return (result);
}

#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
ENGINE *
dst__openssl_getengine(const char *engine) {
	if (engine == NULL) {
		return (NULL);
	}
	if (e == NULL) {
		return (NULL);
	}
	if (strcmp(engine, ENGINE_get_id(e)) == 0) {
		return (e);
	}
	return (NULL);
}
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */

/*! \file */
