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

/*! \file */

#ifdef HAVE_GNUTLS
#include <gnutls/crypto.h>
#include <gnutls/pkcs11.h>
#endif

#include <string.h>

#include <isc/assertions.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/keystore.h>
#include <dns/keyvalues.h>

#ifdef HAVE_GNUTLS
static gnutls_pk_algorithm_t
pk_alg(uint32_t alg) {
	gnutls_pk_algorithm_t pk = GNUTLS_PK_UNKNOWN;

	switch (alg) {
	case DST_ALG_RSASHA1:
	case DST_ALG_NSEC3RSASHA1:
	case DST_ALG_RSASHA256:
	case DST_ALG_RSASHA512:
		pk = GNUTLS_PK_RSA;
		break;
	case DST_ALG_ECDSA256:
	case DST_ALG_ECDSA384:
		pk = GNUTLS_PK_ECDSA;
		break;
	case DST_ALG_ED25519:
		pk = GNUTLS_PK_EDDSA_ED25519;
		break;
	case DST_ALG_ED448:
		pk = GNUTLS_PK_EDDSA_ED448;
		break;
	default:
		pk = GNUTLS_PK_UNKNOWN;
		break;
	}
	return (pk);
}
#endif /* HAVE_GNUTLS */

isc_result_t
dns_keystore_create(isc_mem_t *mctx, const char *name, const char *engine,
		    dns_keystore_t **kspp) {
	dns_keystore_t *keystore;

	REQUIRE(name != NULL);
	REQUIRE(kspp != NULL && *kspp == NULL);

	keystore = isc_mem_get(mctx, sizeof(*keystore));
	keystore->engine = engine;
	keystore->mctx = NULL;
	isc_mem_attach(mctx, &keystore->mctx);

	keystore->name = isc_mem_strdup(mctx, name);
	isc_mutex_init(&keystore->lock);

	isc_refcount_init(&keystore->references, 1);

	ISC_LINK_INIT(keystore, link);

	keystore->directory = NULL;
	keystore->pkcs11uri = NULL;

	keystore->magic = DNS_KEYSTORE_MAGIC;
	*kspp = keystore;

	return (ISC_R_SUCCESS);
}

void
dns_keystore_attach(dns_keystore_t *source, dns_keystore_t **targetp) {
	REQUIRE(DNS_KEYSTORE_VALID(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);
	*targetp = source;
}

static inline void
destroy(dns_keystore_t *keystore) {
	char *name;

	REQUIRE(!ISC_LINK_LINKED(keystore, link));

	isc_mutex_destroy(&keystore->lock);

	DE_CONST(keystore->name, name);
	isc_mem_free(keystore->mctx, name);
	if (keystore->directory != NULL) {
		isc_mem_free(keystore->mctx, keystore->directory);
	}
	if (keystore->pkcs11uri != NULL) {
		isc_mem_free(keystore->mctx, keystore->pkcs11uri);
	}
	isc_mem_putanddetach(&keystore->mctx, keystore, sizeof(*keystore));
}

void
dns_keystore_detach(dns_keystore_t **kspp) {
	REQUIRE(kspp != NULL && DNS_KEYSTORE_VALID(*kspp));

	dns_keystore_t *ks = *kspp;
	*kspp = NULL;

	if (isc_refcount_decrement(&ks->references) == 1) {
		destroy(ks);
	}
}

const char *
dns_keystore_name(dns_keystore_t *keystore) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	return (keystore->name);
}

const char *
dns_keystore_engine(dns_keystore_t *keystore) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	return (keystore->engine);
}

const char *
dns_keystore_directory(dns_keystore_t *keystore) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	return (keystore->directory);
}

void
dns_keystore_setdirectory(dns_keystore_t *keystore, const char *dir) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	if (keystore->directory != NULL) {
		isc_mem_free(keystore->mctx, keystore->directory);
	}
	keystore->directory = (dir == NULL)
				      ? NULL
				      : isc_mem_strdup(keystore->mctx, dir);
}

const char *
dns_keystore_pkcs11uri(dns_keystore_t *keystore) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	return (keystore->pkcs11uri);
}

void
dns_keystore_setpkcs11uri(dns_keystore_t *keystore, const char *uri) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	if (keystore->pkcs11uri != NULL) {
		isc_mem_free(keystore->mctx, keystore->pkcs11uri);
	}
	keystore->pkcs11uri = (uri == NULL)
				      ? NULL
				      : isc_mem_strdup(keystore->mctx, uri);
}

isc_result_t
dns_keystore_keygen(dns_keystore_t *keystore, const dns_name_t *origin,
		    dns_rdataclass_t rdclass, isc_mem_t *mctx, uint32_t alg,
		    int size, int flags, dst_key_t **dstkey) {
	isc_result_t result;
	dst_key_t *newkey = NULL;

	REQUIRE(DNS_KEYSTORE_VALID(keystore));
	REQUIRE(dns_name_isvalid(origin));
	REQUIRE(mctx != NULL);
	REQUIRE(dstkey != NULL && *dstkey == NULL);

	if (dns_keystore_pkcs11uri(keystore) != NULL) {
		char timebuf[18];
		isc_time_t now;
		isc_result_t r = isc_time_now(&now);
		bool ksk = ((flags & DNS_KEYFLAG_KSK) != 0);
		char namebuf[DNS_NAME_FORMATSIZE];
		char object[DNS_NAME_FORMATSIZE + 26];

#ifdef HAVE_GNUTLS
		const char *url = dns_keystore_pkcs11uri(keystore);
		char *label = NULL;
		size_t len;
		uint8_t cidbuf[20] = { 0 };
		gnutls_datum_t cid = { .size = sizeof(cidbuf), .data = cidbuf };
		int gnufl = 0;
		int ret;
#endif

		if (r == ISC_R_SUCCESS) {
			isc_time_formatshorttimestamp(&now, timebuf,
						      sizeof(timebuf));
		}
		dns_name_format(origin, namebuf, sizeof(namebuf));
		snprintf(object, sizeof(object), "%s-%s-%s", namebuf,
			 ksk ? "ksk" : "zsk",
			 r == ISC_R_SUCCESS ? timebuf : "19700101000000000");

#ifdef HAVE_GNUTLS
		gnufl = GNUTLS_PKCS11_OBJ_FLAG_MARK_SENSITIVE |
			GNUTLS_PKCS11_OBJ_FLAG_LOGIN;
		gnutls_rnd(GNUTLS_RND_RANDOM, cidbuf, sizeof(cidbuf));

		ret = gnutls_pkcs11_privkey_generate3(url, pk_alg(alg), size,
						      object, &cid, 0, NULL, 0,
						      gnufl);

		if (ret != GNUTLS_E_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DNSSEC,
				      DNS_LOGMODULE_DNSSEC, ISC_LOG_ERROR,
				      "keymgr: failed to generate key "
				      "%s (ret=%d)",
				      object, ret);
			return (DST_R_CRYPTOFAILURE);
		}

		len = strlen(object) + strlen(url) + 10;
		label = isc_mem_get(mctx, len);
		sprintf(label, "%s;object=%s;", url, object);

		result = dst_key_fromlabel(
			origin, alg, flags, DNS_KEYPROTO_DNSSEC,
			dns_rdataclass_in, dns_keystore_engine(keystore), label,
			NULL, mctx, &newkey);

		isc_mem_put(mctx, label, len);

		if (result != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DNSSEC,
				      DNS_LOGMODULE_DNSSEC, ISC_LOG_ERROR,
				      "keymgr: failed to access key "
				      "%s (%s)",
				      object, isc_result_totext(ret));
		}
#else
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DNSSEC,
			      DNS_LOGMODULE_DNSSEC, ISC_LOG_ERROR,
			      "keymgr: failed to generate key "
			      "%s (#PKCS11 not enabled)",
			      object);
		result = DST_R_NOCRYPTO;
#endif
	} else {
		result = dst_key_generate(origin, alg, size, 0, flags,
					  DNS_KEYPROTO_DNSSEC, rdclass, mctx,
					  &newkey, NULL);
	}

	if (result == ISC_R_SUCCESS) {
		*dstkey = newkey;
	}
	return (result);
}

isc_result_t
dns_keystorelist_find(dns_keystorelist_t *list, const char *name,
		      dns_keystore_t **kspp) {
	dns_keystore_t *keystore = NULL;

	REQUIRE(kspp != NULL && *kspp == NULL);

	if (list == NULL) {
		return (ISC_R_NOTFOUND);
	}

	for (keystore = ISC_LIST_HEAD(*list); keystore != NULL;
	     keystore = ISC_LIST_NEXT(keystore, link))
	{
		if (strcmp(keystore->name, name) == 0) {
			break;
		}
	}

	if (keystore == NULL) {
		return (ISC_R_NOTFOUND);
	}

	dns_keystore_attach(keystore, kspp);
	return (ISC_R_SUCCESS);
}
