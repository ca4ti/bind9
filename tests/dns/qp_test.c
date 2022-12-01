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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/name.h>
#include <dns/qp.h>

#include <tests/dns.h>
#include <tests/qp.h>

ISC_RUN_TEST_IMPL(qpkey_name) {
	struct {
		const char *namestr;
		uint8_t key[512];
		size_t len;
	} testcases[] = {
		{
			.namestr = ".",
			.key = { 0x01, 0x01 },
			.len = 1,
		},
		{
			.namestr = "\\000",
			.key = { 0x02, 0x02, 0x01, 0x01 },
			.len = 3,
		},
		{
			.namestr = "example.com.",
			.key = { 0x01, 0x15, 0x21, 0x1f, 0x01, 0x17, 0x2a, 0x13,
				 0x1f, 0x22, 0x1e, 0x17, 0x01, 0x01 },
			.len = 13,
		},
		{
			.namestr = "example.com",
			.key = { 0x15, 0x21, 0x1f, 0x01, 0x17, 0x2a, 0x13, 0x1f,
				 0x22, 0x1e, 0x17, 0x01, 0x01 },
			.len = 12,
		},
		{
			.namestr = "EXAMPLE.COM",
			.key = { 0x15, 0x21, 0x1f, 0x01, 0x17, 0x2a, 0x13, 0x1f,
				 0x22, 0x1e, 0x17, 0x01, 0x01 },
			.len = 12,
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		size_t len;
		dns_qpkey_t key;
		dns_fixedname_t fn1, fn2;
		dns_name_t *in = NULL, *out = NULL;

		dns_test_namefromstring(testcases[i].namestr, &fn1);
		in = dns_fixedname_name(&fn1);
		len = dns_qpkey_fromname(key, in);

#if 0
		for (int j = 0; j < 512; j++) {
			fprintf(stderr, "%02x ", key[j]);
			if (key[j] == 1 && key[j+1] == 1) {
				fprintf(stderr, "%02x\n", key[j+1]);
				break;
			}
		}
#endif

		assert_true(testcases[i].len == len);
		assert_true(memcmp(testcases[i].key, key, len) == 0);

		out = dns_fixedname_initname(&fn2);
		qp_test_keytoname(key, out);
		assert_true(dns_name_equal(in, out));
	}
}

ISC_RUN_TEST_IMPL(qpkey_sort) {
	struct {
		const char *namestr;
		dns_name_t *name;
		dns_fixedname_t fixed;
		size_t len;
		dns_qpkey_t key;
	} testcases[] = {
		{ .namestr = "." },
		{ .namestr = "\\000." },
		{ .namestr = "example.com." },
		{ .namestr = "EXAMPLE.COM." },
		{ .namestr = "www.example.com." },
		{ .namestr = "exam.com." },
		{ .namestr = "exams.com." },
		{ .namestr = "exam\\000.com." },
	};

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		dns_test_namefromstring(testcases[i].namestr,
					&testcases[i].fixed);
		testcases[i].name = dns_fixedname_name(&testcases[i].fixed);
		testcases[i].len = dns_qpkey_fromname(testcases[i].key,
						      testcases[i].name);
	}

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		for (size_t j = 0; j < ARRAY_SIZE(testcases); j++) {
			int namecmp = dns_name_compare(testcases[i].name,
						       testcases[j].name);
			size_t len = ISC_MIN(testcases[i].len,
					     testcases[j].len);
			/* include extra terminating NOBYTE */
			int keycmp = memcmp(testcases[i].key, testcases[j].key,
					    len + 1);
			assert_true((namecmp < 0) == (keycmp < 0));
			assert_true((namecmp == 0) == (keycmp == 0));
			assert_true((namecmp > 0) == (keycmp > 0));
		}
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(qpkey_name)
ISC_TEST_ENTRY(qpkey_sort)
ISC_TEST_LIST_END

ISC_TEST_MAIN
