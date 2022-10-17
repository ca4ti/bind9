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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <isc/ascii.h>
#include <isc/random.h>
#include <isc/siphash.h>
#include <isc/time.h>

#define SIZE (1024 * 1024)

#define KILOHASHES(count, us) ((us) == 0 ? 0.0 : ((count)*1000.0 / (us)))

int
main(void) {
	static uint8_t bytes[SIZE];
	static uint8_t key[16];

	isc_random_buf(bytes, SIZE);
	isc_random_buf(key, sizeof(key));

	for (size_t len = 256; len > 0; len = len * 4 / 5) {
		isc_time_t start;
		uint64_t count = 0;
		uint64_t sum = 0;
		uint64_t us;

		isc_time_now_hires(&start);

		for (size_t end = len; end < SIZE; end += len) {
			uint64_t hash;
			uint8_t lower[1024];
			isc_ascii_lowercopy(lower, bytes + end - len, len);
			isc_siphash24(key, lower, len, (void *)&hash);
			sum += hash;
			count++;
		}

		isc_time_t finish;
		isc_time_now_hires(&finish);

		us = isc_time_microdiff(&finish, &start);
		printf("%f us wide-lower len %3zu, %7.0f kh/s (%llx)\n",
		       (double)us / 1000000.0, len, KILOHASHES(count, us),
		       (unsigned long long)sum);
	}

	for (size_t len = 256; len > 0; len = len * 4 / 5) {
		isc_time_t start;
		uint64_t count = 0;
		uint64_t sum = 0;
		uint64_t us;

		isc_time_now_hires(&start);

		for (size_t end = len; end < SIZE; end += len) {
			uint64_t hash;
			isc_siphash24(key, bytes + end - len, len,
				      (void *)&hash);
			sum += hash;
			count++;
		}

		isc_time_t finish;
		isc_time_now_hires(&finish);

		us = isc_time_microdiff(&finish, &start);
		printf("%f us wide-icase len %3zu, %7.0f kh/s (%llx)\n",
		       (double)us / 1000000.0, len, KILOHASHES(count, us),
		       (unsigned long long)sum);
	}

	for (size_t len = 256; len > 0; len = len * 4 / 5) {
		isc_time_t start;
		uint64_t count = 0;
		uint64_t sum = 0;
		uint64_t us;

		isc_time_now_hires(&start);

		for (size_t end = len; end < SIZE; end += len) {
			uint32_t hash;
			uint8_t lower[1024];
			isc_ascii_lowercopy(lower, bytes + end - len, len);
			isc_halfsiphash24(key, lower, len, (void *)&hash);
			sum += hash;
			count++;
		}

		isc_time_t finish;
		isc_time_now_hires(&finish);

		us = isc_time_microdiff(&finish, &start);
		printf("%f us half-lower len %3zu, %7.0f kh/s (%llx)\n",
		       (double)us / 1000000.0, len, KILOHASHES(count, us),
		       (unsigned long long)sum);
	}
}
