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

#if HAVE_CMOCKA

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/mem.h>
#include <isc/pool.h>
#include <isc/util.h>

#include "isctest.h"

static int
_setup(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = isc_test_begin(NULL, true, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	isc_test_end();

	return (0);
}

static isc_result_t
poolinit(void **target, void *arg) {
	isc_result_t result;

	isc_taskmgr_t *mgr = (isc_taskmgr_t *)arg;
	isc_task_t *task = NULL;
	result = isc_task_create(mgr, 0, &task);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	*target = (void *)task;
	return (ISC_R_SUCCESS);
}

static void
poolfree(void **target) {
	isc_task_t *task = *(isc_task_t **)target;
	isc_task_destroy(&task);
	*target = NULL;
}

/* Create a pool */
static void
create_pool(void **state) {
	isc_result_t result;
	isc_pool_t *pool = NULL;

	UNUSED(state);

	result = isc_pool_create(test_mctx, 8, poolfree, poolinit, taskmgr,
				 &pool);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_pool_destroy(&pool);
	assert_null(pool);
}

/* Get objects */
static void
get_objects(void **state) {
	isc_result_t result;
	isc_pool_t *pool = NULL;
	void *item;
	isc_task_t *task1 = NULL, *task2 = NULL, *task3 = NULL;

	UNUSED(state);

	result = isc_pool_create(test_mctx, 2, poolfree, poolinit, taskmgr,
				 &pool);
	assert_int_equal(result, ISC_R_SUCCESS);

	item = isc_pool_get(pool, 0);
	assert_non_null(item);
	isc_task_attach((isc_task_t *)item, &task1);

	item = isc_pool_get(pool, 1);
	assert_non_null(item);
	isc_task_attach((isc_task_t *)item, &task2);

	item = isc_pool_get(pool, 0);
	assert_non_null(item);
	isc_task_attach((isc_task_t *)item, &task3);

	isc_task_detach(&task1);
	isc_task_detach(&task2);
	isc_task_detach(&task3);

	isc_pool_destroy(&pool);
	assert_null(pool);
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(create_pool, _setup, _teardown),
		cmocka_unit_test_setup_teardown(get_objects, _setup, _teardown),
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */
