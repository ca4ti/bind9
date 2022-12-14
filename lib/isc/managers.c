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

#include <isc/managers.h>
#include <isc/util.h>

void
isc_managers_create(isc_mem_t **mctxp, uint32_t workers,
		    isc_loopmgr_t **loopmgrp, isc_nm_t **netmgrp,
		    isc_taskmgr_t **taskmgrp) {
	REQUIRE(mctxp != NULL && *mctxp == NULL);
	isc_mem_create(mctxp);
	INSIST(*mctxp != NULL);

	REQUIRE(loopmgrp != NULL && *loopmgrp == NULL);
	isc_loopmgr_create(*mctxp, workers, loopmgrp);
	INSIST(*loopmgrp != NULL);

	REQUIRE(netmgrp != NULL && *netmgrp == NULL);
	isc_netmgr_create(*mctxp, *loopmgrp, netmgrp);
	INSIST(*netmgrp != NULL);

	REQUIRE(taskmgrp != NULL && *taskmgrp == NULL);
	isc_taskmgr_create(*mctxp, *loopmgrp, taskmgrp);
	INSIST(*taskmgrp != NULL);
}

void
isc_managers_destroy(isc_mem_t **mctxp, isc_loopmgr_t **loopmgrp,
		     isc_nm_t **netmgrp, isc_taskmgr_t **taskmgrp) {
	REQUIRE(mctxp != NULL && *mctxp != NULL);
	REQUIRE(loopmgrp != NULL && *loopmgrp != NULL);
	REQUIRE(netmgrp != NULL && *netmgrp != NULL);
	REQUIRE(taskmgrp != NULL && *taskmgrp != NULL);

	/*
	 * The sequence of operations here is important:
	 */

	isc_taskmgr_destroy(taskmgrp);
	isc_netmgr_destroy(netmgrp);
	isc_loopmgr_destroy(loopmgrp);
	isc_mem_destroy(mctxp);
}
