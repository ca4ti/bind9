#!/usr/bin/python3

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import logging
import os
import random

import pytest


# Configure logging to file on DEBUG level
logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s %(message)s",
    level=logging.DEBUG,
    filename="pytest.log",
    filemode="w",
)


@pytest.fixture(scope="module")  # TODO update scope
def named_port(ports):
    return int(ports.get("PORT", 5300))


@pytest.fixture(scope="module")
def named_tlsport(ports):
    return int(ports.get("TLSPORT", 8853))


@pytest.fixture(scope="module")
def named_httpsport(ports):
    return int(ports.get("HTTPSPORT", 4443))


@pytest.fixture(scope="module")
def control_port(ports):
    return int(ports.get("CONTROLPORT", 9953))


@pytest.fixture(scope="module")
def net_ns():
    return False  # TODO create / manage a network/PID namespace


@pytest.fixture(scope="module")
def base_port(net_ns):
    """Determine test base port based on whether we are in a network namespace
    or not. The base port is randomized over time to discover potential
    issues."""
    # TODO randomize ports over time - to discover potential issues
    if net_ns:
        return 5300
    # TODO re-implement get_ports.sh logic in Python
    return random.randint(5001, 25000)


@pytest.fixture(scope="module")
def ports(base_port):
    return {
        "PORT": str(base_port),
        "TLSPORT": str(base_port + 1),
        "HTTPPORT": str(base_port + 2),
        "HTTPSPORT": str(base_port + 3),
        "EXTRAPORT1": str(base_port + 4),
        "EXTRAPORT2": str(base_port + 5),
        "EXTRAPORT3": str(base_port + 6),
        "EXTRAPORT4": str(base_port + 7),
        "EXTRAPORT5": str(base_port + 8),
        "EXTRAPORT6": str(base_port + 9),
        "EXTRAPORT7": str(base_port + 10),
        "EXTRAPORT8": str(base_port + 11),
        "CONTROLPORT": str(base_port + 12),
    }
