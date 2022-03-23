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

# pylint: disable=redefined-outer-name

import logging
import os

import pytest

import isctest


@pytest.fixture(scope='session')
def named_port():
    return int(os.environ.get('PORT', default=5300))


@pytest.fixture(scope='session')
def named_tlsport():
    return int(os.environ.get('TLSPORT', default=8853))


@pytest.fixture(scope='session')
def control_port():
    return int(os.environ.get('CONTROLPORT', default=9953))


@pytest.fixture(scope='module')
def rndc_logger():
    formatter = logging.Formatter('[%(asctime)s] %(message)s')
    handler = logging.FileHandler('rndc.log')
    handler.setFormatter(formatter)
    logger = logging.getLogger('rndc')
    logger.addHandler(handler)
    logger.setLevel('DEBUG')
    return logger


@pytest.fixture(scope='module')
def servers(named_port, control_port, rndc_logger):
    instances = {}
    with os.scandir() as iterator:
        for entry in iterator:
            if entry.is_dir():
                try:
                    dir_name = entry.name
                    ports = isctest.NamedPorts(dns=named_port,
                                               rndc=control_port)
                    instance = isctest.NamedInstance(dir_name, ports,
                                                     rndc_logger)
                    instances[dir_name] = instance
                except ValueError:
                    continue
    return instances
