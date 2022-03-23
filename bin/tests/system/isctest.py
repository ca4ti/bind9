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

from typing import NamedTuple

import abc
import logging
import os
import re
import subprocess


# pylint: disable=too-few-public-methods
class RNDCExecutor(abc.ABC):

    '''
    An interface which RNDC executors have to implement in order for the
    `NamedInstance` class to be able to use them.
    '''

    @abc.abstractmethod
    def call(self, ip: str, port: int, command: str) -> str:
        '''
        Send RNDC `command` to the `named` instance at `ip:port` and return the
        server's response.
        '''


class RNDCException(Exception):
    '''
    Raised by classes implementing the `RNDCExecutor` interface when sending an
    RNDC command fails for any reason.
    '''


class RNDCBinaryExecutor(RNDCExecutor):

    '''
    An `RNDCExecutor` which sends RNDC commands to servers using the `rndc`
    binary.
    '''

    def __init__(self) -> None:
        '''
        This class needs the `RNDC` environment variable to be set to the path
        to the `rndc` binary to use.
        '''
        rndc_path = os.environ.get('RNDC', '/usr/sbin/rndc')
        rndc_conf = os.path.join('..', 'common', 'rndc.conf')
        self._base_cmdline = [rndc_path, '-c', rndc_conf]

    def call(self, ip: str, port: int, command: str) -> str:
        '''
        Send RNDC `command` to the `named` instance at `ip:port` and return the
        server's response.
        '''
        cmdline = self._base_cmdline[:]
        cmdline.extend(['-s', ip])
        cmdline.extend(['-p', str(port)])
        cmdline.extend(command.split())

        try:
            return subprocess.check_output(cmdline, stderr=subprocess.STDOUT,
                                           timeout=10, encoding='utf-8')
        except subprocess.SubprocessError as exc:
            msg = getattr(exc, 'output', 'RNDC exception occurred')
            raise RNDCException(msg) from exc


class NamedPorts(NamedTuple):
    dns: int = 53
    rndc: int = 953


class NamedInstance:

    '''
    A class representing a `named` instance used in a system test.

    This class is expected to be instantiated as part of the `servers` fixture:

    ```python
    def test_foo(servers):
        servers['ns1'].rndc('status')
    ```
    '''

    def __init__(self, identifier: str, ports: NamedPorts = NamedPorts(),
                 rndc_logger: logging.Logger = logging.getLogger(),
                 rndc_executor: RNDCExecutor = RNDCBinaryExecutor()) -> None:
        '''
        `identifier` must be an `ns<X>` string, where `<X>` is an integer
        identifier of the `named` instance this object should represent.

        `ports` is the `NamedPorts` instance listing the UDP/TCP ports on which
        this `named` instance is listening for various types of traffic (both
        DNS traffic and RNDC commands).

        `rndc_logger` is the `logging.Logger` to use for logging RNDC
        commands sent to this `named` instance.

        `rndc_executor` is an object implementing the `RNDCExecutor` interface
        that is used for executing RNDC commands on this `named` instance.
        '''
        regex_match = re.match(r'^ns(?P<index>[0-9]{1,2})$', identifier)
        if not regex_match:
            raise ValueError('Invalid named instance identifier' + identifier)
        self.ip = '10.53.0.' + regex_match.group('index')
        self.ports = ports
        self._log_file = os.path.join(identifier, 'named.run')
        self._rndc_executor = rndc_executor
        self._rndc_logger = rndc_logger

    def rndc(self, command: str, ignore_errors: bool = False,
             log: bool = True) -> str:
        '''
        Send `command` to this named instance using RNDC.  Return the server's
        response.

        If the RNDC command fails, an `RNDCException` is raised unless
        `ignore_errors` is set to `True`.

        The RNDC command will be logged to `rndc.log` (along with the server's
        response) unless `log` is set to `False`.

        >>> # Instances of the `NamedInstance` class are expected to be passed
        >>> # to pytest tests as fixtures; here, some instances are created
        >>> # directly (with a fake RNDC executor) so that doctest can work.
        >>> import unittest.mock
        >>> mock_rndc_executor = unittest.mock.Mock()
        >>> ns1 = NamedInstance('ns1', rndc_executor=mock_rndc_executor)
        >>> ns2 = NamedInstance('ns2', rndc_executor=mock_rndc_executor)
        >>> ns3 = NamedInstance('ns3', rndc_executor=mock_rndc_executor)
        >>> ns4 = NamedInstance('ns4', rndc_executor=mock_rndc_executor)

        >>> # Send the "status" command to ns1.  An `RNDCException` will be
        >>> # raised if the RNDC command fails.  This command will be logged.
        >>> response = ns1.rndc('status')

        >>> # Send the "thaw foo" command to ns2.  No exception will be raised
        >>> # in case the RNDC command fails.  This command will be logged
        >>> # (even if it fails).
        >>> response = ns2.rndc('thaw foo', ignore_errors=True)

        >>> # Send the "stop" command to ns3.  An `RNDCException` will be
        >>> # raised if the RNDC command fails, but this command will not be
        >>> # logged (the server's response will still be returned to the
        >>> # caller, though).
        >>> response = ns3.rndc('stop', log=False)

        >>> # Send the "halt" command to ns4 in "fire & forget mode": no
        >>> # exceptions will be raised and no logging will take place (the
        >>> # server's response will still be returned to the caller, though).
        >>> response = ns4.rndc('stop', ignore_errors=True, log=False)
        '''
        try:
            response = self._rndc_executor.call(self.ip, self.ports.rndc,
                                                command)
            if log:
                self._rndc_log(command, response)
        except RNDCException as exc:
            response = str(exc)
            if log:
                self._rndc_log(command, response)
            if not ignore_errors:
                raise

        return response

    def _rndc_log(self, command: str, response: str) -> None:
        '''
        Log an `rndc` invocation (and its output) to the `rndc.log` file in the
        current working directory.
        '''
        fmt = '%(ip)s: "%(command)s"\n%(separator)s\n%(response)s%(separator)s'
        self._rndc_logger.info(fmt, {'ip': self.ip,
                                     'command': command,
                                     'separator': '-' * 80,
                                     'response': response})
