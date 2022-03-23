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

from typing import Any, Dict, NamedTuple, Optional, TextIO

import abc
import logging
import os
import re
import subprocess
import time


class WatchLog:

    '''
    Wait for a log message to appear in a text file.

    This class should not be used directly; instead, its subclasses,
    `WatchLogFromStart` and `WatchLogFromHere`, should be used.  For `named`
    instances used in system tests, it is recommended to use the
    `watch_log_from_start()` and `watch_log_from_here()` helper methods exposed
    by the `NamedInstance` class (see below for recommended usage patterns).
    '''

    def __init__(self, path: str) -> None:
        '''
        `path` is the path to the log file to watch.

        Every instance of this class must call one of the `wait_for_*()`
        methods exactly once or else an `Exception` is thrown.

        >>> with WatchLogFromStart('/dev/null') as watcher:
        ...     print('Just print something without waiting for a log line')
        Traceback (most recent call last):
          ...
        Exception: wait_for_*() was not called

        >>> with WatchLogFromHere('/dev/null') as watcher:
        ...     try:
        ...         watcher.wait_for_line('foo', timeout=0)
        ...     except TimeoutError:
        ...         pass
        ...     try:
        ...         watcher.wait_for_lines({'bar': 42}, timeout=0)
        ...     except TimeoutError:
        ...         pass
        Traceback (most recent call last):
          ...
        Exception: wait_for_*() was already called
        '''
        self._fd = None  # type: Optional[TextIO]
        self._path = path
        self._wait_function_called = False

    def wait_for_line(self, string: str, timeout: int = 10) -> None:
        '''
        Block execution until a line containing the provided `string` appears
        in the log file.  Return `None` once the line is found or raise a
        `TimeoutError` after `timeout` seconds (default: 10) if `string` does
        not appear in the log file.  (Catching this exception is discouraged as
        it indicates that the test code did not behave as expected.)

        Recommended use:

        ```python
        import isctest

        def test_foo(servers):
            with servers['ns1'].watch_log_from_here() as watcher:
                # ... do stuff here ...
                watcher.wait_for_line('foo bar')
        ```

        One of `wait_for_line()` or `wait_for_lines()` must be called exactly
        once for every `WatchLogFrom*` instance.

        >>> # For `WatchLogFromStart`, `wait_for_line()` returns without
        >>> # raising an exception as soon as the line being looked for appears
        >>> # anywhere in the file, no matter whether that happens before of
        >>> # after the `with` statement is reached.
        >>> import tempfile
        >>> with tempfile.NamedTemporaryFile('w') as file:
        ...     print('foo', file=file, flush=True)
        ...     with WatchLogFromStart(file.name) as watcher:
        ...         retval = watcher.wait_for_line('foo', timeout=1)
        >>> print(retval)
        None
        >>> with tempfile.NamedTemporaryFile('w') as file:
        ...     with WatchLogFromStart(file.name) as watcher:
        ...         print('foo', file=file, flush=True)
        ...         retval = watcher.wait_for_line('foo', timeout=1)
        >>> print(retval)
        None

        >>> # For `WatchLogFromHere`, `wait_for_line()` only returns without
        >>> # raising an exception if the string being looked for appears in
        >>> # the log file after the `with` statement is reached.
        >>> import tempfile
        >>> with tempfile.NamedTemporaryFile('w') as file:
        ...     print('foo', file=file, flush=True)
        ...     with WatchLogFromHere(file.name) as watcher:
        ...         watcher.wait_for_line('foo', timeout=1) #doctest: +ELLIPSIS
        Traceback (most recent call last):
          ...
        TimeoutError: Timeout reached watching ...
        >>> with tempfile.NamedTemporaryFile('w') as file:
        ...     print('foo', file=file, flush=True)
        ...     with WatchLogFromHere(file.name) as watcher:
        ...         print('foo', file=file, flush=True)
        ...         retval = watcher.wait_for_line('foo', timeout=1)
        >>> print(retval)
        None
        '''
        return self._wait_for({string: None}, timeout)

    def wait_for_lines(self, strings: Dict[str, Any],
                       timeout: int = 10) -> None:
        '''
        Block execution until a line of interest appears in the log file.  This
        function is a "multi-match" variant of `wait_for_line()` which is
        useful when some action may cause several different (mutually
        exclusive) messages to appear in the log file.

        `strings` is a `dict` associating each string to look for with the
        value this function should return when that string is found in the log
        file.  If none of the `strings` being looked for appear in the log file
        after `timeout` seconds (default: 10), a `TimeoutError` is raised.
        (Catching this exception is discouraged as it indicates that the test
        code did not behave as expected.)

        `strings` are assumed to be mutually exclusive; no guarantees are made
        about the order in which these `strings` will be looked for in any
        single line.  Values provided in the `strings` dictionary (i.e. values
        which this function is expected to return upon a successful match) can
        be of any type.

        Recommended use:

        ```python
        import isctest

        def test_foo(servers):
            triggers = {
                'message A': 'value returned when message A is found',
                'message B': 'value returned when message B is found',
            }
            with servers['ns1'].watch_log_from_here() as watcher:
                # ... do stuff here ...
                retval = watcher.wait_for_lines(triggers)
        ```

        One of `wait_for_line()` or `wait_for_lines()` must be called exactly
        once for every `WatchLogFromHere` instance.

        >>> # Different values must be returned depending on which line is
        >>> # found in the log file.
        >>> import tempfile
        >>> triggers = {'foo': 42, 'bar': 1337}
        >>> with tempfile.NamedTemporaryFile('w') as file:
        ...     print('foo', file=file, flush=True)
        ...     with WatchLogFromStart(file.name) as watcher:
        ...         retval1 = watcher.wait_for_lines(triggers, timeout=1)
        ...     with WatchLogFromHere(file.name) as watcher:
        ...         print('bar', file=file, flush=True)
        ...         retval2 = watcher.wait_for_lines(triggers, timeout=1)
        >>> print(retval1)
        42
        >>> print(retval2)
        1337
        '''
        return self._wait_for(strings, timeout)

    def _wait_for(self, strings: Dict[str, Any], timeout: int) -> Any:
        '''
        Block execution until one of the `strings` being looked for appears in
        the log file.  Raise a `TimeoutError` if none of the `strings` being
        looked for are found in the log file for `timeout` seconds.
        '''
        if self._wait_function_called:
            raise Exception('wait_for_*() was already called')
        self._wait_function_called = True
        if not self._fd:
            raise Exception('No file to watch')
        deadline = time.time() + timeout
        while time.time() < deadline:
            for line in self._fd.readlines():
                for string, retval in strings.items():
                    if string in line:
                        return retval
            time.sleep(0.1)
        raise TimeoutError('Timeout reached watching {} for {}'
                           .format(self._path, list(strings.keys())))

    def __enter__(self) -> Any:
        self._fd = open(self._path, encoding='utf-8')
        self._seek_on_enter()
        return self

    def _seek_on_enter(self):
        '''
        This method is responsible for setting the file position indicator for
        the file being watched when execution reaches the __enter__() method.
        It is expected to be set differently depending on which `WatchLog`
        subclass is used.  Since the base `WatchLog` class should not be used
        directly, raise an exception upon any attempt of such use.
        '''
        raise NotImplementedError

    def __exit__(self, *_: Any) -> None:
        if not self._wait_function_called:
            raise Exception('wait_for_*() was not called')
        if self._fd:
            self._fd.close()


class WatchLogFromStart(WatchLog):
    '''
    A `WatchLog` subclass which looks for the provided string(s) in the entire
    log file.
    '''
    def _seek_on_enter(self):
        pass


class WatchLogFromHere(WatchLog):
    '''
    A `WatchLog` subclass which only looks for the provided string(s) in the
    portion of the log file which is appended to it after the `with` statement
    is reached.
    '''
    def _seek_on_enter(self):
        self._fd.seek(0, os.SEEK_END)


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

    def watch_log_from_start(self):
        '''
        Return an instance of the `WatchLogFromStart` context manager for this
        `named` instance's log file.
        '''
        return WatchLogFromStart(self._log_file)

    def watch_log_from_here(self):
        '''
        Return an instance of the `WatchLogFromHere` context manager for this
        `named` instance's log file.
        '''
        return WatchLogFromHere(self._log_file)

    def reconfigure(self) -> None:
        '''
        Reconfigure this named `instance` and wait until reconfiguration is
        finished.  Raise an `RNDCException` if reconfiguration fails.
        '''
        with self.watch_log_from_here() as watcher:
            self.rndc('reconfig')
            watcher.wait_for_line('any newly configured zones are now loaded')

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
