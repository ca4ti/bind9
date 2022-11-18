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

from functools import partial
import logging
import os
from pathlib import Path
import random
import re
import subprocess
from typing import Dict, List, Optional

import pytest


# Configure logging to file on DEBUG level
logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s %(message)s",
    level=logging.DEBUG,
    filename="pytest.log",
    filemode="w",
)

FILE_DIR = os.path.abspath(Path(__file__).parent)

ENV_RE = re.compile("([^=]+)=(.*)")


@pytest.fixture(scope="session")
def conf_env():
    """Common environment variables for running tests."""
    # FUTURE Define all variables in pytest only. This is currently not done in
    # order to support the legacy way of running system tests without having to
    # duplicate the env variables both here and in conf.sh.

    def parse_env(env):
        """Parse the POSIX env format into Python dictionary."""
        out = {}
        for line in env.decode("utf-8").splitlines():
            match = ENV_RE.match(line)
            if match:
                out[match.groups()[0]] = match.groups()[1]
        return out

    def _get_env(cmd):
        try:
            proc = subprocess.run(
                [cmd],
                shell=True,
                check=True,
                cwd=FILE_DIR,
                stdout=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as exc:
            logging.error("failed to get shell env: %s", exc)
            raise exc
        return parse_env(proc.stdout)

    pure_env = _get_env("env")
    mod_env = _get_env(". ./conf.sh && env")
    conf_env = {
        name: value
        for name, value in mod_env.items()
        if (name not in pure_env or value != pure_env[name])
    }
    logging.debug("conf.sh env: %s", conf_env)
    return conf_env


@pytest.fixture
def env(conf_env, ports):
    test_env = conf_env.copy()
    test_env.update(ports)
    test_env["builddir"] = f"{test_env['TOP_BUILDDIR']}/bin/tests/system"
    test_env["srcdir"] = f"{test_env['TOP_SRCDIR']}/bin/tests/system"
    return test_env


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


def pytest_collect_file(parent, file_path):
    if file_path.name == "tests.sh":
        return ShellSystemTest.from_parent(parent, path=file_path.parent)


class ShellSystemTest(pytest.Module):
    def collect(self):
        yield pytest.Function.from_parent(
            name=f"tests_sh",
            parent=self,
            callobj=partial(run_system_test, self.path.name),
        )

# TODO turn this into setup/cleanup directory level (module scope) fixture &
# run "tests.sh" and pytests as separate test cases  (function scope)
def run_system_test(name: str, env: Dict[str, str]):
    system_dir = f"{env['TOP_BUILDDIR']}/bin/tests/system"
    systest_dir = f"{system_dir}/{name}"

    logger = logging.getLogger(name)

    def _run_script(
        interpreter: str,
        script: str,
        args: Optional[List[str]] = None,
    ):
        if args is None:
            args = []
        path = Path(script)
        if not path.is_absolute():
            # make sure relative paths are always relative to system_dir
            path = Path(system_dir) / path
        script = str(path)
        cwd = os.getcwd()
        if not path.exists():
            raise FileNotFoundError(f"script {script} not found in {cwd}")
        logger.debug("running script: %s %s %s", interpreter, script, " ".join(args))
        logger.debug("  workdir: %s", cwd)
        stdout = b""
        returncode = 1
        try:
            proc = subprocess.run(
                [interpreter, script] + args,
                env=env,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as exc:
            stdout = exc.stdout
            returncode = exc.returncode
            raise exc
        else:
            stdout = proc.stdout
            returncode = proc.returncode
        finally:
            if stdout:
                for line in stdout.decode().splitlines():
                    logger.debug("    %s", line)
            logger.debug("  exited with %d", returncode)
        return proc

    perl = partial(_run_script, env["PERL"])
    shell = partial(_run_script, env["SHELL"])

    def check_net_interfaces():
        try:
            perl("testsock.pl", ["-p", env["PORT"]])  # TODO python rewrite
        except subprocess.CalledProcessError as exc:
            logger.error("testsock.pl: exited with code %d", exc.returncode)
            logger.info("SKIPPED")
            pytest.skip("Network interface aliases not set up.")

    def check_prerequisites():
        try:
            shell(f"{testdir}/prereq.sh")
        except FileNotFoundError:
            pass  # prereq.sh is optional
        except subprocess.CalledProcessError:
            logger.info("test ended (SKIPPED)")
            pytest.skip("Prerequisites missing.")

    def cleanup_test(initial: bool = True):
        try:
            shell(f"{testdir}/clean.sh")
        except subprocess.CalledProcessError:
            if initial:
                logger.error("cleanup.sh: failed to run initial cleanup")
                pytest.skip("Cleanup script failed.")
            else:
                logger.warning("clean.sh: failed to clean up after test")

    def setup_test():
        try:
            shell(f"{testdir}/setup.sh")
        except FileNotFoundError:
            pass  # setup.sh is optional
        except subprocess.CalledProcessError:
            logger.error("setup.sh: failed to run test setup")
            raise

    def start_servers():
        try:
            perl("start.pl", ["--port", env["PORT"], name])
        except subprocess.CalledProcessError:
            logger.error("start.pl: failed to start servers")
            raise

    def stop_servers():
        try:
            perl("stop.pl", [name])
        except subprocess.CalledProcessError:
            logger.warning("stop.pl: failed to stop servers")

    def run_tests_sh():
        stdout = b""
        try:
            tests_proc = shell(f"{testdir}/tests.sh")
        except subprocess.CalledProcessError as exc:
            stdout = exc.stdout
            raise
        else:
            stdout = tests_proc.stdout
        finally:
            if stdout:
                # Print is called here in order to integrate with pytest
                # output. Combined with pytests's -rA option (our default from
                # pytest.ini), it will display the log from each test for both
                # successessful and failed tests.
                print(stdout.decode().strip())

    # FUTURE Always create a tempdir for the test and run it out of tree. It
    # would get rid of the need for explicit cleanup and eliminate the risk of
    # some previous unclean state from affecting the current test.
    testdir = systest_dir

    logger.info("test started")
    check_net_interfaces()

    # TODO Do we need --restart option for the runner? IMO not for now (as long
    # as old way of running system tests exists)

    # System tests are meant to be executed from their directory - switch to it.
    old_cwd = os.getcwd()
    os.chdir(testdir)
    logging.debug("changed workdir to: %s", testdir)

    try:
        check_prerequisites()
        cleanup_test(initial=True)
        passed = False
        try:
            setup_test()
            start_servers()

            # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            # TODO everything above should be a directory-level fixture setup
            #
            run_tests_sh()
            #
            # TODO everything below should be a directory-level fixture cleanup
            # vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

            # TODO run existing pytests once directory-level fixtures are supported
            # Existing pytests assume default unmodified named.conf, i.e. the same
            # as at the start of tests.sh, not after tests.sh is finished. This
            # might clash with the concept of directory-level fixtures for
            # setup/cleanup and running all the tests (both tests.sh and individual
            # pytests) in between.

            passed = True
        finally:  # TODO run this cleanup on KeyboardInterrupt from pytest
            stop_servers()
            if passed:  # TODO implement --keep option
                cleanup_test(initial=False)

            # TODO get_core_dumps

            if passed:
                logger.info("test ended (PASSED)")
            else:
                logger.error("test ended (FAILED)")
    finally:
        os.chdir(old_cwd)
        logger.debug("changed workdir to: %s", testdir)
