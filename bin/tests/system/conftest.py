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
import glob
import logging
import os
from pathlib import Path
import random
import re
import subprocess
from typing import Dict, List, Optional

import pytest


# Configure logging to file on DEBUG level
XDIST_WORKER = os.environ.get("PYTEST_XDIST_WORKER", "")
LOGFILE = f"pytest{f'-{XDIST_WORKER}' if XDIST_WORKER else ''}.log"
logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s %(message)s",
    level=logging.DEBUG,
    filename=LOGFILE,
    filemode="w",
)

FILE_DIR = os.path.abspath(Path(__file__).parent)

ENV_RE = re.compile("([^=]+)=(.*)")


def pytest_configure(config):
    if not XDIST_WORKER:  # run on main instance before any xdist workers are spawned
        logging.debug("compiling required files")
        env = os.environ.copy()
        env["TESTS"] = ""  # disable automake test framework - compile-only
        try:
            proc = subprocess.run(
                "make -e check",
                shell=True,
                check=True,
                cwd=FILE_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
            )
        except subprocess.CalledProcessError as exc:
            logging.debug(exc.stdout)
            logging.error("failed to compile test files: %s", exc)
            raise exc
        logging.debug(proc.stdout)


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Hook that is used to expose test results to session (for use in fixtures)."""
    # execute all other hooks to obtain the report object
    outcome = yield
    report = outcome.get_result()

    # Set the test outcome in session, so we can access it from module-level
    # fixture using nodeid. Note that this hook is called three times: for
    # setup, call and teardown. We only care about the overall result so we
    # merge the results together and preserve the information whether a test
    # passed.
    test_results = {}
    try:
        test_results = getattr(item.session, "test_results")
    except AttributeError:
        setattr(item.session, "test_results", test_results)
    # nodeid may have @loadgroup attached to it when running with xdist's --loadgroup
    nodeid = item.nodeid.split("@")[0]  # ignore the @loadgroup part
    node_result = test_results.get(nodeid)
    if node_result is None or report.outcome != "passed":
        test_results[nodeid] = report.outcome


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


@pytest.fixture(scope="module")
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
            callobj=run_tests_sh,
        )


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(session, config, items):
    for item in items:
        name = _system_test_name_from_path(item.path)
        item.add_marker(pytest.mark.xdist_group(name))


def _system_test_name_from_path(path):
    if path.name.endswith(".py"):
        return path.parent.name
    return path.name


@pytest.fixture(scope="module")
def system_test_name(request):
    return _system_test_name_from_path(request.path)


@pytest.fixture(scope="module")
def system_test_dir(system_test_name, env):
    system_dir = f"{env['TOP_BUILDDIR']}/bin/tests/system"
    return f"{system_dir}/{system_test_name}"


@pytest.fixture(scope="module")
def logger(system_test_name):
    return logging.getLogger(system_test_name)  # TODO consider different name


def _run_script(
    logger,
    system_test_dir: str,
    env,
    interpreter: str,
    script: str,
    args: Optional[List[str]] = None,
):
    if args is None:
        args = []
    path = Path(script)
    if not path.is_absolute():
        # make sure relative paths are always relative to system_dir
        path = Path(system_test_dir).parent / path
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


@pytest.fixture(scope="module")
def shell(env, system_test_dir, logger):
    return partial(_run_script, logger, system_test_dir, env, env["SHELL"])


@pytest.fixture(scope="module")
def perl(env, system_test_dir, logger):
    return partial(_run_script, logger, system_test_dir, env, env["PERL"])


def run_tests_sh(system_test_dir, shell):
    stdout = b""
    try:
        tests_proc = shell(f"{system_test_dir}/tests.sh")
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


@pytest.fixture(scope="module", autouse=True)
def system_test(
    request, env: Dict[str, str], logger, system_test_dir, system_test_name, shell, perl
):
    systest_dir = system_test_dir

    def check_net_interfaces():
        try:
            perl("testsock.pl", ["-p", env["PORT"]])  # TODO python rewrite
        except subprocess.CalledProcessError as exc:
            logger.error("testsock.pl: exited with code %d", exc.returncode)
            pytest.skip("Network interface aliases not set up.")

    def check_prerequisites():
        try:
            shell(f"{testdir}/prereq.sh")
        except FileNotFoundError:
            pass  # prereq.sh is optional
        except subprocess.CalledProcessError:
            pytest.skip("Prerequisites missing.")

    def check_for_log_files():
        log_files = glob.glob(f"{testdir}/**/named.run", recursive=True)
        if log_files:
            logger.debug("found log files: %s", ', '.join(log_files))
            pytest.skip("Unclean test directory (previsouly failed test?).")

    def cleanup_test(initial: bool = True):
        try:
            shell(f"{testdir}/clean.sh")
        except subprocess.CalledProcessError:
            if initial:
                logger.error("cleanup.sh: failed to run initial cleanup")
                pytest.fail("Cleanup script failed.")
            else:
                logger.warning("clean.sh: failed to clean up after test")

    def setup_test():
        try:
            shell(f"{testdir}/setup.sh")
        except FileNotFoundError:
            pass  # setup.sh is optional
        except subprocess.CalledProcessError as exc:
            logger.error("setup.sh: failed to run test setup")
            pytest.fail(f"setup.sh exited with {exc.returncode}")

    def start_servers():
        try:
            perl("start.pl", ["--port", env["PORT"], system_test_name])
        except subprocess.CalledProcessError as exc:
            logger.error("start.pl: failed to start servers")
            pytest.fail(f"start.pl exited with {exc.returncode}")

    def stop_servers():
        try:
            perl("stop.pl", [system_test_name])
        except subprocess.CalledProcessError as exc:
            logger.error("stop.pl: failed to stop servers")
            pytest.fail(f"stop.pl exited with {exc.returncode}")

    def get_test_result():
        """Aggregate test results from all individual tests from this module
        into a single result: failed > skipped > passed."""
        test_results = [
            request.session.test_results[node.nodeid]
            for node in request.node.collect()
            if node.nodeid in request.session.test_results
        ]
        assert len(test_results)
        failed = any([res == "failed" for res in test_results])
        skipped = any([res == "skipped" for res in test_results])
        if failed:
            return "failed"
        if skipped:
            return "skipped"
        assert all([res == "passed" for res in test_results])
        return "passed"

    # FUTURE Always create a tempdir for the test and run it out of tree. It
    # would get rid of the need for explicit cleanup and eliminate the risk of
    # some previous unclean state from affecting the current test.
    testdir = systest_dir

    logger.info(f"test started: {request.node.name}")
    result = "skipped"
    try:
        check_net_interfaces()

        # TODO Do we need --restart option for the runner? IMO not for now (as long
        # as old way of running system tests exists)

        # System tests are meant to be executed from their directory - switch to it.
        old_cwd = os.getcwd()
        os.chdir(testdir)
        logger.debug("changed workdir to: %s", testdir)

        try:
            check_prerequisites()
            check_for_log_files()
            result = "failed"
            cleanup_test(initial=True)
            setup_test()
            try:
                start_servers()
                yield
            finally:
                stop_servers()

            # If we get here, it means no pytest.fail() was called in any the
            # fixture functions (since that would halt execution and only enter
            # "finally" blocks).
            #
            # It means that on a fixture-level, all went well
            # (starting/stopping servers). However, individual test cases might
            # have still failed. Examine these below.
            result = get_test_result()

            if result == "passed":  # TODO implement --keep option
                cleanup_test(initial=False)
        finally:
            os.chdir(old_cwd)
            logger.debug("changed workdir to: %s", old_cwd)
    finally:
        if result == "failed":
            logger.error("test ended (FAILED): %s", request.node.name)
        else:
            # FIXME this may log incorrect results when pytest is interrupted
            logger.info(f"test ended (%s): %s", result.upper(), request.node.name)
