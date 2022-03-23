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

from typing import NamedTuple, Tuple

import os
import subprocess
import sys
import time

import pytest

pytest.importorskip('dns', minversion='2.0.0')
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype


def has_signed_apex_nsec(zone, response):
    has_nsec = False
    has_rrsig = False

    ttl = 300
    nextname = "a."
    types = "NS SOA RRSIG NSEC DNSKEY CDS CDNSKEY"
    match = "{0} {1} IN NSEC {2}{0} {3}".format(zone, ttl, nextname, types)
    sig = "{0} {1} IN RRSIG NSEC 13 2 300".format(zone, ttl)

    for rr in response.answer:
        if match in rr.to_text():
            has_nsec = True
        if sig in rr.to_text():
            has_rrsig = True

    if not has_nsec:
        print("error: missing apex NSEC record in response")
    if not has_rrsig:
        print("error: missing NSEC signature in response")

    return has_nsec and has_rrsig


def do_query(server, qname, qtype, tcp=False):
    query = dns.message.make_query(qname, qtype, use_edns=True,
                                   want_dnssec=True)
    try:
        if tcp:
            response = dns.query.tcp(query, server.ip, timeout=3,
                                     port=server.ports.dns)
        else:
            response = dns.query.udp(query, server.ip, timeout=3,
                                     port=server.ports.dns)
    except dns.exception.Timeout:
        print("error: query timeout for query {} {} to {}".format(
              qname, qtype, server.ip))
        return None

    return response


def verify_zone(zone, transfer):
    verify = os.getenv("VERIFY")
    assert verify is not None

    filename = "{}out".format(zone)
    with open(filename, 'w', encoding='utf-8') as file:
        for rr in transfer.answer:
            file.write(rr.to_text())
            file.write('\n')

    # dnssec-verify command with default arguments.
    verify_cmd = [verify, "-z", "-o", zone, filename]

    verifier = subprocess.run(verify_cmd, capture_output=True, check=True)

    if verifier.returncode != 0:
        print("error: dnssec-verify {} failed".format(zone))
        sys.stderr.buffer.write(verifier.stderr)

    return verifier.returncode == 0


def read_statefile(server, zone):
    addr = server.ip
    count = 0
    keyid = 0
    state = {}

    response = do_query(server, zone, "DS", tcp=True)
    if not isinstance(response, dns.message.Message):
        print("error: no response for {} DS from {}".format(zone, addr))
        return {}

    if response.rcode() == dns.rcode.NOERROR:
        # fetch key id from response.
        for rr in response.answer:
            if rr.match(dns.name.from_text(zone), dns.rdataclass.IN,
                        dns.rdatatype.DS, dns.rdatatype.NONE):
                if count == 0:
                    keyid = list(dict(rr.items).items())[0][0].key_tag
                count += 1

        if count != 1:
            print("error: expected a single DS in response for {} from {},"
                  "got {}".format(zone, addr, count))
            return {}
    else:
        print("error: {} response for {} DNSKEY from {}".format(
              dns.rcode.to_text(response.rcode()), zone, addr))
        return {}

    filename = "ns9/K{}+013+{:05d}.state".format(zone, keyid)
    print("read state file {}".format(filename))

    try:
        with open(filename, 'r', encoding='utf-8') as file:
            for line in file:
                if line.startswith(';'):
                    continue
                key, val = line.strip().split(':', 1)
                state[key.strip()] = val.strip()

    except FileNotFoundError:
        # file may not be written just yet.
        return {}

    return state


def zone_check(server, zone):
    addr = server.ip

    # wait until zone is fully signed.
    signed = False
    for _ in range(10):
        response = do_query(server, zone, 'NSEC')
        if not isinstance(response, dns.message.Message):
            print("error: no response for {} NSEC from {}".format(zone, addr))
        elif response.rcode() == dns.rcode.NOERROR:
            signed = has_signed_apex_nsec(zone, response)
        else:
            print("error: {} response for {} NSEC from {}".format(
                dns.rcode.to_text(response.rcode()), zone, addr))

        if signed:
            break

        time.sleep(1)

    assert signed

    # check if zone if DNSSEC valid.
    verified = False
    transfer = do_query(server, zone, 'AXFR', tcp=True)
    if not isinstance(transfer, dns.message.Message):
        print("error: no response for {} AXFR from {}".format(zone, addr))
    elif transfer.rcode() == dns.rcode.NOERROR:
        verified = verify_zone(zone, transfer)
    else:
        print("error: {} response for {} AXFR from {}".format(
           dns.rcode.to_text(transfer.rcode()), zone, addr))

    assert verified


def keystate_check(server, zone, key):
    val = 0
    deny = False

    search = key
    if key.startswith('!'):
        deny = True
        search = key[1:]

    for _ in range(10):
        state = read_statefile(server, zone)
        try:
            val = state[search]
        except KeyError:
            pass

        if not deny and val != 0:
            break
        if deny and val == 0:
            break

        time.sleep(1)

    if deny:
        assert val == 0
    else:
        assert val != 0


class CheckDSTest(NamedTuple):
    zone: str
    logs_to_wait_for: Tuple[str, ...]
    expected_parent_state: str


dspublished_tests = [
    # DS correctly published in parent.
    CheckDSTest(zone='dspublished.checkds.',
                logs_to_wait_for=('DS response from 10.53.0.2',),
                expected_parent_state='DSPublish'),
    # DS correctly published in parent (reference to parental-agent).
    CheckDSTest(zone='reference.checkds.',
                logs_to_wait_for=('DS response from 10.53.0.2',),
                expected_parent_state='DSPublish'),
    # DS not published in parent.
    CheckDSTest(zone='missing-dspublished.checkds.',
                logs_to_wait_for=('empty DS response from 10.53.0.5',),
                expected_parent_state='!DSPublish'),
    # Badly configured parent.
    CheckDSTest(zone='bad-dspublished.checkds.',
                logs_to_wait_for=('bad DS response from 10.53.0.6',),
                expected_parent_state='!DSPublish'),
    # TBD: DS published in parent, but bogus signature.

    # DS correctly published in all parents.
    CheckDSTest(zone='multiple-dspublished.checkds.',
                logs_to_wait_for=('DS response from 10.53.0.2',
                                  'DS response from 10.53.0.4',),
                expected_parent_state='DSPublish'),
    # DS published in only one of multiple parents.
    CheckDSTest(zone='incomplete-dspublished.checkds.',
                logs_to_wait_for=('DS response from 10.53.0.2',
                                  'DS response from 10.53.0.4',
                                  'empty DS response from 10.53.0.5',),
                expected_parent_state='!DSPublish'),
    # One of the parents is badly configured.
    CheckDSTest(zone='bad2-dspublished.checkds.',
                logs_to_wait_for=('DS response from 10.53.0.2',
                                  'DS response from 10.53.0.4',
                                  'bad DS response from 10.53.0.6',),
                expected_parent_state='!DSPublish'),
    # TBD: DS published in all parents, but one has bogus signature.

    # TBD: Check with TSIG

    # TBD: Check with TLS

]


dswithdrawn_tests = [
    # DS correctly published in single parent.
    CheckDSTest(zone='dswithdrawn.checkds.',
                logs_to_wait_for=('empty DS response from 10.53.0.5',),
                expected_parent_state='DSRemoved'),
    # DS not withdrawn from parent.
    CheckDSTest(zone='missing-dswithdrawn.checkds.',
                logs_to_wait_for=('DS response from 10.53.0.2',),
                expected_parent_state='!DSRemoved'),
    # Badly configured parent.
    CheckDSTest(zone='bad-dswithdrawn.checkds.',
                logs_to_wait_for=('bad DS response from 10.53.0.6',),
                expected_parent_state='!DSRemoved'),
    # TBD: DS published in parent, but bogus signature.

    # DS correctly withdrawn from all parents.
    CheckDSTest(zone='multiple-dswithdrawn.checkds.',
                logs_to_wait_for=('empty DS response from 10.53.0.5',
                                  'empty DS response from 10.53.0.7',),
                expected_parent_state='DSRemoved'),
    # DS withdrawn from only one of multiple parents.
    CheckDSTest(zone='incomplete-dswithdrawn.checkds.',
                logs_to_wait_for=('DS response from 10.53.0.2',
                                  'empty DS response from 10.53.0.5',
                                  'empty DS response from 10.53.0.7',),
                expected_parent_state='!DSRemoved'),
    # One of the parents is badly configured.
    CheckDSTest(zone='bad2-dswithdrawn.checkds.',
                logs_to_wait_for=('empty DS response from 10.53.0.5',
                                  'empty DS response from 10.53.0.7',
                                  'bad DS response from 10.53.0.6',),
                expected_parent_state='!DSRemoved'),
    # TBD: DS withdrawn from all parents, but one has bogus signature.

]


@pytest.mark.parametrize('params', dspublished_tests + dswithdrawn_tests,
                         ids=lambda t: t.zone)
def test_checkds(servers, params):
    # Wait until the provided zone is signed and then verify its DNSSEC data.
    zone_check(servers['ns9'], params.zone)

    # Wait until all the expected log lines are found in the log file for the
    # provided server.
    log_prefix = 'zone {zone_name}/IN (signed): checkds: '
    for log_string in params.logs_to_wait_for:
        log_format = log_prefix + log_string
        log_line = log_format.format(zone_name=params.zone.rstrip('.'))
        with servers['ns9'].watch_log_from_start() as watcher:
            watcher.wait_for_line(log_line)

    # Check whether key states on the parent server provided match
    # expectations.
    keystate_check(servers['ns2'], params.zone, params.expected_parent_state)
