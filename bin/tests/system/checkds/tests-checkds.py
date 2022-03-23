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


def test_checkds_dspublished(named_port, servers):
    # DS correctly published in parent.
    zone_check(servers['ns9'], "dspublished.checkds.")
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone dspublished.checkds/IN (signed): checkds: "
                "DS response from 10.53.0.2")
        watcher.wait_for_line(line)
    keystate_check(servers['ns2'], "dspublished.checkds.", "DSPublish")

    # DS correctly published in parent (reference to parental-agent).
    zone_check(servers['ns9'], "reference.checkds.")
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone reference.checkds/IN (signed): checkds: "
                "DS response from 10.53.0.2")
        watcher.wait_for_line(line)
    keystate_check(servers['ns2'], "reference.checkds.", "DSPublish")

    # DS not published in parent.
    zone_check(servers['ns9'], "missing-dspublished.checkds.")
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone missing-dspublished.checkds/IN (signed): checkds: "
                "empty DS response from 10.53.0.5")
        watcher.wait_for_line(line)
    keystate_check(servers['ns2'], "missing-dspublished.checkds.", "!DSPublish")

    # Badly configured parent.
    zone_check(servers['ns9'], "bad-dspublished.checkds.")
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone bad-dspublished.checkds/IN (signed): checkds: "
                "bad DS response from 10.53.0.6")
        watcher.wait_for_line(line)
    keystate_check(servers['ns2'], "bad-dspublished.checkds.", "!DSPublish")

    # TBD: DS published in parent, but bogus signature.

    # DS correctly published in all parents.
    zone_check(servers['ns9'], "multiple-dspublished.checkds.")
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone multiple-dspublished.checkds/IN (signed): checkds: "
                "DS response from 10.53.0.2")
        watcher.wait_for_line(line)
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone multiple-dspublished.checkds/IN (signed): checkds: "
                "DS response from 10.53.0.4")
        watcher.wait_for_line(line)
    keystate_check(servers['ns2'], "multiple-dspublished.checkds.", "DSPublish")

    # DS published in only one of multiple parents.
    zone_check(servers['ns9'], "incomplete-dspublished.checkds.")
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone incomplete-dspublished.checkds/IN (signed): checkds: "
                "DS response from 10.53.0.2")
        watcher.wait_for_line(line)
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone incomplete-dspublished.checkds/IN (signed): checkds: "
                "DS response from 10.53.0.4")
        watcher.wait_for_line(line)
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone incomplete-dspublished.checkds/IN (signed): checkds: "
                "empty DS response from 10.53.0.5")
        watcher.wait_for_line(line)
    keystate_check(servers['ns2'], "incomplete-dspublished.checkds.", "!DSPublish")

    # One of the parents is badly configured.
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone bad2-dspublished.checkds/IN (signed): checkds: "
                "DS response from 10.53.0.2")
        watcher.wait_for_line(line)
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone bad2-dspublished.checkds/IN (signed): checkds: "
                "DS response from 10.53.0.4")
        watcher.wait_for_line(line)
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone bad2-dspublished.checkds/IN (signed): checkds: "
                "bad DS response from 10.53.0.6")
        watcher.wait_for_line(line)
    keystate_check(servers['ns2'], "bad2-dspublished.checkds.", "!DSPublish")

    # TBD: DS published in all parents, but one has bogus signature.

    # TBD: Check with TSIG

    # TBD: Check with TLS


def test_checkds_dswithdrawn(named_port, servers):
    # DS correctly published in single parent.
    zone_check(servers['ns9'], "dswithdrawn.checkds.")
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone dswithdrawn.checkds/IN (signed): checkds: "
                "empty DS response from 10.53.0.5")
        watcher.wait_for_line(line)
    keystate_check(servers['ns2'], "dswithdrawn.checkds.", "DSRemoved")

    # DS not withdrawn from parent.
    zone_check(servers['ns9'], "missing-dswithdrawn.checkds.")
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone missing-dswithdrawn.checkds/IN (signed): checkds: "
                "DS response from 10.53.0.2")
        watcher.wait_for_line(line)
    keystate_check(servers['ns2'], "missing-dswithdrawn.checkds.", "!DSRemoved")

    # Badly configured parent.
    zone_check(servers['ns9'], "bad-dswithdrawn.checkds.")
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone bad-dswithdrawn.checkds/IN (signed): checkds: "
                "bad DS response from 10.53.0.6")
        watcher.wait_for_line(line)
    keystate_check(servers['ns2'], "bad-dswithdrawn.checkds.", "!DSRemoved")

    # TBD: DS published in parent, but bogus signature.

    # DS correctly withdrawn from all parents.
    zone_check(servers['ns9'], "multiple-dswithdrawn.checkds.")
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone multiple-dswithdrawn.checkds/IN (signed): checkds: "
                "empty DS response from 10.53.0.5")
        watcher.wait_for_line(line)
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone multiple-dswithdrawn.checkds/IN (signed): checkds: "
                "empty DS response from 10.53.0.7")
        watcher.wait_for_line(line)
    keystate_check(servers['ns2'], "multiple-dswithdrawn.checkds.", "DSRemoved")

    # DS withdrawn from only one of multiple parents.
    zone_check(servers['ns9'], "incomplete-dswithdrawn.checkds.")
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone incomplete-dswithdrawn.checkds/IN (signed): checkds: "
                "DS response from 10.53.0.2")
        watcher.wait_for_line(line)
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone incomplete-dswithdrawn.checkds/IN (signed): checkds: "
                "empty DS response from 10.53.0.5")
        watcher.wait_for_line(line)
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone incomplete-dswithdrawn.checkds/IN (signed): checkds: "
                "empty DS response from 10.53.0.7")
        watcher.wait_for_line(line)
    keystate_check(servers['ns2'], "incomplete-dswithdrawn.checkds.", "!DSRemoved")

    # One of the parents is badly configured.
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone bad2-dswithdrawn.checkds/IN (signed): checkds: "
                "empty DS response from 10.53.0.5")
        watcher.wait_for_line(line)
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone bad2-dswithdrawn.checkds/IN (signed): checkds: "
                "empty DS response from 10.53.0.7")
        watcher.wait_for_line(line)
    with servers['ns9'].watch_log_from_start() as watcher:
        line = ("zone bad2-dswithdrawn.checkds/IN (signed): checkds: "
                "bad DS response from 10.53.0.6")
        watcher.wait_for_line(line)
    keystate_check(servers['ns2'], "bad2-dswithdrawn.checkds.", "!DSRemoved")

    # TBD: DS withdrawn from all parents, but one has bogus signature.
