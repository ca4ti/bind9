#!/bin/sh

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

# shellcheck source=conf.sh
. ../conf.sh
# shellcheck source=kasp.sh
. ../kasp.sh

dig_with_opts() {
	$DIG +tcp +noadd +nosea +nostat +nocmd +dnssec -p $PORT "$@"
}


start_time="$(TZ=UTC date +%s)"
status=0
n=0

set_zone "model2.multisigner"
set_policy "model2" "2" "3600"

# Key properties and states.
key_clear        "KEY1"
set_keyrole      "KEY1" "ksk"
set_keylifetime  "KEY1" "0"
set_keyalgorithm "KEY1" "13" "ECDSAP256SHA256" "256"
set_keysigning   "KEY1" "yes"
set_zonesigning  "KEY1" "no"
set_keystate     "KEY1" "GOAL"         "omnipresent"
set_keystate     "KEY1" "STATE_DNSKEY" "omnipresent"
set_keystate     "KEY1" "STATE_KRRSIG" "omnipresent"
set_keystate     "KEY1" "STATE_DS"     "omnipresent"

key_clear        "KEY2"
set_keyrole      "KEY2" "zsk"
set_keylifetime  "KEY2" "0"
set_keyalgorithm "KEY2" "13" "ECDSAP256SHA256" "256"
set_keysigning   "KEY2" "no"
set_zonesigning  "KEY2" "yes"
set_keystate     "KEY2" "GOAL"         "omnipresent"
set_keystate     "KEY2" "STATE_DNSKEY" "omnipresent"
set_keystate     "KEY2" "STATE_ZRRSIG" "omnipresent"

key_clear "KEY3"
key_clear "KEY4"

set_keytimes_model2() {
	# The first KSK is immediately published and activated.
	created=$(key_get KEY1 CREATED)
	set_keytime "KEY1" "PUBLISHED"   "${created}"
        set_keytime "KEY1" "ACTIVE"      "${created}"
        set_keytime "KEY1" "SYNCPUBLISH" "${created}"

        # The first ZSKs are immediately published and activated.
        created=$(key_get KEY2 CREATED)
        set_keytime "KEY2" "PUBLISHED" "${created}"
        set_keytime "KEY2" "ACTIVE"    "${created}"
}

set_server "ns3" "10.53.0.3"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_model2
check_keytimes
check_apex
dnssec_verify

set_server "ns4" "10.53.0.4"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_model2
check_keytimes
check_apex
dnssec_verify


#
# Update DNSKEY RRset.
#

# Check that the ZSKs from the other provider are published.
zsks_are_published() {
	dig_with_opts "$ZONE" "@${SERVER}" DNSKEY > "dig.out.$DIR.test$n" || return 1
	# We should have two ZSKs.
	lines=$(grep "256 3 13" dig.out.$DIR.test$n | wc -l)
	test "$lines" -eq 2 || return 1
	# And one KSK.
	lines=$(grep "257 3 13" dig.out.$DIR.test$n | wc -l)
	test "$lines" -eq 1 || return 1
}

n=$((n+1))
echo_i "update zone ${ZONE} at ns3 with ZSK from provider ns4"
ret=0
set_server "ns3" "10.53.0.3"
(
echo zone "${ZONE}"
echo server "${SERVER}" "${PORT}"
echo update add $(cat "ns4/${ZONE}.zsk")
echo send
) | $NSUPDATE
echo_i "check zone ${ZONE} DNSKEY RRset after update ($n)"
retry_quiet 10 zsks_are_published || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))
# Verify again.
dnssec_verify


n=$((n+1))
echo_i "update zone ${ZONE} at ns4 with ZSK from provider ns3"
ret=0
set_server "ns4" "10.53.0.4"
(
echo zone "${ZONE}"
echo server "${SERVER}" "${PORT}"
echo update add $(cat "ns3/${ZONE}.zsk")
echo send
) | $NSUPDATE
echo_i "check zone ${ZONE} DNSKEY RRset after update ($n)"
retry_quiet 10 zsks_are_published || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))
# Verify again.
dnssec_verify


#
# Update CDNSKEY RRset.
#

# Check that the CDNSKEY from both providers are published.
records_published() {
	_rrtype=$1
	_expect=$2

	dig_with_opts "$ZONE" "@${SERVER}" "${_rrtype}" > "dig.out.$DIR.test$n" || return 1
	lines=$(awk -v rt="${_rrtype}" '$4 == rt {print}' dig.out.$DIR.test$n | wc -l)
	test "$lines" -eq "$_expect" || return 1
}

# Retrieve CDNSKEY records from the other provider.
dig_with_opts ${ZONE} @10.53.0.3 CDNSKEY > dig.out.ns3.cdnskey
awk '$4 == "CDNSKEY" {print}' dig.out.ns3.cdnskey > cdnskey.ns3
dig_with_opts ${ZONE} @10.53.0.4 CDNSKEY > dig.out.ns4.cdnskey
awk '$4 == "CDNSKEY" {print}' dig.out.ns4.cdnskey > cdnskey.ns4

set_server "ns3" "10.53.0.3"

# Initially there should be one CDNSKEY.
n=$((n+1))
echo_i "check zone ${ZONE} ${DIR} initially CDNSKEY ($n)"
ret=0
retry_quiet 10 records_published CDNSKEY 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "update zone ${ZONE} at ns3 with CDNSKEY from provider ns4"
ret=0
(
echo zone "${ZONE}"
echo server "${SERVER}" "${PORT}"
echo update add $(cat "cdnskey.ns4")
echo send
) | $NSUPDATE
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Now there should be two CDNSKEY records (we test that BIND does not
# skip it during DNSSEC maintenance).
n=$((n+1))
echo_i "check zone ${ZONE} CDNSKEY RRset after update ($n)"
ret=0
retry_quiet 10 records_published CDNSKEY 2 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

set_server "ns4" "10.53.0.4"

# Initially there should be one CDNSKEY.
n=$((n+1))
echo_i "check zone ${ZONE} ${DIR} initially CDNSKEY ($n)"
ret=0
retry_quiet 10 records_published CDNSKEY 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "update zone ${ZONE} at ns4 with CDNSKEY from provider ns3"
ret=0
(
echo zone "${ZONE}"
echo server "${SERVER}" "${PORT}"
echo update add $(cat "cdnskey.ns3")
echo send
) | $NSUPDATE
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Now there should be two CDNSKEY records (we test that BIND does not
# skip it during DNSSEC maintenance).
n=$((n+1))
echo_i "check zone ${ZONE} CDNSKEY RRset after update ($n)"
ret=0
retry_quiet 10 records_published CDNSKEY 2 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))


#
# Update CDS RRset.
#

# Retrieve CDS records from the other provider.
dig_with_opts ${ZONE} @10.53.0.3 CDS > dig.out.ns3.cds
awk '$4 == "CDS" {print}' dig.out.ns3.cds > cds.ns3
dig_with_opts ${ZONE} @10.53.0.4 CDS > dig.out.ns4.cds
awk '$4 == "CDS" {print}' dig.out.ns4.cds > cds.ns4

n=$((n+1))
echo_i "update zone ${ZONE} at ns3 with CDS from provider ns4"
ret=0
set_server "ns3" "10.53.0.3"
# Initially there should be one CDS.
retry_quiet 10 records_published CDS 1 || ret=1
(
echo zone "${ZONE}"
echo server "${SERVER}" "${PORT}"
echo update add $(cat "cds.ns4")
echo send
) | $NSUPDATE
# Now there should be two CDS records (we test that BIND does not
# skip it during DNSSEC maintenance).
echo_i "check zone ${ZONE} CDS RRset after update ($n)"
retry_quiet 10 records_published CDS 2 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))


n=$((n+1))
echo_i "update zone ${ZONE} at ns4 with CDS from provider ns3"
ret=0
set_server "ns4" "10.53.0.4"
# Initially there should be one CDS.
retry_quiet 10 records_published CDS 1 || ret=1
(
echo zone "${ZONE}"
echo server "${SERVER}" "${PORT}"
echo update add $(cat "cds.ns3")
echo send
) | $NSUPDATE
# Now there should be two CDS records (we test that BIND does not
# skip it during DNSSEC maintenance).
echo_i "check zone ${ZONE} CDS RRset after update ($n)"
retry_quiet 10 records_published CDS 2 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
