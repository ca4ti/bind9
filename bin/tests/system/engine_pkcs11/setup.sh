#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck source=conf.sh
. ../conf.sh

set -e

softhsm2-util --init-token --free --pin 1234 --so-pin 1234 --label "softhsm2-engine_pkcs11" | awk '/^The token has been initialized and is reassigned to slot/ { print $NF }'

printf '%s' "${HSMPIN:-1234}" > ns1/pin
PWD=$(pwd)

copy_setports ns1/named.conf.in ns1/named.conf

keygen() {
	type="$1"
	bits="$2"
	zone="$3"
	id="$4"

	label="${id}-${zone}"
	p11id=$(echo "${label}" | sha1sum - | awk '{print $1}')
	pkcs11-tool --module $SOFTHSM2_MODULE --token-label "softhsm2-engine_pkcs11" -l -k --key-type $type:$bits --label "${label}" --id "${p11id//$'\n'/}" --pin $(cat $PWD/ns1/pin) > pkcs11-tool.out.$zone.$id || return 1
}

keyfromlabel() {
        alg="$1"
        zone="$2"
        id="$3"
	dir="$4"
        shift 4

	$KEYFRLAB -K $dir -E pkcs11 -a $alg -l "token=softhsm2-engine_pkcs11;object=${id}-${zone};pin-source=$PWD/ns1/pin" "$@" $zone >> keyfromlabel.out.$zone.$id 2>> /dev/null || return 1
	cat keyfromlabel.out.$zone.$id
}


# Setup ns1.
dir="ns1"
infile="${dir}/template.db.in"
for algtypebits in rsasha256:rsa:2048 rsasha512:rsa:2048 \
		   ecdsap256sha256:EC:prime256v1 ecdsap384sha384:EC:prime384v1
		   # Edwards curves are not yet supported by OpenSC
		   # ed25519:EC:edwards25519 ed448:EC:edwards448
do
	alg=$(echo "$algtypebits" | cut -f 1 -d :)
	type=$(echo "$algtypebits" | cut -f 2 -d :)
	bits=$(echo "$algtypebits" | cut -f 3 -d :)

	tld="example"
	if $SHELL ../testcrypto.sh $alg; then
		zone="$alg.$tld"
		zonefile="zone.$alg.$tld.db"
		ret=0

		echo_i "Generate keys $alg $type:$bits for zone $zone"
		keygen $type $bits $zone enginepkcs11-zsk || ret=1
		keygen $type $bits $zone enginepkcs11-ksk || ret=1
		test "$ret" -eq 0 || exit 1

		echo_i "Get ZSK $alg $zone $type:$bits"
		zsk1=$(keyfromlabel $alg $zone enginepkcs11-zsk $dir)
		test -z "$zsk1" && exit 1

		echo_i "Get KSK $alg $zone $type:$bits"
		ksk1=$(keyfromlabel $alg $zone enginepkcs11-ksk $dir -f KSK)
		test -z "$ksk1" && exit 1

		(
			cd $dir
			zskid1=$(keyfile_to_key_id $zsk1)
			kskid1=$(keyfile_to_key_id $ksk1)
			echo "$zskid1" > $zone.zskid1
			echo "$kskid1" > $zone.kskid1
		)

		echo_i "Sign zone with $ksk1 $zsk1"
		cat "$infile" "${dir}/${ksk1}.key" "${dir}/${zsk1}.key" > "${dir}/${zonefile}"
		$SIGNER -K $dir -E pkcs11 -S -a -g -O full -o "$zone" "${dir}/${zonefile}" > signer.out.$zone || ret=1
		test "$ret" -eq 0 || exit 1

		echo_i "Generate successor keys $alg $type:$bits for zone $zone"
		keygen $type $bits $zone enginepkcs11-zsk2 || ret=1
		keygen $type $bits $zone enginepkcs11-ksk2 || ret=1
		test "$ret" -eq 0 || exit 1

		echo_i "Get ZSK $alg $id-$zone $type:$bits"
		zsk2=$(keyfromlabel $alg $zone enginepkcs11-zsk2 $dir)
		test -z "$zsk2" && exit 1

		echo_i "Get KSK $alg $id-$zone $type:$bits"
		ksk2=$(keyfromlabel $alg $zone enginepkcs11-ksk2 $dir -f KSK)
		test -z "$ksk2" && exit 1

		(
			cd $dir
			zskid2=$(keyfile_to_key_id $zsk2)
			kskid2=$(keyfile_to_key_id $ksk2)
			echo "$zskid2" > $zone.zskid2
			echo "$kskid2" > $zone.kskid2
			cp "${zsk2}.key" "${zsk2}.zsk2"
			cp "${ksk2}.key" "${ksk2}.ksk2"
		)

		echo_i "Add zone $alg.kasp to named.conf"
		cp $infile ${dir}/zone.${alg}.kasp.db

		echo_i "Add zone $zone to named.conf"
		cat >> "${dir}/named.conf" <<EOF
zone "$zone" {
	type primary;
	file "${zonefile}.signed";
	allow-update { any; };
};

dnssec-policy "$alg" {
	keys {
		ksk key-store "hsm" lifetime unlimited algorithm ${alg};
		zsk key-store "pin" lifetime unlimited algorithm ${alg};
	};
};

zone "${alg}.kasp" {
	type primary;
	file "zone.${alg}.kasp.db";
	dnssec-policy "$alg";
	allow-update { any; };
};

EOF
        fi
done
