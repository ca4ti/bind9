/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include <isc/attributes.h>
#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/region.h>
#include <isc/string.h>
#include <isc/util.h>

#include <pk11/site.h>

#include <dns/dnssec.h>
#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/log.h>
#include <dns/name.h>
#include <dns/rdataclass.h>
#include <dns/result.h>
#include <dns/secalg.h>

#include <dst/dst.h>

#if USE_PKCS11
#include <pk11/result.h>
#endif /* if USE_PKCS11 */

#include "dnssectool.h"

#define MAX_RSA 4096 /* should be long enough... */

const char *program = "dnssec-keyfromlabel";

ISC_NORETURN static void
usage(void);

static void
usage(void) {
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "    %s -l label [options] name\n\n", program);
	fprintf(stderr, "Version: %s\n", PACKAGE_VERSION);
	fprintf(stderr, "Required options:\n");
	fprintf(stderr, "    -l label: label of the key pair\n");
	fprintf(stderr, "    name: owner of the key\n");
	fprintf(stderr, "Other options:\n");
	fprintf(stderr, "    -a algorithm: \n"
			"        DH | RSASHA1 |\n"
			"        NSEC3RSASHA1 |\n"
			"        RSASHA256 | RSASHA512 |\n"
			"        ECDSAP256SHA256 | ECDSAP384SHA384 |\n"
			"        ED25519 | ED448\n");
	fprintf(stderr, "    -3: use NSEC3-capable algorithm\n");
	fprintf(stderr, "    -c class (default: IN)\n");
	fprintf(stderr, "    -E <engine>:\n");
#if USE_PKCS11
	fprintf(stderr,
		"        path to PKCS#11 provider library "
		"(default is %s)\n",
		PK11_LIB_LOCATION);
#else  /* if USE_PKCS11 */
	fprintf(stderr, "        name of an OpenSSL engine to use\n");
#endif /* if USE_PKCS11 */
	fprintf(stderr, "    -f keyflag: KSK | REVOKE\n");
	fprintf(stderr, "    -K directory: directory in which to place "
			"key files\n");
	fprintf(stderr, "    -k: generate a TYPE=KEY key\n");
	fprintf(stderr, "    -L ttl: default key TTL\n");
	fprintf(stderr, "    -n nametype: ZONE | HOST | ENTITY | USER | "
			"OTHER\n");
	fprintf(stderr, "        (DNSKEY generation defaults to ZONE\n");
	fprintf(stderr, "    -p protocol: default: 3 [dnssec]\n");
	fprintf(stderr, "    -t type: "
			"AUTHCONF | NOAUTHCONF | NOAUTH | NOCONF "
			"(default: AUTHCONF)\n");
	fprintf(stderr, "    -y: permit keys that might collide\n");
	fprintf(stderr, "    -v verbose level\n");
	fprintf(stderr, "    -V: print version information\n");
	fprintf(stderr, "Date options:\n");
	fprintf(stderr, "    -P date/[+-]offset: set key publication date\n");
	fprintf(stderr, "    -P sync date/[+-]offset: set CDS and CDNSKEY "
			"publication date\n");
	fprintf(stderr, "    -A date/[+-]offset: set key activation date\n");
	fprintf(stderr, "    -R date/[+-]offset: set key revocation date\n");
	fprintf(stderr, "    -I date/[+-]offset: set key inactivation date\n");
	fprintf(stderr, "    -D date/[+-]offset: set key deletion date\n");
	fprintf(stderr, "    -D sync date/[+-]offset: set CDS and CDNSKEY "
			"deletion date\n");
	fprintf(stderr, "    -G: generate key only; do not set -P or -A\n");
	fprintf(stderr, "    -C: generate a backward-compatible key, omitting"
			" all dates\n");
	fprintf(stderr, "    -S <key>: generate a successor to an existing "
			"key\n");
	fprintf(stderr, "    -i <interval>: prepublication interval for "
			"successor key "
			"(default: 30 days)\n");
	fprintf(stderr, "Output:\n");
	fprintf(stderr, "     K<name>+<alg>+<id>.key, "
			"K<name>+<alg>+<id>.private\n");

	exit(-1);
}

int
main(int argc, char **argv) {
	char *algname = NULL, *freeit = NULL;
	char *nametype = NULL, *type = NULL;
	const char *directory = NULL;
	const char *predecessor = NULL;
	dst_key_t *prevkey = NULL;
	const char *engine = NULL;
	char *classname = NULL;
	char *endp;
	dst_key_t *key = NULL;
	dns_fixedname_t fname;
	dns_name_t *name;
	uint16_t flags = 0, kskflag = 0, revflag = 0;
	dns_secalg_t alg;
	bool oldstyle = false;
	isc_mem_t *mctx = NULL;
	int ch;
	int protocol = -1, signatory = 0;
	isc_result_t ret;
	isc_textregion_t r;
	char filename[255];
	isc_buffer_t buf;
	isc_log_t *log = NULL;
	dns_rdataclass_t rdclass;
	int options = DST_TYPE_PRIVATE | DST_TYPE_PUBLIC;
	char *label = NULL;
	dns_ttl_t ttl = 0;
	isc_stdtime_t publish = 0, activate = 0, revoke = 0;
	isc_stdtime_t inactive = 0, deltime = 0;
	isc_stdtime_t now;
	int prepub = -1;
	bool setpub = false, setact = false;
	bool setrev = false, setinact = false;
	bool setdel = false, setttl = false;
	bool unsetpub = false, unsetact = false;
	bool unsetrev = false, unsetinact = false;
	bool unsetdel = false;
	bool genonly = false;
	bool use_nsec3 = false;
	bool avoid_collisions = true;
	bool exact;
	unsigned char c;
	isc_stdtime_t syncadd = 0, syncdel = 0;
	bool unsetsyncadd = false, setsyncadd = false;
	bool unsetsyncdel = false, setsyncdel = false;

	if (argc == 1) {
		usage();
	}

	isc_mem_create(&mctx);

	isc_commandline_errprint = false;

	isc_stdtime_get(&now);

#define CMDLINE_FLAGS "3A:a:Cc:D:E:Ff:GhI:i:kK:L:l:n:P:p:R:S:t:v:Vy"
	while ((ch = isc_commandline_parse(argc, argv, CMDLINE_FLAGS)) != -1) {
		switch (ch) {
		case '3':
			use_nsec3 = true;
			break;
		case 'a':
			algname = isc_commandline_argument;
			break;
		case 'C':
			oldstyle = true;
			break;
		case 'c':
			classname = isc_commandline_argument;
			break;
		case 'E':
			engine = isc_commandline_argument;
			break;
		case 'f':
			c = (unsigned char)(isc_commandline_argument[0]);
			if (toupper(c) == 'K') {
				kskflag = DNS_KEYFLAG_KSK;
			} else if (toupper(c) == 'R') {
				revflag = DNS_KEYFLAG_REVOKE;
			} else {
				fatal("unknown flag '%s'",
				      isc_commandline_argument);
			}
			break;
		case 'K':
			directory = isc_commandline_argument;
			ret = try_dir(directory);
			if (ret != ISC_R_SUCCESS) {
				fatal("cannot open directory %s: %s", directory,
				      isc_result_totext(ret));
			}
			break;
		case 'k':
			options |= DST_TYPE_KEY;
			break;
		case 'L':
			ttl = strtottl(isc_commandline_argument);
			setttl = true;
			break;
		case 'l':
			label = isc_mem_strdup(mctx, isc_commandline_argument);
			break;
		case 'n':
			nametype = isc_commandline_argument;
			break;
		case 'p':
			protocol = strtol(isc_commandline_argument, &endp, 10);
			if (*endp != '\0' || protocol < 0 || protocol > 255) {
				fatal("-p must be followed by a number "
				      "[0..255]");
			}
			break;
		case 't':
			type = isc_commandline_argument;
			break;
		case 'v':
			verbose = strtol(isc_commandline_argument, &endp, 0);
			if (*endp != '\0') {
				fatal("-v must be followed by a number");
			}
			break;
		case 'y':
			avoid_collisions = false;
			break;
		case 'G':
			genonly = true;
			break;
		case 'P':
			/* -Psync ? */
			if (isoptarg("sync", argv, usage)) {
				if (unsetsyncadd || setsyncadd) {
					fatal("-P sync specified more than "
					      "once");
				}

				syncadd = strtotime(isc_commandline_argument,
						    now, now, &setsyncadd);
				unsetsyncadd = !setsyncadd;
				break;
			}
			/* -Pdnskey ? */
			(void)isoptarg("dnskey", argv, usage);
			if (setpub || unsetpub) {
				fatal("-P specified more than once");
			}

			publish = strtotime(isc_commandline_argument, now, now,
					    &setpub);
			unsetpub = !setpub;
			break;
		case 'A':
			if (setact || unsetact) {
				fatal("-A specified more than once");
			}

			activate = strtotime(isc_commandline_argument, now, now,
					     &setact);
			unsetact = !setact;
			break;
		case 'R':
			if (setrev || unsetrev) {
				fatal("-R specified more than once");
			}

			revoke = strtotime(isc_commandline_argument, now, now,
					   &setrev);
			unsetrev = !setrev;
			break;
		case 'I':
			if (setinact || unsetinact) {
				fatal("-I specified more than once");
			}

			inactive = strtotime(isc_commandline_argument, now, now,
					     &setinact);
			unsetinact = !setinact;
			break;
		case 'D':
			/* -Dsync ? */
			if (isoptarg("sync", argv, usage)) {
				if (unsetsyncdel || setsyncdel) {
					fatal("-D sync specified more than "
					      "once");
				}

				syncdel = strtotime(isc_commandline_argument,
						    now, now, &setsyncdel);
				unsetsyncdel = !setsyncdel;
				break;
			}
			/* -Ddnskey ? */
			(void)isoptarg("dnskey", argv, usage);
			if (setdel || unsetdel) {
				fatal("-D specified more than once");
			}

			deltime = strtotime(isc_commandline_argument, now, now,
					    &setdel);
			unsetdel = !setdel;
			break;
		case 'S':
			predecessor = isc_commandline_argument;
			break;
		case 'i':
			prepub = strtottl(isc_commandline_argument);
			break;
		case 'F':
		/* Reserved for FIPS mode */
		/* FALLTHROUGH */
		case '?':
			if (isc_commandline_option != '?') {
				fprintf(stderr, "%s: invalid argument -%c\n",
					program, isc_commandline_option);
			}
		/* FALLTHROUGH */
		case 'h':
			/* Does not return. */
			usage();

		case 'V':
			/* Does not return. */
			version(program);

		default:
			fprintf(stderr, "%s: unhandled option -%c\n", program,
				isc_commandline_option);
			exit(1);
		}
	}

	ret = dst_lib_init(mctx, engine);
	if (ret != ISC_R_SUCCESS) {
		fatal("could not initialize dst: %s", isc_result_totext(ret));
	}

	setup_logging(mctx, &log);

	if (predecessor == NULL) {
		if (label == NULL) {
			fatal("the key label was not specified");
		}
		if (argc < isc_commandline_index + 1) {
			fatal("the key name was not specified");
		}
		if (argc > isc_commandline_index + 1) {
			fatal("extraneous arguments");
		}

		name = dns_fixedname_initname(&fname);
		isc_buffer_init(&buf, argv[isc_commandline_index],
				strlen(argv[isc_commandline_index]));
		isc_buffer_add(&buf, strlen(argv[isc_commandline_index]));
		ret = dns_name_fromtext(name, &buf, dns_rootname, 0, NULL);
		if (ret != ISC_R_SUCCESS) {
			fatal("invalid key name %s: %s",
			      argv[isc_commandline_index],
			      isc_result_totext(ret));
		}

		if (strchr(label, ':') == NULL) {
			char *l;
			int len;

			len = strlen(label) + 8;
			l = isc_mem_allocate(mctx, len);
			snprintf(l, len, "pkcs11:%s", label);
			isc_mem_free(mctx, label);
			label = l;
		}

		if (algname == NULL) {
			fatal("no algorithm specified");
		}

		r.base = algname;
		r.length = strlen(algname);
		ret = dns_secalg_fromtext(&alg, &r);
		if (ret != ISC_R_SUCCESS) {
			fatal("unknown algorithm %s", algname);
		}
		if (alg == DST_ALG_DH) {
			options |= DST_TYPE_KEY;
		}

		if (use_nsec3) {
			switch (alg) {
			case DST_ALG_RSASHA1:
				alg = DST_ALG_NSEC3RSASHA1;
				break;
			case DST_ALG_NSEC3RSASHA1:
			case DST_ALG_RSASHA256:
			case DST_ALG_RSASHA512:
			case DST_ALG_ECDSA256:
			case DST_ALG_ECDSA384:
			case DST_ALG_ED25519:
			case DST_ALG_ED448:
				break;
			default:
				fatal("%s is incompatible with NSEC3; "
				      "do not use the -3 option",
				      algname);
			}
		}

		if (type != NULL && (options & DST_TYPE_KEY) != 0) {
			if (strcasecmp(type, "NOAUTH") == 0) {
				flags |= DNS_KEYTYPE_NOAUTH;
			} else if (strcasecmp(type, "NOCONF") == 0) {
				flags |= DNS_KEYTYPE_NOCONF;
			} else if (strcasecmp(type, "NOAUTHCONF") == 0) {
				flags |= (DNS_KEYTYPE_NOAUTH |
					  DNS_KEYTYPE_NOCONF);
			} else if (strcasecmp(type, "AUTHCONF") == 0) {
				/* nothing */
			} else {
				fatal("invalid type %s", type);
			}
		}

		if (!oldstyle && prepub > 0) {
			if (setpub && setact && (activate - prepub) < publish) {
				fatal("Activation and publication dates "
				      "are closer together than the\n\t"
				      "prepublication interval.");
			}

			if (!setpub && !setact) {
				setpub = setact = true;
				publish = now;
				activate = now + prepub;
			} else if (setpub && !setact) {
				setact = true;
				activate = publish + prepub;
			} else if (setact && !setpub) {
				setpub = true;
				publish = activate - prepub;
			}

			if ((activate - prepub) < now) {
				fatal("Time until activation is shorter "
				      "than the\n\tprepublication interval.");
			}
		}
	} else {
		char keystr[DST_KEY_FORMATSIZE];
		isc_stdtime_t when;
		int major, minor;

		if (prepub == -1) {
			prepub = (30 * 86400);
		}

		if (algname != NULL) {
			fatal("-S and -a cannot be used together");
		}
		if (nametype != NULL) {
			fatal("-S and -n cannot be used together");
		}
		if (type != NULL) {
			fatal("-S and -t cannot be used together");
		}
		if (setpub || unsetpub) {
			fatal("-S and -P cannot be used together");
		}
		if (setact || unsetact) {
			fatal("-S and -A cannot be used together");
		}
		if (use_nsec3) {
			fatal("-S and -3 cannot be used together");
		}
		if (oldstyle) {
			fatal("-S and -C cannot be used together");
		}
		if (genonly) {
			fatal("-S and -G cannot be used together");
		}

		ret = dst_key_fromnamedfile(predecessor, directory,
					    DST_TYPE_PUBLIC | DST_TYPE_PRIVATE,
					    mctx, &prevkey);
		if (ret != ISC_R_SUCCESS) {
			fatal("Invalid keyfile %s: %s", predecessor,
			      isc_result_totext(ret));
		}
		if (!dst_key_isprivate(prevkey)) {
			fatal("%s is not a private key", predecessor);
		}

		name = dst_key_name(prevkey);
		alg = dst_key_alg(prevkey);
		flags = dst_key_flags(prevkey);

		dst_key_format(prevkey, keystr, sizeof(keystr));
		dst_key_getprivateformat(prevkey, &major, &minor);
		if (major != DST_MAJOR_VERSION || minor < DST_MINOR_VERSION) {
			fatal("Key %s has incompatible format version %d.%d\n\t"
			      "It is not possible to generate a successor key.",
			      keystr, major, minor);
		}

		ret = dst_key_gettime(prevkey, DST_TIME_ACTIVATE, &when);
		if (ret != ISC_R_SUCCESS) {
			fatal("Key %s has no activation date.\n\t"
			      "You must use dnssec-settime -A to set one "
			      "before generating a successor.",
			      keystr);
		}

		ret = dst_key_gettime(prevkey, DST_TIME_INACTIVE, &activate);
		if (ret != ISC_R_SUCCESS) {
			fatal("Key %s has no inactivation date.\n\t"
			      "You must use dnssec-settime -I to set one "
			      "before generating a successor.",
			      keystr);
		}

		publish = activate - prepub;
		if (publish < now) {
			fatal("Key %s becomes inactive\n\t"
			      "sooner than the prepublication period "
			      "for the new key ends.\n\t"
			      "Either change the inactivation date with "
			      "dnssec-settime -I,\n\t"
			      "or use the -i option to set a shorter "
			      "prepublication interval.",
			      keystr);
		}

		ret = dst_key_gettime(prevkey, DST_TIME_DELETE, &when);
		if (ret != ISC_R_SUCCESS) {
			fprintf(stderr,
				"%s: WARNING: Key %s has no removal "
				"date;\n\t it will remain in the zone "
				"indefinitely after rollover.\n\t "
				"You can use dnssec-settime -D to "
				"change this.\n",
				program, keystr);
		}

		setpub = setact = true;
	}

	if (nametype == NULL) {
		if ((options & DST_TYPE_KEY) != 0) { /* KEY */
			fatal("no nametype specified");
		}
		flags |= DNS_KEYOWNER_ZONE; /* DNSKEY */
	} else if (strcasecmp(nametype, "zone") == 0) {
		flags |= DNS_KEYOWNER_ZONE;
	} else if ((options & DST_TYPE_KEY) != 0) { /* KEY */
		if (strcasecmp(nametype, "host") == 0 ||
		    strcasecmp(nametype, "entity") == 0) {
			flags |= DNS_KEYOWNER_ENTITY;
		} else if (strcasecmp(nametype, "user") == 0) {
			flags |= DNS_KEYOWNER_USER;
		} else {
			fatal("invalid KEY nametype %s", nametype);
		}
	} else if (strcasecmp(nametype, "other") != 0) { /* DNSKEY */
		fatal("invalid DNSKEY nametype %s", nametype);
	}

	rdclass = strtoclass(classname);

	if (directory == NULL) {
		directory = ".";
	}

	if ((options & DST_TYPE_KEY) != 0) { /* KEY */
		flags |= signatory;
	} else if ((flags & DNS_KEYOWNER_ZONE) != 0) { /* DNSKEY */
		flags |= kskflag;
		flags |= revflag;
	}

	if (protocol == -1) {
		protocol = DNS_KEYPROTO_DNSSEC;
	} else if ((options & DST_TYPE_KEY) == 0 &&
		   protocol != DNS_KEYPROTO_DNSSEC) {
		fatal("invalid DNSKEY protocol: %d", protocol);
	}

	if ((flags & DNS_KEYFLAG_TYPEMASK) == DNS_KEYTYPE_NOKEY) {
		if ((flags & DNS_KEYFLAG_SIGNATORYMASK) != 0) {
			fatal("specified null key with signing authority");
		}
	}

	if ((flags & DNS_KEYFLAG_OWNERMASK) == DNS_KEYOWNER_ZONE &&
	    alg == DNS_KEYALG_DH)
	{
		fatal("a key with algorithm '%s' cannot be a zone key",
		      algname);
	}

	isc_buffer_init(&buf, filename, sizeof(filename) - 1);

	/* associate the key */
	ret = dst_key_fromlabel(name, alg, flags, protocol, rdclass,
#if USE_PKCS11
				"pkcs11",
#else  /* if USE_PKCS11 */
				engine,
#endif /* if USE_PKCS11 */
				label, NULL, mctx, &key);

	if (ret != ISC_R_SUCCESS) {
		char namestr[DNS_NAME_FORMATSIZE];
		char algstr[DNS_SECALG_FORMATSIZE];
		dns_name_format(name, namestr, sizeof(namestr));
		dns_secalg_format(alg, algstr, sizeof(algstr));
		fatal("failed to get key %s/%s: %s", namestr, algstr,
		      isc_result_totext(ret));
		/* NOTREACHED */
		exit(-1);
	}

	/*
	 * Set key timing metadata (unless using -C)
	 *
	 * Publish and activation dates are set to "now" by default, but
	 * can be overridden.  Creation date is always set to "now".
	 */
	if (!oldstyle) {
		dst_key_settime(key, DST_TIME_CREATED, now);

		if (genonly && (setpub || setact)) {
			fatal("cannot use -G together with -P or -A options");
		}

		if (setpub) {
			dst_key_settime(key, DST_TIME_PUBLISH, publish);
		} else if (setact) {
			dst_key_settime(key, DST_TIME_PUBLISH, activate);
		} else if (!genonly && !unsetpub) {
			dst_key_settime(key, DST_TIME_PUBLISH, now);
		}

		if (setact) {
			dst_key_settime(key, DST_TIME_ACTIVATE, activate);
		} else if (!genonly && !unsetact) {
			dst_key_settime(key, DST_TIME_ACTIVATE, now);
		}

		if (setrev) {
			if (kskflag == 0) {
				fprintf(stderr,
					"%s: warning: Key is "
					"not flagged as a KSK, but -R "
					"was used. Revoking a ZSK is "
					"legal, but undefined.\n",
					program);
			}
			dst_key_settime(key, DST_TIME_REVOKE, revoke);
		}

		if (setinact) {
			dst_key_settime(key, DST_TIME_INACTIVE, inactive);
		}

		if (setdel) {
			dst_key_settime(key, DST_TIME_DELETE, deltime);
		}
		if (setsyncadd) {
			dst_key_settime(key, DST_TIME_SYNCPUBLISH, syncadd);
		}
		if (setsyncdel) {
			dst_key_settime(key, DST_TIME_SYNCDELETE, syncdel);
		}
	} else {
		if (setpub || setact || setrev || setinact || setdel ||
		    unsetpub || unsetact || unsetrev || unsetinact ||
		    unsetdel || genonly || setsyncadd || setsyncdel)
		{
			fatal("cannot use -C together with "
			      "-P, -A, -R, -I, -D, or -G options");
		}
		/*
		 * Compatibility mode: Private-key-format
		 * should be set to 1.2.
		 */
		dst_key_setprivateformat(key, 1, 2);
	}

	/* Set default key TTL */
	if (setttl) {
		dst_key_setttl(key, ttl);
	}

	/*
	 * Do not overwrite an existing key.  Warn LOUDLY if there
	 * is a risk of ID collision due to this key or another key
	 * being revoked.
	 */
	if (key_collision(key, name, directory, mctx, &exact)) {
		isc_buffer_clear(&buf);
		ret = dst_key_buildfilename(key, 0, directory, &buf);
		if (ret != ISC_R_SUCCESS) {
			fatal("dst_key_buildfilename returned: %s\n",
			      isc_result_totext(ret));
		}
		if (exact) {
			fatal("%s: %s already exists\n", program, filename);
		}

		if (avoid_collisions) {
			fatal("%s: %s could collide with another key upon "
			      "revokation\n",
			      program, filename);
		}

		fprintf(stderr,
			"%s: WARNING: Key %s could collide with "
			"another key upon revokation.  If you plan "
			"to revoke keys, destroy this key and "
			"generate a different one.\n",
			program, filename);
	}

	ret = dst_key_tofile(key, options, directory);
	if (ret != ISC_R_SUCCESS) {
		char keystr[DST_KEY_FORMATSIZE];
		dst_key_format(key, keystr, sizeof(keystr));
		fatal("failed to write key %s: %s\n", keystr,
		      isc_result_totext(ret));
	}

	isc_buffer_clear(&buf);
	ret = dst_key_buildfilename(key, 0, NULL, &buf);
	if (ret != ISC_R_SUCCESS) {
		fatal("dst_key_buildfilename returned: %s\n",
		      isc_result_totext(ret));
	}
	printf("%s\n", filename);
	dst_key_free(&key);
	if (prevkey != NULL) {
		dst_key_free(&prevkey);
	}

	cleanup_logging(&log);
	dst_lib_destroy();
	if (verbose > 10) {
		isc_mem_stats(mctx, stdout);
	}
	isc_mem_free(mctx, label);
	isc_mem_destroy(&mctx);

	if (freeit != NULL) {
		free(freeit);
	}

	return (0);
}
