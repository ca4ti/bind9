/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */


/*! \file */

#include <stdbool.h>

#include <isc/mem.h>
#include <isc/print.h>
#include <isc/refcount.h>
#include <isc/rwlock.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/util.h>

#include <dns/dnssec.h>
#include <dns/keytable.h>
#include <dns/fixedname.h>
#include <dns/rbt.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/result.h>

#define KEYTABLE_MAGIC                  ISC_MAGIC('K', 'T', 'b', 'l')
#define VALID_KEYTABLE(kt)              ISC_MAGIC_VALID(kt, KEYTABLE_MAGIC)

#define KEYNODE_MAGIC                   ISC_MAGIC('K', 'N', 'o', 'd')
#define VALID_KEYNODE(kn)               ISC_MAGIC_VALID(kn, KEYNODE_MAGIC)

struct dns_keytable {
	/* Unlocked. */
	unsigned int            magic;
	isc_mem_t               *mctx;
	atomic_uint_fast32_t	active_nodes;
	isc_refcount_t          references;
	isc_rwlock_t            rwlock;
	/* Locked by rwlock. */
	dns_rbt_t               *table;
};

struct dns_keynode {
	unsigned int            magic;
	isc_refcount_t          refcount;
	dst_key_t		*key;
	dns_rdatalist_t		*dslist;
	dns_rdataset_t		dsset;
	bool			managed;
	bool			initial;
	struct dns_keynode	*next;
};

static void
free_keynode(void *node, void *arg) {
	dns_keynode_t *keynode = node;
	isc_mem_t *mctx = arg;

	dns_keynode_detachall(mctx, &keynode);
}

isc_result_t
dns_keytable_create(isc_mem_t *mctx, dns_keytable_t **keytablep) {
	dns_keytable_t *keytable;
	isc_result_t result;

	/*
	 * Create a keytable.
	 */

	REQUIRE(keytablep != NULL && *keytablep == NULL);

	keytable = isc_mem_get(mctx, sizeof(*keytable));

	keytable->table = NULL;
	result = dns_rbt_create(mctx, free_keynode, mctx, &keytable->table);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_keytable;
	}

	result = isc_rwlock_init(&keytable->rwlock, 0, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_rbt;
	}

	atomic_init(&keytable->active_nodes, 0);
	isc_refcount_init(&keytable->references, 1);

	keytable->mctx = NULL;
	isc_mem_attach(mctx, &keytable->mctx);
	keytable->magic = KEYTABLE_MAGIC;
	*keytablep = keytable;

	return (ISC_R_SUCCESS);

 cleanup_rbt:
	dns_rbt_destroy(&keytable->table);

 cleanup_keytable:
	isc_mem_putanddetach(&mctx, keytable, sizeof(*keytable));

	return (result);
}

void
dns_keytable_attach(dns_keytable_t *source, dns_keytable_t **targetp) {

	/*
	 * Attach *targetp to source.
	 */

	REQUIRE(VALID_KEYTABLE(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);

	*targetp = source;
}

void
dns_keytable_detach(dns_keytable_t **keytablep) {
	REQUIRE(keytablep != NULL && VALID_KEYTABLE(*keytablep));
	dns_keytable_t *keytable = *keytablep;
	*keytablep = NULL;

	if (isc_refcount_decrement(&keytable->references) == 1) {
		isc_refcount_destroy(&keytable->references);
		REQUIRE(atomic_load_acquire(&keytable->active_nodes) == 0);
		dns_rbt_destroy(&keytable->table);
		isc_rwlock_destroy(&keytable->rwlock);
		keytable->magic = 0;
		isc_mem_putanddetach(&keytable->mctx,
				     keytable, sizeof(*keytable));
	}
}

static void
free_dslist(isc_mem_t *mctx, dns_keynode_t *knode) {
	dns_rdata_t *rdata = NULL;

	for (rdata = ISC_LIST_HEAD(knode->dslist->rdata);
	     rdata != NULL;
	     rdata = ISC_LIST_HEAD(knode->dslist->rdata))
	{
		ISC_LIST_UNLINK(knode->dslist->rdata, rdata, link);
		isc_mem_put(mctx, rdata->data, DNS_DS_BUFFERSIZE);
		isc_mem_put(mctx, rdata, sizeof(*rdata));
	}

	isc_mem_put(mctx, knode->dslist, sizeof(*knode->dslist));
	knode->dslist = NULL;
}

static isc_result_t
add_ds(dns_keynode_t *knode, dns_rdata_ds_t *ds, isc_mem_t *mctx) {
	isc_result_t result;
	dns_rdata_t *rdata = NULL;
	void *data = NULL;
	isc_buffer_t b;

	if (knode->dslist == NULL) {
		knode->dslist = isc_mem_get(mctx, sizeof(*knode->dslist));
		dns_rdatalist_init(knode->dslist);
		knode->dslist->rdclass = dns_rdataclass_in;
		knode->dslist->type = dns_rdatatype_ds;
	}

	rdata = isc_mem_get(mctx, sizeof(*rdata));
	dns_rdata_init(rdata);

	data = isc_mem_get(mctx, DNS_DS_BUFFERSIZE);
	isc_buffer_init(&b, data, DNS_DS_BUFFERSIZE);

	result = dns_rdata_fromstruct(rdata, dns_rdataclass_in,
				      dns_rdatatype_ds, ds, &b);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	ISC_LIST_APPEND(knode->dslist->rdata, rdata, link);

	if (dns_rdataset_isassociated(&knode->dsset)) {
		dns_rdataset_disassociate(&knode->dsset);
	}

	result = dns_rdatalist_tordataset(knode->dslist, &knode->dsset);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	knode->dsset.trust = dns_trust_ultimate;
	return (ISC_R_SUCCESS);
}

/*%
 * Create a keynode for "ds" (or a null key node if "ds" is NULL), set
 * "managed" and "initial" as requested and attach the keynode to
 * to "node" in "keytable".
 */
static isc_result_t
new_keynode(dns_rdata_ds_t *ds, dns_rbtnode_t *node,
	    dns_keytable_t *keytable, bool managed, bool initial)
{
	dns_keynode_t *knode = NULL;
	isc_result_t result;

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(!initial || managed);

	knode = isc_mem_get(keytable->mctx, sizeof(dns_keynode_t));
	*knode = (dns_keynode_t) {
		.magic = KEYNODE_MAGIC
	};

	dns_rdataset_init(&knode->dsset);
	isc_refcount_init(&knode->refcount, 1);

	/*
	 * If a DS was supplied, initialize an rdatalist.
	 */
	if (ds != NULL) {
		result = add_ds(knode, ds, keytable->mctx);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}

	knode->managed = managed;
	knode->initial = initial;

	knode->next = node->data;
	node->data = knode;

	return (ISC_R_SUCCESS);
}

/*%
 * Add key trust anchor "ds" at "keyname" in "keytable".  If an anchor
 * already exists at the requested name does not contain "ds", update it.
 * If "ds" is NULL, add a null key to indicate that "keyname" should be
 * treated as a secure domain without supplying key data which would allow
 * the domain to be validated.
 */
static isc_result_t
insert(dns_keytable_t *keytable, bool managed, bool initial,
       const dns_name_t *keyname, dns_rdata_ds_t *ds)
{
	dns_rbtnode_t *node = NULL;
	isc_result_t result;

	REQUIRE(VALID_KEYTABLE(keytable));

	RWLOCK(&keytable->rwlock, isc_rwlocktype_write);

	result = dns_rbt_addnode(keytable->table, keyname, &node);
	if (result == ISC_R_SUCCESS) {
		/*
		 * There was no node for "keyname" in "keytable" yet, so one
		 * was created.  Create a new key node for the supplied
		 * trust anchor (or a null key node if both "ds" is NULL)
		 * and attach it to the created node.
		 */
		result = new_keynode(ds, node, keytable, managed, initial);
	} else if (result == ISC_R_EXISTS) {
		/*
		 * A node already exists for "keyname" in "keytable".
		 */
		if (ds == NULL) {
			/*
			 * We were told to add a null key at "keyname", which
			 * means there is nothing left to do as there is either
			 * a null key at this node already or there is a
			 * non-null key node which would not be affected.
			 * Reset result to reflect the fact that the node for
			 * "keyname" is already marked as secure.
			 */
			result = ISC_R_SUCCESS;
		} else {
			dns_keynode_t *knode = node->data;
			if (knode == NULL) {
				result = new_keynode(ds, node, keytable,
						     managed, initial);
			} else {
				result = add_ds(knode, ds, keytable->mctx);
			}
		}
	}

	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_write);

	return (result);
}

isc_result_t
dns_keytable_add(dns_keytable_t *keytable, bool managed, bool initial,
		 dns_name_t *name, dns_rdata_ds_t *ds)
{
	REQUIRE(ds != NULL);
	REQUIRE(!initial || managed);
	return (insert(keytable, managed, initial, name, ds));
}

isc_result_t
dns_keytable_marksecure(dns_keytable_t *keytable, const dns_name_t *name) {
	return (insert(keytable, true, false, name, NULL));
}

isc_result_t
dns_keytable_delete(dns_keytable_t *keytable, const dns_name_t *keyname) {
	isc_result_t result;
	dns_rbtnode_t *node = NULL;

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(keyname != NULL);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_write);
	result = dns_rbt_findnode(keytable->table, keyname, NULL, &node, NULL,
				  DNS_RBTFIND_NOOPTIONS, NULL, NULL);
	if (result == ISC_R_SUCCESS) {
		if (node->data != NULL)
			result = dns_rbt_deletenode(keytable->table,
						    node, false);
		else
			result = ISC_R_NOTFOUND;
	} else if (result == DNS_R_PARTIALMATCH)
		result = ISC_R_NOTFOUND;
	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_write);

	return (result);
}

isc_result_t
dns_keytable_deletekey(dns_keytable_t *keytable, const dns_name_t *keyname,
		       dns_rdata_dnskey_t *dnskey)
{
	isc_result_t result;
	dns_rbtnode_t *node = NULL;
	dns_keynode_t *knode = NULL, **kprev = NULL;
	dst_key_t *dstkey = NULL;
	unsigned char data[4096];
	isc_buffer_t buffer;
	dns_rdata_t rdata = DNS_RDATA_INIT;

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(dnskey != NULL);

	/* Convert dnskey to DST key. */
	isc_buffer_init(&buffer, data, sizeof(data));
	dns_rdata_fromstruct(&rdata, dnskey->common.rdclass,
			     dns_rdatatype_dnskey, dnskey, &buffer);
	result = dns_dnssec_keyfromrdata(keyname, &rdata, keytable->mctx,
					 &dstkey);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	RWLOCK(&keytable->rwlock, isc_rwlocktype_write);
	result = dns_rbt_findnode(keytable->table, keyname, NULL, &node, NULL,
				  DNS_RBTFIND_NOOPTIONS, NULL, NULL);

	if (result == DNS_R_PARTIALMATCH) {
		result = ISC_R_NOTFOUND;
	}
	if (result != ISC_R_SUCCESS) {
		goto finish;
	}

	if (node->data == NULL) {
		result = ISC_R_NOTFOUND;
		goto finish;
	}

	knode = node->data;
	if (knode->next == NULL && knode->key != NULL &&
	    dst_key_compare(knode->key, dstkey))
	{
		result = dns_rbt_deletenode(keytable->table, node, false);
		goto finish;
	}

	kprev = (dns_keynode_t **) &node->data;
	while (knode != NULL) {
		if (knode->key != NULL && dst_key_compare(knode->key, dstkey)) {
			break;
		}

		kprev = &knode->next;
		knode = knode->next;
	}

	if (knode != NULL) {
		if (knode->key != NULL) {
			dst_key_free(&knode->key);
		}

		/*
		 * This is equivalent to:
		 * dns_keynode_attach(knode->next, &tmp);
		 * dns_keynode_detach(kprev);
		 * dns_keynode_attach(tmp, &kprev);
		 * dns_keynode_detach(&tmp);
		 */
		*kprev = knode->next;
		knode->next = NULL;
		dns_keynode_detach(keytable->mctx, &knode);
	} else {
		result = DNS_R_PARTIALMATCH;
	}

  finish:
	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_write);
	dst_key_free(&dstkey);
	return (result);
}

isc_result_t
dns_keytable_find(dns_keytable_t *keytable, const dns_name_t *keyname,
		  dns_keynode_t **keynodep)
{
	isc_result_t result;
	dns_rbtnode_t *node = NULL;

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(keyname != NULL);
	REQUIRE(keynodep != NULL && *keynodep == NULL);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_read);
	result = dns_rbt_findnode(keytable->table, keyname, NULL, &node, NULL,
				  DNS_RBTFIND_NOOPTIONS, NULL, NULL);
	if (result == ISC_R_SUCCESS) {
		if (node->data != NULL) {
			dns_keytable_attachkeynode(keytable, node->data,
						   keynodep);
		} else {
			result = ISC_R_NOTFOUND;
		}
	} else if (result == DNS_R_PARTIALMATCH) {
		result = ISC_R_NOTFOUND;
	}
	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_read);

	return (result);
}

isc_result_t
dns_keytable_finddeepestmatch(dns_keytable_t *keytable, const dns_name_t *name,
			      dns_name_t *foundname)
{
	isc_result_t result;
	void *data;

	/*
	 * Search for the deepest match in 'keytable'.
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(foundname != NULL);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_read);

	data = NULL;
	result = dns_rbt_findname(keytable->table, name, 0, foundname, &data);

	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		result = ISC_R_SUCCESS;
	}

	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_read);

	return (result);
}

void
dns_keytable_attachkeynode(dns_keytable_t *keytable, dns_keynode_t *source,
			   dns_keynode_t **target)
{
	/*
	 * Give back a keynode found via dns_keytable_findkeynode().
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(VALID_KEYNODE(source));
	REQUIRE(target != NULL && *target == NULL);

	REQUIRE(atomic_fetch_add_relaxed(&keytable->active_nodes,
					 1) < UINT32_MAX);

	dns_keynode_attach(source, target);
}

void
dns_keytable_detachkeynode(dns_keytable_t *keytable, dns_keynode_t **keynodep)
{
	/*
	 * Give back a keynode found via dns_keytable_findkeynode().
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(keynodep != NULL && VALID_KEYNODE(*keynodep));

	REQUIRE(atomic_fetch_sub_release(&keytable->active_nodes, 1) > 0);

	dns_keynode_detach(keytable->mctx, keynodep);
}

isc_result_t
dns_keytable_issecuredomain(dns_keytable_t *keytable, const dns_name_t *name,
			    dns_name_t *foundname, bool *wantdnssecp)
{
	isc_result_t result;
	dns_rbtnode_t *node = NULL;

	/*
	 * Is 'name' at or beneath a trusted key?
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(wantdnssecp != NULL);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_read);

	result = dns_rbt_findnode(keytable->table, name, foundname, &node,
				  NULL, DNS_RBTFIND_NOOPTIONS, NULL, NULL);
	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		INSIST(node->data != NULL);
		*wantdnssecp = true;
		result = ISC_R_SUCCESS;
	} else if (result == ISC_R_NOTFOUND) {
		*wantdnssecp = false;
		result = ISC_R_SUCCESS;
	}

	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_read);

	return (result);
}

static isc_result_t
putstr(isc_buffer_t **b, const char *str) {
	isc_result_t result;

	result = isc_buffer_reserve(b, strlen(str));
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	isc_buffer_putstr(*b, str);
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_keytable_dump(dns_keytable_t *keytable, FILE *fp) {
	isc_result_t result;
	isc_buffer_t *text = NULL;

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(fp != NULL);

	result = isc_buffer_allocate(keytable->mctx, &text, 4096);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = dns_keytable_totext(keytable, &text);

	if (isc_buffer_usedlength(text) != 0) {
		(void) putstr(&text, "\n");
	} else if (result == ISC_R_SUCCESS) {
		(void) putstr(&text, "none");
	} else {
		(void) putstr(&text, "could not dump key table: ");
		(void) putstr(&text, isc_result_totext(result));
	}

	fprintf(fp, "%.*s", (int) isc_buffer_usedlength(text),
		(char *) isc_buffer_base(text));

	isc_buffer_free(&text);
	return (result);
}

static isc_result_t
keynode_dslist_totext(dns_name_t *name, dns_keynode_t *keynode,
		      isc_buffer_t **text)
{
	isc_result_t result;
	char namebuf[DNS_NAME_FORMATSIZE];
	char obuf[DNS_NAME_FORMATSIZE + 200];
	dns_rdataset_t *dsset = NULL;

	dns_name_format(name, namebuf, sizeof(namebuf));

	dsset = dns_keynode_dsset(keynode);

	for (result = dns_rdataset_first(dsset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(dsset))
	{
		char algbuf[DNS_SECALG_FORMATSIZE];
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdata_ds_t ds;

		dns_rdataset_current(dsset, &rdata);
		result = dns_rdata_tostruct(&rdata, &ds, NULL);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);

		dns_secalg_format(ds.algorithm, algbuf, sizeof(algbuf));

		snprintf(obuf, sizeof(obuf), "%s/%s/%d ; %s%s (DS)\n",
			 namebuf, algbuf, ds.key_tag,
			 keynode->initial ? "initializing " : "",
			 keynode->managed ? "managed" : "static");

		result = putstr(text, obuf);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_keytable_totext(dns_keytable_t *keytable, isc_buffer_t **text) {
	isc_result_t result;
	dns_keynode_t *knode;
	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;
	dns_name_t *foundname, *origin, *fullname;
	dns_fixedname_t fixedfoundname, fixedorigin, fixedfullname;

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(text != NULL && *text != NULL);

	origin = dns_fixedname_initname(&fixedorigin);
	fullname = dns_fixedname_initname(&fixedfullname);
	foundname = dns_fixedname_initname(&fixedfoundname);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_read);
	dns_rbtnodechain_init(&chain);
	result = dns_rbtnodechain_first(&chain, keytable->table, NULL, NULL);
	if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
		if (result == ISC_R_NOTFOUND) {
			result = ISC_R_SUCCESS;
		}
		goto cleanup;
	}
	for (;;) {
		char pbuf[DST_KEY_FORMATSIZE];

		dns_rbtnodechain_current(&chain, foundname, origin, &node);

		knode = node->data;
		if (knode != NULL && knode->dslist != NULL) {
			result = dns_name_concatenate(foundname, origin,
						      fullname, NULL);
			if (result != ISC_R_SUCCESS) {
				goto cleanup;
			}

			result = keynode_dslist_totext(fullname, knode, text);
			goto cleanup;
		}

		for (; knode != NULL; knode = knode->next) {
			char obuf[DNS_NAME_FORMATSIZE + 200];

			if (knode->key == NULL) {
				continue;
			}

			dst_key_format(knode->key, pbuf, sizeof(pbuf));
			snprintf(obuf, sizeof(obuf), "%s ; %s%s\n", pbuf,
				 knode->initial ? "initializing " : "",
				 knode->managed ? "managed" : "static");

			result = putstr(text, obuf);
			if (result != ISC_R_SUCCESS) {
				break;
			}
		}

		result = dns_rbtnodechain_next(&chain, NULL, NULL);
		if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
			if (result == ISC_R_NOMORE) {
				result = ISC_R_SUCCESS;
			}
			break;
		}
	}

   cleanup:
	dns_rbtnodechain_invalidate(&chain);
	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_read);
	return (result);
}

isc_result_t
dns_keytable_forall(dns_keytable_t *keytable,
		    void (*func)(dns_keytable_t *, dns_keynode_t *,
				 dns_name_t *, void *),
		    void *arg)
{
	isc_result_t result;
	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;
	dns_fixedname_t fixedfoundname, fixedorigin, fixedfullname;
	dns_name_t *foundname, *origin, *fullname;

	REQUIRE(VALID_KEYTABLE(keytable));

	origin = dns_fixedname_initname(&fixedorigin);
	fullname = dns_fixedname_initname(&fixedfullname);
	foundname = dns_fixedname_initname(&fixedfoundname);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_read);
	dns_rbtnodechain_init(&chain);
	result = dns_rbtnodechain_first(&chain, keytable->table, NULL, NULL);
	if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
		if (result == ISC_R_NOTFOUND) {
			result = ISC_R_SUCCESS;
		}
		goto cleanup;
	}
	REQUIRE(atomic_fetch_add_relaxed(&keytable->active_nodes,
					 1) < UINT32_MAX);
	for (;;) {
		dns_rbtnodechain_current(&chain, foundname, origin, &node);
		if (node->data != NULL) {
			result = dns_name_concatenate(foundname, origin,
						      fullname, NULL);
			RUNTIME_CHECK(result == ISC_R_SUCCESS);
			(*func)(keytable, node->data, fullname, arg);
		}
		result = dns_rbtnodechain_next(&chain, NULL, NULL);
		if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
			if (result == ISC_R_NOMORE) {
				result = ISC_R_SUCCESS;
			}
			break;
		}
	}
	REQUIRE(atomic_fetch_sub_release(&keytable->active_nodes, 1) > 0);

   cleanup:
	dns_rbtnodechain_invalidate(&chain);
	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_read);
	return (result);
}

dns_rdataset_t *
dns_keynode_dsset(dns_keynode_t *keynode) {
	REQUIRE(VALID_KEYNODE(keynode));

	if (keynode->dslist != NULL) {
		return (&keynode->dsset);
	}

	return (NULL);
}

bool
dns_keynode_managed(dns_keynode_t *keynode) {
	REQUIRE(VALID_KEYNODE(keynode));

	return (keynode->managed);
}

bool
dns_keynode_initial(dns_keynode_t *keynode) {
	REQUIRE(VALID_KEYNODE(keynode));

	return (keynode->initial);
}

void
dns_keynode_trust(dns_keynode_t *keynode) {
	REQUIRE(VALID_KEYNODE(keynode));

	keynode->initial = false;
}

void
dns_keynode_attach(dns_keynode_t *source, dns_keynode_t **target) {
	REQUIRE(VALID_KEYNODE(source));
	isc_refcount_increment(&source->refcount);
	*target = source;
}

void
dns_keynode_detach(isc_mem_t *mctx, dns_keynode_t **keynodep) {
	REQUIRE(keynodep != NULL && VALID_KEYNODE(*keynodep));
	dns_keynode_t *knode = *keynodep;
	*keynodep = NULL;

	if (isc_refcount_decrement(&knode->refcount) == 1) {
		isc_refcount_destroy(&knode->refcount);
		if (knode->key != NULL) {
			dst_key_free(&knode->key);
		}
		if (knode->dslist != NULL) {
			if (dns_rdataset_isassociated(&knode->dsset)) {
				dns_rdataset_disassociate(&knode->dsset);
			}
			free_dslist(mctx, knode);
		}
		isc_mem_put(mctx, knode, sizeof(dns_keynode_t));
	}
}

void
dns_keynode_detachall(isc_mem_t *mctx, dns_keynode_t **keynode) {
	dns_keynode_t *next = NULL, *node = *keynode;
	REQUIRE(VALID_KEYNODE(node));
	while (node != NULL) {
		next = node->next;
		dns_keynode_detach(mctx, &node);
		node = next;
	}
	*keynode = NULL;
}
