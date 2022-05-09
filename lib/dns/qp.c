/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*
 * For an overview, see doc/design/qp-trie.md
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/time.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/log.h>
#include <dns/name.h>
#include <dns/qp.h>
#include <dns/types.h>

#include "qp_p.h"

/*
 * very basic garbage collector statistics
 *
 * XXXFANF for now we're logging GC times, but ideally we should
 * accumulate stats more quietly and report via the statschannel
 */
static uint64_t compact_time;
static uint64_t recycle_time;
static uint64_t rollback_time;

#if 1
#define QP_LOG_STATS(...)                                                   \
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_QP, \
		      ISC_LOG_DEBUG(1), __VA_ARGS__)
#else
#define QP_LOG_STATS(...)
#endif

#define PRItime " %" PRIu64 " us "

#if 0
/*
 * QP_TRACE is generally used in allocation-related functions so it doesn't
 * trace very high-frequency ops
 */
#define QP_TRACE(fmt, ...)                                               \
	if (isc_log_wouldlog(dns_lctx, ISC_LOG_DEBUG(7))) {              \
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,        \
			      DNS_LOGMODULE_QP, ISC_LOG_DEBUG(7),        \
			      "%s:%d:%s(qp %p ctx \"%s\" gen %u): " fmt, \
			      __FILE__, __LINE__, __func__, qp,          \
			      triename(qp, (char[256]){}, 256),          \
			      qp->generation, ##__VA_ARGS__);            \
	} else                                                           \
		do {                                                     \
		} while (0)
#else
#define QP_TRACE(...)
#endif

/***********************************************************************
 *
 *  converting DNS names to trie keys
 */

/*
 * Lookup table definitions - see `qp_p.h` for declarations.
 */
uint16_t dns_qp_bits_for_byte[256] = { 0 };
uint8_t dns_qp_byte_for_bit[SHIFT_OFFSET] = { 0 };

/*
 * Fill in the lookup tables at program startup. (It doesn't matter
 * when this is initialized relative to other startup code.)
 */
static void
initialize_bits_for_byte(void) ISC_CONSTRUCTOR;

/*
 * The bit positions have to be between SHIFT_BITMAP and SHIFT_OFFSET.
 *
 * Each byte range in between common hostname characters has a different
 * escape character, to preserve the correct lexical order.
 *
 * Escaped byte ranges mostly fit into the space available in the
 * bitmap, except for those above 'z' (which is mostly bytes with the
 * top bit set). So, when we reach the end of the bitmap we roll over
 * to the next escape character.
 *
 * After filling the table we ensure that the bit positions for
 * hostname characters and escape characters all fit.
 */
static void
initialize_bits_for_byte(void) {
	qp_shift bit_one = SHIFT_BITMAP;
	qp_shift bit_two = SHIFT_BITMAP;
	bool escaping = true;

	for (unsigned int byte = 0; byte < 256; byte++) {
		if (qp_common_character(byte)) {
			escaping = false;
			bit_one++;
			dns_qp_byte_for_bit[bit_one] = byte;
			dns_qp_bits_for_byte[byte] = bit_one;
		} else if ('A' <= byte && byte <= 'Z') {
			/* map upper case to lower case */
			qp_shift after_esc = bit_one + 1;
			qp_shift skip_punct = 'a' - '_';
			qp_shift letter = byte - 'A';
			qp_shift bit = after_esc + skip_punct + letter;
			dns_qp_bits_for_byte[byte] = bit;
			/* to simplify reverse conversion in the tests */
			bit_two++;
		} else {
			/* non-hostname characters need to be escaped */
			if (!escaping || bit_two >= SHIFT_OFFSET) {
				escaping = true;
				bit_one++;
				dns_qp_byte_for_bit[bit_one] = byte;
				bit_two = SHIFT_BITMAP;
			}
			dns_qp_bits_for_byte[byte] = bit_two << 8 | bit_one;
			bit_two++;
		}
	}
	ENSURE(bit_one < SHIFT_OFFSET);
}

/*
 * Convert a DNS name into a trie lookup key.
 *
 * Returns the length of the key.
 *
 * For performance we get our hands dirty in the guts of the name.
 *
 * We dont't worry about the distinction between absolute and relative
 * names. When the trie is only used with absolute names, the first byte
 * of the key will always be SHIFT_NOBYTE and it will always be skipped
 * when traversing the trie. So keeping the root label costs little, and
 * it allows us to support tries of relative names too. In fact absolute
 * and relative names can be mixed in the same trie without causing
 * confusion, because the presence or absence of the initial
 * SHIFT_NOBYTE in the key disambiguates them (exactly like a trailing
 * dot in a zone file).
 */
size_t
dns_qpkey_fromname(dns_qpkey_t key, const dns_name_t *name) {
	size_t off, label;

	REQUIRE(ISC_MAGIC_VALID(name, DNS_NAME_MAGIC));
	REQUIRE(name->offsets != NULL);
	REQUIRE(name->labels > 0);

	off = 0;
	label = name->labels;
	while (label-- > 0) {
		const uint8_t *ldata = name->ndata + name->offsets[label];
		size_t len = *ldata++;
		for (size_t byte = 0; byte < len; byte++) {
			uint16_t bits = dns_qp_bits_for_byte[ldata[byte]];
			key[off++] = bits & 0xFF;
			if ((bits >> 8) != 0) {
				key[off++] = bits >> 8;
			}
		}
		/* label terminator */
		key[off++] = SHIFT_NOBYTE;
	}
	/* mark end with a double NOBYTE */
	key[off] = SHIFT_NOBYTE;
	return (off);
}

/*
 * Sentinel value for equal keys
 */
#define QP_KEY_EQUAL (~(size_t)0)

/*
 * Compare two keys and return the offset where they differ.
 *
 * This offset is used to work out where a trie search diverged: when one
 * of the keys is in the trie and one is not, the common prefix (up to the
 * offset) is the part of the unknown key that exists in the trie. This
 * matters for adding new keys or finding neighbours of missing keys.
 *
 * When the keys are different lengths it is possible (but unwise) for
 * the longer key to be the same as the shorter key but with superfluous
 * trailing SHIFT_NOBYTE elements. This makes the keys equal for the
 * purpose of traversing the trie.
 */
static size_t
keycmp(const dns_qpkey_t keya, size_t lena, const dns_qpkey_t keyb,
       size_t lenb) {
	size_t len = ISC_MAX(lena, lenb);
	for (size_t off = 0; off < len; off++) {
		if (keybit(keya, lena, off) != keybit(keyb, lenb, off)) {
			return (off);
		}
	}
	return (QP_KEY_EQUAL);
}

/***********************************************************************
 *
 *  allocator wrappers
 */

#if FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

/*
 * Optionally (for debugging) during a copy-on-write transaction, use
 * memory protection to ensure that the shared chunks are not modified.
 * Once a chunk becomes shared, it remains read-only until it is freed.
 * POSIX says we have to use mmap() to get an allocation that we can
 * definitely pass to mprotect().
 */

static size_t
chunk_size_raw(void) {
	size_t size = (size_t)sysconf(_SC_PAGE_SIZE);
	return (ISC_MAX(size, QP_CHUNK_BYTES));
}

static void *
chunk_get_raw(dns_qp_t *qp) {
	if (qp->write_protect) {
		size_t size = chunk_size_raw();
		void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
				 MAP_ANON | MAP_PRIVATE, -1, 0);
		RUNTIME_CHECK(ptr != MAP_FAILED);
		return (ptr);
	} else {
		return (isc_mem_allocate(qp->mctx, QP_CHUNK_BYTES));
	}
}

static void
chunk_free_raw(dns_qp_t *qp, void *ptr) {
	if (qp->write_protect) {
		RUNTIME_CHECK(munmap(ptr, chunk_size_raw()) == 0);
	} else {
		isc_mem_free(qp->mctx, ptr);
	}
}

static void *
chunk_shrink_raw(dns_qp_t *qp, void *ptr, size_t bytes) {
	if (qp->write_protect) {
		return (ptr);
	} else {
		return (isc_mem_reallocate(qp->mctx, ptr, bytes));
	}
}

static void
write_protect(dns_qp_t *qp, void *ptr, bool readonly) {
	if (qp->write_protect) {
		int prot = readonly ? PROT_READ : PROT_READ | PROT_WRITE;
		size_t size = chunk_size_raw();
		RUNTIME_CHECK(mprotect(ptr, size, prot) >= 0);
	}
}

static void
write_protect_all(dns_qp_t *qp) {
	for (qp_chunk chunk = 0; chunk < qp->chunk_max; chunk++) {
		if (chunk != qp->bump && qp->base[chunk] != NULL) {
			write_protect(qp, qp->base[chunk], true);
		}
	}
}

#else

#define chunk_get_raw(qp)	isc_mem_allocate(qp->mctx, QP_CHUNK_BYTES)
#define chunk_free_raw(qp, ptr) isc_mem_free(qp->mctx, ptr)

#define chunk_shrink_raw(qp, ptr, size) isc_mem_reallocate(qp->mctx, ptr, size)

#define write_protect(qp, chunk, readonly)
#define write_protect_all(qp)

#endif

static void *
clone_array(isc_mem_t *mctx, void *oldp, size_t oldsz, size_t newsz,
	    size_t elemsz) {
	uint8_t *newp = NULL;

	INSIST(oldsz <= newsz);
	INSIST(newsz < UINT32_MAX);
	INSIST(elemsz < UINT32_MAX);
	INSIST(((uint64_t)newsz) * ((uint64_t)elemsz) <= UINT32_MAX);

	/* sometimes we clone an array before it has been populated */
	if (newsz > 0) {
		oldsz *= elemsz;
		newsz *= elemsz;
		newp = isc_mem_allocate(mctx, newsz);
		if (oldsz > 0) {
			memmove(newp, oldp, oldsz);
		}
		memset(newp + oldsz, 0, newsz - oldsz);
	}
	return (newp);
}

/***********************************************************************
 *
 *  allocator
 */

/*
 * How many cells are actually in use in a chunk?
 */
static inline qp_cell
chunk_usage(dns_qp_t *qp, qp_chunk chunk) {
	return (qp->usage[chunk].used - qp->usage[chunk].free);
}

/*
 * We can mutate a chunk if it was allocated in the current generation.
 * This might not be true for the `bump` chunk when it is reused.
 */
static inline bool
chunk_mutable(dns_qp_t *qp, qp_chunk chunk) {
	return (qp->usage[chunk].generation == qp->generation);
}

/*
 * When we reuse the bump chunk across multiple write transactions,
 * it can have an immutable prefix and a mutable suffix.
 */
static inline bool
twigs_mutable(dns_qp_t *qp, qp_ref ref) {
	qp_chunk chunk = refchunk(ref);
	qp_cell cell = refcell(ref);
	if (chunk == qp->bump) {
		return (cell >= qp->budding);
	} else {
		return (chunk_mutable(qp, chunk));
	}
}

/*
 * Create a fresh bump chunk and allocate some twigs from it.
 */
static qp_ref
chunk_alloc(dns_qp_t *qp, qp_chunk chunk, qp_weight size) {
	REQUIRE(qp->base[chunk] == NULL);
	REQUIRE(qp->usage[chunk].generation == 0);
	REQUIRE(qp->usage[chunk].used == 0);
	REQUIRE(qp->usage[chunk].free == 0);

	qp->base[chunk] = chunk_get_raw(qp);
	qp->usage[chunk].generation = qp->generation;
	qp->usage[chunk].used = size;
	qp->usage[chunk].free = 0;
	qp->used_count += size;
	qp->bump = chunk;
	qp->budding = 0;

	QP_TRACE("chunk %u gen %u base %p", chunk, qp->usage[chunk].generation,
		 qp->base[chunk]);
	return (makeref(chunk, 0));
}

static void
free_chunk_arrays(dns_qp_t *qp) {
	QP_TRACE("base %p usage %p max %u", qp->base, qp->usage, qp->chunk_max);
	/*
	 * They should both be null or both non-null; if they are out of sync,
	 * this will intentionally trigger an assert in `isc_mem_free()`.
	 */
	if (qp->base != NULL || qp->usage != NULL) {
		isc_mem_free(qp->mctx, qp->base);
		isc_mem_free(qp->mctx, qp->usage);
	}
}

/*
 * This is used both to grow the arrays when they fill up, and to copy them at
 * the start of an update transaction. We check if the old arrays are in use by
 * readers, in which case we will do safe memory reclamation later.
 */
static void
clone_chunk_arrays(dns_qp_t *qp, qp_chunk newmax) {
	qp_chunk oldmax;
	void *base, *usage;

	oldmax = qp->chunk_max;
	qp->chunk_max = newmax;

	base = clone_array(qp->mctx, qp->base, oldmax, newmax,
			   sizeof(*qp->base));
	usage = clone_array(qp->mctx, qp->usage, oldmax, newmax,
			    sizeof(*qp->usage));

	if (qp->shared_arrays) {
		qp->shared_arrays = false;
	} else {
		free_chunk_arrays(qp);
	}
	qp->base = base;
	qp->usage = usage;

	QP_TRACE("base %p usage %p max %u", qp->base, qp->usage, qp->chunk_max);
}

/*
 * There was no space in the bump chunk, so find a place to put a fresh
 * chunk in the chunk table, then allocate some twigs from it.
 */
static qp_ref
alloc_slow(dns_qp_t *qp, qp_weight size) {
	qp_chunk chunk;

	for (chunk = 0; chunk < qp->chunk_max; chunk++) {
		if (qp->base[chunk] == NULL) {
			return (chunk_alloc(qp, chunk, size));
		}
	}
	ENSURE(chunk == qp->chunk_max);
	clone_chunk_arrays(qp, GROWTH_FACTOR(chunk));
	return (chunk_alloc(qp, chunk, size));
}

/*
 * Allocate some fresh twigs. This is the bump allocator fast path.
 */
static inline qp_ref
alloc_twigs(dns_qp_t *qp, qp_weight size) {
	qp_chunk chunk = qp->bump;
	qp_cell cell = qp->usage[chunk].used;
	if (cell + size <= QP_CHUNK_SIZE) {
		qp->usage[chunk].used += size;
		qp->used_count += size;
		return (makeref(chunk, cell));
	} else {
		return (alloc_slow(qp, size));
	}
}

/*
 * Record that some twigs are no longer being used. NOTE: the caller is
 * responsible for detaching and/or zeroing the old twigs as required.
 */
static inline void
free_twigs(dns_qp_t *qp, qp_ref twigs, qp_weight size) {
	qp_chunk chunk = refchunk(twigs);
	qp->usage[chunk].free += size;
	qp->free_count += size;
	ENSURE(qp->usage[chunk].free <= qp->usage[chunk].used);
}

/***********************************************************************
 *
 *  chunk reclamation
 */

/*
 * When a chunk is being recycled after a long-running read transaction,
 * or after a rollback, we need to detach any leaves that remain.
 */
static void
chunk_free(dns_qp_t *qp, qp_chunk chunk) {
	QP_TRACE("chunk %u gen %u base %p", chunk, qp->usage[chunk].generation,
		 qp->base[chunk]);

	qp_node *n = qp->base[chunk];
	write_protect(qp, n, false);

	for (qp_cell count = qp->usage[chunk].used; count > 0; count--, n++) {
		if (!isbranch(n) && leaf_pval(n) != NULL) {
			detach_leaf(qp, n);
		}
	}
	chunk_free_raw(qp, qp->base[chunk]);

	INSIST(qp->used_count >= qp->usage[chunk].used);
	INSIST(qp->free_count >= qp->usage[chunk].free);
	qp->used_count -= qp->usage[chunk].used;
	qp->free_count -= qp->usage[chunk].free;
	qp->usage[chunk].used = 0;
	qp->usage[chunk].free = 0;
	qp->usage[chunk].generation = 0;
	qp->base[chunk] = NULL;
}

/*
 * If we have any nodes on hold during a transaction, we must leave
 * immutable chunks intact. As the last stage of safe memory reclamation,
 * we can clear the hold counter and recycle all empty chunks (even from a
 * nominally read-only `dns_qp_t`) because nothing refers to them any more.
 *
 * If we are using RCU, this can be called by `defer_rcu()` or `call_rcu()`
 * to clean up after readers have left their critical sections.
 */
static void
recycle(dns_qp_t *qp) {
	isc_time_t t0, t1;
	uint64_t time;
	unsigned int live = 0;
	unsigned int keep = 0;
	unsigned int free = 0;

	QP_TRACE("expect to free %u cells -> %u chunks",
		 (qp->free_count - qp->hold_count),
		 (qp->free_count - qp->hold_count) / QP_CHUNK_SIZE);

	isc_time_now_hires(&t0);

	for (qp_chunk chunk = 0; chunk < qp->chunk_max; chunk++) {
		if (qp->base[chunk] == NULL) {
			continue;
		} else if (chunk == qp->bump || chunk_usage(qp, chunk) > 0) {
			live++;
		} else if (chunk_mutable(qp, chunk) || qp->hold_count == 0) {
			chunk_free(qp, chunk);
			free++;
		} else {
			keep++;
		}
	}

	isc_time_now_hires(&t1);
	time = isc_time_microdiff(&t1, &t0);
	recycle_time += time;

	QP_LOG_STATS("qp recycle" PRItime "live %u keep %u free %u chunks",
		     time, live, keep, free);
	QP_LOG_STATS("qp recycle after leaf %u live %u used %u free %u hold %u",
		     qp->leaf_count, qp->used_count - qp->free_count,
		     qp->used_count, qp->free_count, qp->hold_count);
}

/***********************************************************************
 *
 *  garbage collector
 */

/*
 * A node's twigs need to be evacuated when they are in a fragmented chunk.
 */
static inline bool
should_evacuate(dns_qp_t *qp, qp_node *n) {
	return (qp->usage[refchunk(twigref(n))].free > QP_MAX_FREE ||
		qp->compact_all);
}

/*
 * Move a node's twigs to the `bump` chunk, for copy-on-write or for
 * garbage collection. We don't update the node in place because
 * `compact_recursive()` does not ensure the node is mutable until
 * after it discovers evacuation was necessary.
 */
static qp_ref
evacuate_twigs(dns_qp_t *qp, qp_node *n) {
	qp_weight max = twigmax(n);
	qp_ref oldref = twigref(n);
	qp_ref newref = alloc_twigs(qp, max);
	qp_node *oldptr = refptr(qp, oldref);
	qp_node *newptr = refptr(qp, newref);

	twigmove(newptr, oldptr, max);
	free_twigs(qp, oldref, max);

	if (twigs_mutable(qp, oldref)) {
		/* so that chunk_free() skips these twigs */
		twigzero(oldptr, max);
	} else {
		qp->hold_count += max;
		ENSURE(qp->free_count >= qp->hold_count);
		for (qp_weight pos = 0; pos < max; pos++) {
			qp_node *twig = newptr + pos;
			if (!isbranch(twig)) {
				attach_leaf(qp, twig);
			}
		}
	}

	return (newref);
}

/*
 * Evacuate the node's twigs and update the node in place.
 */
static void
evacuate(dns_qp_t *qp, qp_node *n) {
	*n = newnode(branch_index(n), evacuate_twigs(qp, n));
}

/*
 * Compact the trie by traversing the whole thing recursively, copying
 * bottom-up as required. The aim is to avoid evacuation as much as
 * possible, but when parts of the trie are shared, we need to evacuate
 * the paths from the root to the parts of the trie that occupy
 * fragmented chunks.
 *
 * Without the should_evacuate() check, the algorithm will leave the
 * trie unchanged. If this node's twigs are all leaves, the loop
 * changes nothing, so we will return this node's original ref. If
 * this node's twigs are all leaves or unchanged branches, again, the
 * loop changes nothing. So the should_evacuate() check is the only
 * place that the algorithm introduces ref changes, that then bubble
 * up through the logic inside the loop.
 */
static qp_ref
compact_recursive(dns_qp_t *qp, qp_node *n) {
	qp_ref ref = twigref(n);
	if (should_evacuate(qp, n)) {
		ref = evacuate_twigs(qp, n);
	}
	bool mutable = twigs_mutable(qp, ref);
	qp_weight max = twigmax(n);
	for (qp_weight pos = 0; pos < max; pos++) {
		qp_node *t = refptr(qp, ref) + pos;
		if (!isbranch(t)) {
			continue;
		}
		qp_ref oldref = twigref(t);
		qp_ref newref = compact_recursive(qp, t);
		if (oldref == newref) {
			continue;
		}
		if (!mutable) {
			ref = evacuate_twigs(qp, n);
			/* the twigs have moved */
			t = refptr(qp, ref) + pos;
			mutable = true;
		}
		*t = newnode(branch_index(t), newref);
	}
	return (ref);
}

static void
compact(dns_qp_t *qp) {
	isc_time_t t0, t1;
	uint64_t time;

	QP_LOG_STATS(
		"qp compact before leaf %u live %u used %u free %u hold %u",
		qp->leaf_count, qp->used_count - qp->free_count, qp->used_count,
		qp->free_count, qp->hold_count);

	isc_time_now_hires(&t0);

	/*
	 * Reset the bump chunk if it is fragmented.
	 */
	if (qp->usage[qp->bump].free > QP_MAX_FREE) {
		alloc_slow(qp, 0);
	}

	if (isbranch(&qp->root)) {
		qp->root = newnode(branch_index(&qp->root),
				   compact_recursive(qp, &qp->root));
	}
	qp->compact_all = false;

	isc_time_now_hires(&t1);
	time = isc_time_microdiff(&t1, &t0);
	compact_time += time;

	QP_LOG_STATS("qp compact" PRItime
		     "leaf %u live %u used %u free %u hold %u",
		     time, qp->leaf_count, qp->used_count - qp->free_count,
		     qp->used_count, qp->free_count, qp->hold_count);
}

void
dns_qp_compact(dns_qp_t *qp) {
	REQUIRE(VALID_QP(qp));
	qp->compact_all = true;
	compact(qp);
	recycle(qp);
}

static void
auto_compact_recycle(dns_qp_t *qp) {
	compact(qp);
	recycle(qp);
	/*
	 * This shouldn't happen if the garbage collector is
	 * working correctly. We can recover at the cost of some
	 * time and space, but recovery should be cheaper than
	 * letting compact+recycle fail repeatedly.
	 */
	if (QP_MAX_GARBAGE(qp)) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_QP, ISC_LOG_NOTICE,
			      "qp %p ctx \"%s\" compact/recycle "
			      "failed to recover any space, "
			      "scheduling a full compaction",
			      qp, triename(qp, (char[256]){}, 256));
		qp->compact_all = true;
	}
}

/*
 * This is used by the modification functions, which need to ensure that
 * there isn't a spurious double detach when the chunk is later
 * recycled. Also, we might need to compact the trie; the space
 * accounting is similar to `evacuate_twigs()` above.
 *
 * NOTE: the caller is responsible for detaching any old leaves as
 * required.
 *
 * Aside: In typical garbage collectors, compaction is triggered when
 * the allocator runs out of space. But that is because typical garbage
 * collectors do not know how much memory can be recovered, so they must
 * find out by scanning the heap. The qp-trie code was originally
 * designed to use malloc() and free(), so it has more information about
 * when garbage collection might be worthwhile. Hence we can trigger
 * collection when garbage passes a threshold.
 *
 * XXXFANF: If we need to avoid latency outliers caused by compaction in
 * write transactions, we can check qp->transaction_mode here.
 */
static inline void
wipe_twigs(dns_qp_t *qp, qp_ref twigs, qp_weight max) {
	free_twigs(qp, twigs, max);
	if (twigs_mutable(qp, twigs)) {
		twigzero(refptr(qp, twigs), max);
		if (QP_MAX_GARBAGE(qp)) {
			auto_compact_recycle(qp);
		}
	} else {
		qp->hold_count += max;
		ENSURE(qp->free_count >= qp->hold_count);
	}
}

/*
 * Shared twigs need copy-on-write. As we walk down the trie finding the
 * right place to modify, twigcow() is called to ensure that shared nodes
 * on the path from the root are copied to a mutable chunk.
 */
static inline void
twigcow(dns_qp_t *qp, struct qp_node *n) {
	if (!twigs_mutable(qp, twigref(n))) {
		evacuate(qp, n);
	}
}

/***********************************************************************
 *
 *  public accessors for memory management internals
 */

dns_qp_memusage_t
dns_qp_memusage(dns_qp_t *qp) {
	REQUIRE(VALID_QP(qp));

	dns_qp_memusage_t memusage = {
		.ctx = qp->ctx,
		.leaves = qp->leaf_count,
		.live = qp->used_count - qp->free_count,
		.used = qp->used_count,
		.hold = qp->hold_count,
		.free = qp->free_count,
		.node_size = sizeof(qp_node),
		.chunk_size = QP_CHUNK_SIZE,
	};

	for (qp_chunk chunk = 0; chunk < qp->chunk_max; chunk++) {
		if (qp->base[chunk] != NULL) {
			memusage.chunk_count += 1;
		}
	}

	/* slight over-estimate if chunks have been shrunk */
	memusage.bytes = memusage.chunk_count * QP_CHUNK_BYTES +
			 qp->chunk_max * sizeof(*qp->base) +
			 qp->chunk_max * sizeof(*qp->usage);

	return (memusage);
}

void
dns_qp_gctime(uint64_t *compact_p, uint64_t *recycle_p, uint64_t *rollback_p) {
	*compact_p = compact_time;
	*recycle_p = recycle_time;
	*rollback_p = rollback_time;
}

/***********************************************************************
 *
 *  read-write transactions
 */

static dns_qp_t *
transaction_open(dns_qpmulti_t *multi, dns_qp_t **qptp) {
	dns_qp_t *qp, *old;

	REQUIRE(VALID_QPMULTI(multi));
	REQUIRE(qptp != NULL && *qptp == NULL);

	LOCK(&multi->mutex);

	old = multi->read;
	qp = write_phase(multi);

	INSIST(VALID_QP(old));
	INSIST(!VALID_QP(qp));

	/*
	 * prepare for copy-on-write
	 */
	*qp = *old;
	qp->shared_arrays = true;
	qp->hold_count = qp->free_count;

	/*
	 * Start a new generation, and ensure it isn't zero because we
	 * want to avoid confusion with unset qp->usage structures.
	 */
	if (++qp->generation == 0) {
		++qp->generation;
	}

	*qptp = qp;
	return (qp);
}

/*
 * a write is light
 *
 * We need to ensure we alloce from a fresh chunk if the last transaction
 * shrunk the bump chunk; but usually in a sequence of write transactions
 * we just mark the point where we started this generation.
 *
 * (Instead of keeping the previous transaction's mode, I considered
 * forcing allocation into the slow path by fiddling with the bump
 * chunk's usage counters. But that is troublesome because
 * `chunk_free_now()` needs to know how much of the chunk to scan.)
 */
void
dns_qpmulti_write(dns_qpmulti_t *multi, dns_qp_t **qptp) {
	dns_qp_t *qp = transaction_open(multi, qptp);
	QP_TRACE("");

	if (qp->transaction_mode == QP_UPDATE) {
		alloc_slow(qp, 0);
	} else {
		qp->budding = qp->usage[qp->bump].used;
	}

	qp->transaction_mode = QP_WRITE;
	write_protect_all(qp);
}

/*
 * an update is heavy
 *
 * Make sure we have copies of all usage counters so that we can rollback.
 * Do this before allocating a bump chunk so that all chunks allocated in
 * this transaction are in the fresh chunk arrays. (If the existing chunk
 * arrays happen to be full we might immediately clone them a second time.
 * Probably not worth worrying about?)
 */
void
dns_qpmulti_update(dns_qpmulti_t *multi, dns_qp_t **qptp) {
	dns_qp_t *qp = transaction_open(multi, qptp);
	QP_TRACE("");

	clone_chunk_arrays(qp, qp->chunk_max);
	alloc_slow(qp, 0);

	qp->transaction_mode = QP_UPDATE;
	write_protect_all(qp);
}

void
dns_qpmulti_commit(dns_qpmulti_t *multi, dns_qp_t **qptp) {
	dns_qp_t *qp, *old;

	REQUIRE(VALID_QPMULTI(multi));
	REQUIRE(qptp != NULL);
	REQUIRE(*qptp == write_phase(multi));

	old = multi->read;
	qp = write_phase(multi);

	QP_TRACE("");

	if (qp->transaction_mode == QP_UPDATE) {
		qp_chunk c;
		size_t bytes;

		compact(qp);
		c = qp->bump;
		bytes = qp->usage[c].used * sizeof(qp_node);
		if (bytes == 0) {
			chunk_free(qp, c);
		} else {
			qp->base[c] = chunk_shrink_raw(qp, qp->base[c], bytes);
		}
	}

#if HAVE_LIBURCU
	rcu_assign_pointer(multi->read, qp);
	/*
	 * XXXFANF: At this point we need to wait for a grace period (to be
	 * sure readers have finished) before recovering memory. This is not
	 * very fast, hurting write throughput. To fix it we need read
	 * transactions to be able to survive multiple write transactions, so
	 * that it matters less if we are slow to detect when readers have
	 * exited their critical sections. Instead of the current read / snap
	 * distinction, we need to allocate a read snapshot when a
	 * transaction commits, and clean it up (along with the unused
	 * chunks) in an rcu callback.
	 */
	synchronize_rcu();
#else
	RWLOCK(&multi->rwlock, isc_rwlocktype_write);
	multi->read = qp;
	RWUNLOCK(&multi->rwlock, isc_rwlocktype_write);
#endif

	/*
	 * Were the chunk arrays reallocated at some point?
	 */
	if (qp->shared_arrays) {
		INSIST(old->base == qp->base);
		INSIST(old->usage == qp->usage);
		/* this becomes correct when `*old` is invalidated */
		qp->shared_arrays = false;
	} else {
		INSIST(old->base != qp->base);
		INSIST(old->usage != qp->usage);
		free_chunk_arrays(old);
	}

	/*
	 * It is safe to recycle all empty chunks if they aren't being
	 * used by snapshots.
	 */
	qp->hold_count = 0;
	if (multi->snapshots == 0) {
		recycle(qp);
	}

	*old = (dns_qp_t){};
	*qptp = NULL;
	UNLOCK(&multi->mutex);
}

/*
 * Throw away everything that was allocated during this transaction.
 */
void
dns_qpmulti_rollback(dns_qpmulti_t *multi, dns_qp_t **qptp) {
	dns_qp_t *qp;
	isc_time_t t0, t1;
	uint64_t time;
	unsigned int free = 0;

	REQUIRE(VALID_QPMULTI(multi));
	REQUIRE(qptp != NULL);
	REQUIRE(*qptp == write_phase(multi));

	qp = *qptp;

	REQUIRE(qp->transaction_mode == QP_UPDATE);
	QP_TRACE("");

	isc_time_now_hires(&t0);

	/*
	 * recycle any chunks allocated in this transaction,
	 * including the bump chunk, and detach value objects
	 */
	for (qp_chunk chunk = 0; chunk < qp->chunk_max; chunk++) {
		if (qp->base[chunk] != NULL && chunk_mutable(qp, chunk)) {
			chunk_free(qp, chunk);
			free++;
		}
	}

	/* free the cloned arrays */
	INSIST(!qp->shared_arrays);
	free_chunk_arrays(qp);

	isc_time_now_hires(&t1);
	time = isc_time_microdiff(&t1, &t0);
	rollback_time += time;

	QP_LOG_STATS("qp rollback" PRItime "free %u chunks", time, free);

	*qp = (dns_qp_t){};
	*qptp = NULL;
	UNLOCK(&multi->mutex);
}

/***********************************************************************
 *
 *  read-only transactions
 */

/*
 * a query is light
 */

void
dns_qpmulti_query(dns_qpmulti_t *multi, dns_qpread_t **qprp) {
	REQUIRE(VALID_QPMULTI(multi));
	REQUIRE(qprp != NULL && *qprp == NULL);

#if HAVE_LIBURCU
	rcu_read_lock();
	*qprp = (dns_qpread_t *)rcu_dereference(multi->read);
#else
	RWLOCK(&multi->rwlock, isc_rwlocktype_read);
	*qprp = (dns_qpread_t *)multi->read;
#endif
}

void
dns_qpread_destroy(dns_qpmulti_t *multi, dns_qpread_t **qprp) {
	REQUIRE(VALID_QPMULTI(multi));
	REQUIRE(qprp != NULL && *qprp != NULL);

	/*
	 * when we are using RCU, then multi->read can change during
	 * our critical section, so it can be different from *qprp
	 */
	dns_qp_t *qp = (dns_qp_t *)*qprp;
	*qprp = NULL;
	REQUIRE(qp == &multi->phase[0] || qp == &multi->phase[1]);

#if HAVE_LIBURCU
	rcu_read_unlock();
#else
	RWUNLOCK(&multi->rwlock, isc_rwlocktype_read);
#endif
}

/*
 * a snapshot is heavy
 */

void
dns_qpmulti_snapshot(dns_qpmulti_t *multi, dns_qpsnap_t **qpsp) {
	dns_qp_t *old;
	dns_qpsnap_t *qp;
	size_t array_size, alloc_size;

	REQUIRE(VALID_QPMULTI(multi));
	REQUIRE(qpsp != NULL && *qpsp == NULL);

	/*
	 * we need a consistent view of the chunk base array and chunk_max so
	 * we can't use the rwlock here (nor can we use dns_qpmulti_query)
	 */
	LOCK(&multi->mutex);
	old = multi->read;

	array_size = sizeof(qp_node *) * old->chunk_max;
	alloc_size = sizeof(dns_qpsnap_t) + array_size;
	qp = isc_mem_allocate(old->mctx, alloc_size);
	*qp = (dns_qpsnap_t){
		.magic = QP_MAGIC,
		.root = old->root,
		.methods = old->methods,
		.ctx = old->ctx,
		.generation = old->generation,
		.base = qp->base_array,
		.whence = multi,
	};
	/* sometimes we take a snapshot of an empty trie */
	if (array_size > 0) {
		memmove(qp->base, old->base, array_size);
	}

	multi->snapshots++;
	*qpsp = qp;

	QP_TRACE("multi %p snaps %u", multi, multi->snapshots);
	UNLOCK(&multi->mutex);
}

void
dns_qpsnap_destroy(dns_qpmulti_t *multi, dns_qpsnap_t **qpsp) {
	dns_qpsnap_t *qp;

	REQUIRE(VALID_QPMULTI(multi));
	REQUIRE(qpsp != NULL && *qpsp != NULL);

	qp = *qpsp;
	*qpsp = NULL;

	/*
	 * `multi` and `whence` are redundant, but it helps
	 * to make sure the API is being used correctly
	 */
	REQUIRE(multi == qp->whence);

	LOCK(&multi->mutex);
	QP_TRACE("multi %p snaps %u gen %u", multi, multi->snapshots,
		 multi->read->generation);

	isc_mem_free(multi->read->mctx, qp);
	multi->snapshots--;
	if (multi->snapshots == 0) {
		/*
		 * Clean up if there were updates while we were working,
		 * and we are the last snapshot keeping the memory alive
		 */
		recycle(multi->read);
	}
	UNLOCK(&multi->mutex);
}

/***********************************************************************
 *
 *  constructors, destructors
 */

static void
initialize_guts(isc_mem_t *mctx, const dns_qpmethods_t *methods, void *ctx,
		dns_qp_t *qp) {
	REQUIRE(methods != NULL);
	REQUIRE(methods->attach != NULL);
	REQUIRE(methods->detach != NULL);
	REQUIRE(methods->makekey != NULL);
	REQUIRE(methods->triename != NULL);

	*qp = (dns_qp_t){
		.magic = QP_MAGIC,
		.methods = methods,
		.ctx = ctx,
	};
	isc_mem_attach(mctx, &qp->mctx);
}

void
dns_qp_create(isc_mem_t *mctx, const dns_qpmethods_t *methods, void *ctx,
	      dns_qp_t **qptp) {
	dns_qp_t *qp;

	REQUIRE(qptp != NULL && *qptp == NULL);

	qp = isc_mem_get(mctx, sizeof(*qp));
	initialize_guts(mctx, methods, ctx, qp);
	alloc_slow(qp, 0);
	QP_TRACE("");
	*qptp = qp;
}

void
dns_qpmulti_create(isc_mem_t *mctx, const dns_qpmethods_t *methods, void *ctx,
		   dns_qpmulti_t **qpmp) {
	dns_qpmulti_t *multi;
	dns_qp_t *qp;

	REQUIRE(qpmp != NULL && *qpmp == NULL);

	multi = isc_mem_get(mctx, sizeof(*multi));
	*multi = (dns_qpmulti_t){
		.magic = QPMULTI_MAGIC,
		.read = &multi->phase[0],
	};
	isc_rwlock_init(&multi->rwlock, 0, 0);
	isc_mutex_init(&multi->mutex);

	/*
	 * Do not waste effort allocating a bump chunk that will be thrown
	 * away when a transaction is opened. dns_qpmulti_update() always
	 * allocates; to ensure dns_qpmulti_write() does too, pretend the
	 * previous transaction was an update
	 */
	qp = multi->read;
	initialize_guts(mctx, methods, ctx, qp);
	qp->transaction_mode = QP_UPDATE;
	QP_TRACE("");
	*qpmp = multi;
}

static void
destroy_guts(dns_qp_t *qp) {
	if (qp->leaf_count == 1) {
		detach_leaf(qp, &qp->root);
	}
	if (qp->chunk_max == 0) {
		return;
	}
	for (qp_chunk chunk = 0; chunk < qp->chunk_max; chunk++) {
		if (qp->base[chunk] != NULL) {
			chunk_free(qp, chunk);
		}
	}
	ENSURE(qp->used_count == 0);
	ENSURE(qp->free_count == 0);
	ENSURE(qp->hold_count == 0);
	free_chunk_arrays(qp);
}

void
dns_qp_destroy(dns_qp_t **qptp) {
	dns_qp_t *qp;

	REQUIRE(qptp != NULL);
	REQUIRE(VALID_QP(*qptp));

	qp = *qptp;
	*qptp = NULL;

	/* do not try to destroy part of a dns_qpmulti_t */
	REQUIRE(qp->transaction_mode == QP_NONE);

	QP_TRACE("");
	destroy_guts(qp);
	isc_mem_putanddetach(&qp->mctx, qp, sizeof(*qp));
}

void
dns_qpmulti_destroy(dns_qpmulti_t **qpmp) {
	dns_qp_t *qp = NULL;
	dns_qpmulti_t *multi = NULL;

	REQUIRE(qpmp != NULL);
	REQUIRE(VALID_QPMULTI(*qpmp));

	multi = *qpmp;
	qp = multi->read;
	*qpmp = NULL;

	REQUIRE(VALID_QP(qp));
	REQUIRE(!VALID_QP(write_phase(multi)));
	REQUIRE(multi->snapshots == 0);

	QP_TRACE("");
	destroy_guts(qp);
	isc_mutex_destroy(&multi->mutex);
	isc_rwlock_destroy(&multi->rwlock);
	isc_mem_putanddetach(&qp->mctx, multi, sizeof(*multi));
}

/***********************************************************************
 *
 *  modification
 */

isc_result_t
dns_qp_insert(dns_qp_t *qp, void *pval, uint32_t ival) {
	qp_ref newr, oldr;
	qp_node newn, oldn;
	qp_node *newp, *oldp;
	qp_shift newb, oldb;
	dns_qpkey_t newk, oldk;
	size_t newl, oldl;
	size_t off;
	uint64_t index;
	qp_shift bit;
	qp_weight pos, max;
	qp_node *n;

	REQUIRE(VALID_QP(qp));

	newn = newleaf(pval, ival);
	newl = leaf_key(qp, &newn, newk);

	/* first leaf in an empty trie? */
	if (qp->leaf_count == 0) {
		qp->root = newn;
		qp->leaf_count++;
		attach_leaf(qp, &newn);
		return (ISC_R_SUCCESS);
	}

	/*
	 * We need to keep searching down to a leaf even if our key is
	 * missing from this branch. It doesn't matter which twig we
	 * choose since the keys are all the same up to this node's
	 * offset. Note that if we simply use twigpos(n, bit) we may get
	 * an out-of-bounds access if our bit is greater than all the
	 * set bits in the node.
	 */
	n = &qp->root;
	while (isbranch(n)) {
		__builtin_prefetch(twig(qp, n, 0));
		bit = twigbit(n, newk, newl);
		pos = hastwig(n, bit) ? twigpos(n, bit) : 0;
		n = twig(qp, n, pos);
	}

	/* do the keys differ, and if so, where? */
	oldl = leaf_key(qp, n, oldk);
	off = keycmp(newk, newl, oldk, oldl);
	if (off == QP_KEY_EQUAL) {
		return (ISC_R_EXISTS);
	}
	newb = keybit(newk, newl, off);
	oldb = keybit(oldk, oldl, off);

	qp->leaf_count++;
	attach_leaf(qp, &newn);

	/* find where to insert a branch or grow an existing branch. */
	n = &qp->root;
	while (isbranch(n)) {
		__builtin_prefetch(twig(qp, n, 0));
		if (off < keyoff(n)) {
			goto newbranch;
		}
		if (off == keyoff(n)) {
			goto growbranch;
		}
		twigcow(qp, n);
		bit = twigbit(n, newk, newl);
		INSIST(hastwig(n, bit));
		n = twig(qp, n, twigpos(n, bit));
	}

newbranch:
	newr = alloc_twigs(qp, 2);
	newp = refptr(qp, newr);
	oldn = *n; /* save before overwriting. */
	index = BRANCH_TAG | (1ULL << newb) | (1ULL << oldb) |
		((uint64_t)off << SHIFT_OFFSET);
	*n = newnode(index, newr);
	newp[oldb < newb] = newn;
	newp[newb < oldb] = oldn;
	return (ISC_R_SUCCESS);

growbranch:
	INSIST(!hastwig(n, newb));
	pos = twigpos(n, newb);
	max = twigmax(n);
	oldr = twigref(n);
	newr = alloc_twigs(qp, max + 1);
	index = branch_index(n) | (1ULL << newb);
	*n = newnode(index, newr);
	oldp = refptr(qp, oldr);
	newp = refptr(qp, newr);
	twigmove(newp, oldp, pos);
	newp[pos] = newn;
	twigmove(newp + pos + 1, oldp + pos, max - pos);
	wipe_twigs(qp, oldr, max);
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_qp_deletekey(dns_qp_t *qp, const dns_qpkey_t searchk, size_t searchl) {
	dns_qpkey_t foundk;
	size_t foundl;
	qp_shift bit = 0; /* suppress warning */
	qp_weight pos, max;
	qp_ref ref;
	qp_node *twigs;
	qp_node *p; /* parent */
	qp_node *n; /* current node */

	REQUIRE(VALID_QP(qp));

	p = NULL;
	n = &qp->root;
	while (isbranch(n)) {
		__builtin_prefetch(twig(qp, n, 0));
		bit = twigbit(n, searchk, searchl);
		if (!hastwig(n, bit)) {
			return (ISC_R_NOTFOUND);
		}
		twigcow(qp, n);
		p = n;
		n = twig(qp, n, twigpos(n, bit));
	}

	/* empty trie? */
	if (leaf_pval(n) == NULL) {
		return (ISC_R_NOTFOUND);
	}

	foundl = leaf_key(qp, n, foundk);
	if (keycmp(searchk, searchl, foundk, foundl) != QP_KEY_EQUAL) {
		return (ISC_R_NOTFOUND);
	}

	qp->leaf_count--;
	detach_leaf(qp, n);

	/* trie becomes empty */
	if (qp->leaf_count == 0) {
		INSIST(n == &qp->root && p == NULL);
		twigzero(n, 1);
		return (ISC_R_SUCCESS);
	}

	/* step back to parent node */
	n = p;
	p = NULL;

	INSIST(bit != 0);
	max = twigmax(n);
	pos = twigpos(n, bit);
	ref = twigref(n);
	twigs = refptr(qp, ref);

	if (max == 2) {
		/*
		 * move the other twig to the parent branch.
		 */
		*n = twigs[!pos];
		wipe_twigs(qp, ref, 2);
	} else {
		/*
		 * shrink the twigs in place, to avoid using the bump
		 * chunk too fast - the gc will clean up after us
		 */
		*n = newnode(branch_index(n) & ~(1ULL << bit), ref);
		twigmove(twigs + pos, twigs + pos + 1, max - pos - 1);
		wipe_twigs(qp, ref + max - 1, 1);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_qp_deletename(dns_qp_t *qp, const dns_name_t *name) {
	dns_qpkey_t key;
	size_t len = dns_qpkey_fromname(key, name);
	return (dns_qp_deletekey(qp, key, len));
}

/***********************************************************************
 *
 *  search
 */

isc_result_t
dns_qp_getkey(dns_qpreadable_t qpr, const dns_qpkey_t searchk, size_t searchl,
	      void **pval_r, uint32_t *ival_r) {
	dns_qpread_t *qp = dns_qpreadable_cast(qpr);
	dns_qpkey_t foundk;
	size_t foundl;
	qp_shift bit;
	qp_node *n;

	REQUIRE(VALID_QP(qp));
	REQUIRE(pval_r != NULL);
	REQUIRE(ival_r != NULL);

	n = &qp->root;
	while (isbranch(n)) {
		__builtin_prefetch(twig(qp, n, 0));
		bit = twigbit(n, searchk, searchl);
		if (!hastwig(n, bit)) {
			return (ISC_R_NOTFOUND);
		}
		n = twig(qp, n, twigpos(n, bit));
	}

	/* empty trie? */
	if (leaf_pval(n) == NULL) {
		return (ISC_R_NOTFOUND);
	}

	foundl = leaf_key(qp, n, foundk);
	if (keycmp(searchk, searchl, foundk, foundl) != QP_KEY_EQUAL) {
		return (ISC_R_NOTFOUND);
	}

	*pval_r = leaf_pval(n);
	*ival_r = leaf_ival(n);
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_qp_getname(dns_qpreadable_t qpr, const dns_name_t *name, void **pval_r,
	       uint32_t *ival_r) {
	dns_qpkey_t key;
	size_t len = dns_qpkey_fromname(key, name);
	return (dns_qp_getkey(qpr, key, len, pval_r, ival_r));
}

/**********************************************************************/
