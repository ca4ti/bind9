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

#pragma once

/***********************************************************************
 *
 *  interior node basics
 */

/*
 * A qp-trie node can be a leaf or a branch. It consists of three 32-bit words
 * into which the components are packed. They are used as a 64-bit word and a
 * 32-bit word, but they are not declared like that to avoid unwanted padding,
 * keeping the size down to 12 bytes. They are in native endian order so getting
 * the 64-bit part should compile down to an unaligned load.
 *
 * In a branch the 64-bit word is described by the enum below. The 32-bit word
 * is a reference to the packed sparse vector of "twigs", i.e. child nodes. A
 * branch node has at least 2 and less than SHIFT_OFFSET twigs (see the enum
 * below). The qp-trie update functions ensure that branches actually branch,
 * i.e. branches cannot have only 1 child.
 *
 * The contents of each leaf are set by the trie's user. The 64-bit word
 * contains a word-aligned pointer value, and the 32-bit word is an
 * arbitrary integer value.
 */
typedef struct qp_node {
#if WORDS_BIGENDIAN
	uint32_t bighi, biglo, small;
#else
	uint32_t biglo, bighi, small;
#endif
} qp_node;

/*
 * A branch node contains a 64-bit word comprising the branch/leaf tag,
 * the bitmap, and an offset into the key. It is called an "index word"
 * because it describes how to access the twigs vector (think "database
 * index"). The following enum sets up the bit positions of these parts.
 *
 * In a leaf, the same 64-bit word contains a pointer. The pointer
 * must be word-aligned so that the branch/leaf tag bit is zero.
 *
 * The bitmap is just above the tag bit. The `bits_for_byte[]` table is
 * used to fill in a key so that bit tests can work directly against the
 * index word without superfluous masking or shifting; we don't need to
 * mask out the bitmap before testing a bit, but we do need to mask the
 * bitmap before calling popcount.
 *
 * The byte offset into the key is at the top of the word, so that it
 * can be extracted with just a shift, with no masking needed.
 *
 * The names are SHIFT_thing because they are qp_shift values. (See
 * below for the various `qp_*` type declarations.)
 */
enum {
	SHIFT_BRANCH = 0,  /* branch / leaf tag */
	SHIFT_NOBYTE,	   /* label separator has no byte value */
	SHIFT_BITMAP,	   /* many bits here */
	SHIFT_OFFSET = 48, /* offset of byte in key */
};

/*
 * Value of the node type tag bit.
 */
#define BRANCH_TAG (1ULL << SHIFT_BRANCH)

/***********************************************************************
 *
 *  garbage collector tuning parameters
 */

/*
 * A "cell" is a location that can contain a `qp_node`, and a "chunk"
 * is a moderately large array of cells. A big trie can occupy
 * multiple chunks. (Unlike other nodes, a trie's root node lives in
 * its `struct dns_qp` instead of being allocated in a cell.)
 *
 * The qp-trie allocator hands out space for twigs vectors. Allocations are
 * made sequentially from one of the chunks; this kind of "sequential
 * allocator" is also known as a "bump allocator", so in `struct dns_qp`
 * (see below) the allocation chunk is called `bump`.
 */

/*
 * Number of cells in a chunk is a power of 2, which must have space for
 * a full twigs vector (48 wide). When testing, use a much smaller chunk
 * size to make the allocator work harder.
 */
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define QP_CHUNK_LOG 7
#else
#define QP_CHUNK_LOG 10
#endif

STATIC_ASSERT(6 <= QP_CHUNK_LOG && QP_CHUNK_LOG <= 20,
	      "qp-trie chunk size is unreasonable");

#define QP_CHUNK_SIZE  (1U << QP_CHUNK_LOG)
#define QP_CHUNK_BYTES (QP_CHUNK_SIZE * sizeof(qp_node))

/*
 * A chunk needs to be compacted if it has fragmented this much.
 * (12% overhead seems reasonable)
 */
#define QP_MAX_FREE (QP_CHUNK_SIZE / 8)

/*
 * Compact automatically when we pass this threshold: when there is a lot
 * of free space in absolute terms, and when we have freed more than half
 * of the space we allocated.
 *
 * The current compaction algorithm scans the whole trie, so it is important
 * to scale the threshold based on the size of the trie to avoid quadratic
 * behaviour. XXXFANF find an algorithm that scans less of the trie!
 *
 * During a modification transaction, when we copy-on-write some twigs we
 * count the old copy as "free", because they will be when the transaction
 * commits. But they cannot be recovered immediately so they are also
 * counted as on hold, and discounted when we decide whether to compact.
 */
#define QP_MAX_GARBAGE(qp)                                            \
	(((qp)->free_count - (qp)->hold_count) > QP_CHUNK_SIZE * 4 && \
	 ((qp)->free_count - (qp)->hold_count) > (qp)->used_count / 2)

/*
 * The chunk base and usage arrays are resized geometically and start off
 * with two entries.
 */
#define GROWTH_FACTOR(size) ((size) + (size) / 2 + 2)

/***********************************************************************
 *
 *  helper types
 */

/*
 * C is not strict enough with its integer types for these typedefs to
 * improve type safety, but it helps to have annotations saying what
 * particular kind of number we are dealing with.
 */

/*
 * The number or position of a bit inside a word. (0..63)
 *
 * Note: A dns_qpkey_t is logically an array of qp_shift values, but it
 * isn't declared that way because dns_qpkey_t is a public type whereas
 * qp_shift is private.
 */
typedef uint8_t qp_shift;

/*
 * The number of bits set in a word (as in Hamming weight or popcount)
 * which is used for the position of a node in the packed sparse
 * vector of twigs. (0..47) because our bitmap does not fill the word.
 */
typedef uint8_t qp_weight;

/*
 * A chunk number, i.e. an index into the chunk arrays.
 */
typedef uint32_t qp_chunk;

/*
 * Cell offset within a chunk, or a count of cells. Each cell in a
 * chunk can contain a node.
 */
typedef uint32_t qp_cell;

/*
 * A twig reference is used to refer to a twigs vector, which occupies a
 * contiguous group of cells.
 */
typedef uint32_t qp_ref;

/*
 * Constructors and accessors for qp_ref values, defined here to show
 * how the qp_ref, qp_chunk, qp_cell types relate to each other
 */

static inline qp_ref
makeref(qp_chunk chunk, qp_cell cell) {
	return (QP_CHUNK_SIZE * chunk + cell);
}

static inline qp_chunk
refchunk(qp_ref ref) {
	return (ref / QP_CHUNK_SIZE);
}

static inline qp_cell
refcell(qp_ref ref) {
	return (ref % QP_CHUNK_SIZE);
}

/***********************************************************************
 *
 *  main qp-trie structures
 */

#define QP_MAGIC     ISC_MAGIC('t', 'r', 'i', 'e')
#define VALID_QP(qp) ISC_MAGIC_VALID(qp, QP_MAGIC)

/*
 * This is annoying: C doesn't allow us to use a predeclared structure as
 * an anonymous struct member, so we have to fart around. The feature we
 * want is available in GCC and Clang with -fms-extensions, but a
 * non-standard extension won't make these declarations neater if we must
 * also have a standard alternative.
 */

/*
 * Lightweight read-only access to a qp-trie.
 *
 * Just the fields neded for the hot path. The `base` field points
 * to an array containing pointers to the base of each chunk like
 * `qp->base[chunk]` - see `refptr()` below.
 *
 * A `dns_qpread_t` has a lifetime that does not extend across multiple
 * write transactions, so it can share a chunk `base` array belonging to
 * the `dns_qpmulti_t` it came from.
 *
 * We're lucky with the layout on 64 bit systems: this is only 40 bytes,
 * with no padding.
 */
#define DNS_QPREAD_COMMON \
	uint32_t magic;   \
	qp_node root;     \
	qp_node **base;   \
	void *ctx;        \
	const dns_qpmethods_t *methods

struct dns_qpread {
	DNS_QPREAD_COMMON;
};

/*
 * Heavyweight read-only snapshots of a qp-trie.
 *
 * Unlike a lightweight `dns_qpread_t`, a snapshot can survive across
 * multiple write transactions, any of which may need to expand the
 * chunk `base` array. So a `dns_qpsnap_t` keeps its own copy of the
 * array, which will always be equal to some prefix of the expanded
 * arrays in the `dns_qpmulti_t` that it came from.
 *
 * The `dns_qpmulti_t` keeps a refcount of its snapshots, and while
 * the refcount is non-zero, chunks are not freed or reused. When a
 * `dns_qpsnap_t` is destroyed, if it decrements the refcount to zero,
 * it can do any deferred cleanup.
 *
 * The generation number is used for tracing.
 */
struct dns_qpsnap {
	DNS_QPREAD_COMMON;
	uint32_t generation;
	dns_qpmulti_t *whence;
	qp_node *base_array[];
};

/*
 * Read-write access to a qp-trie requires extra fields to support the
 * allocator and garbage collector.
 *
 * The chunk `base` and `usage` arrays are separate because the `usage`
 * array is only needed for allocation, so it is kept separate from the
 * data needed by the read-only hot path. The arrays have empty slots
 * where new chunks can be placed.
 *
 * Bare instances of a `struct dns_qp` are used for stand-alone
 * single-threaded tries. For multithreaded access, transactions alternate
 * between the `phase` pair of dns_qp objects inside a dns_qpmulti.
 *
 * For multithreaded access, the `generation` counter allows us to know
 * which chunks are writable or not: writable chunks were allocated in the
 * current generation. For single-threaded access, the generation counter
 * is always zero, so all chunks are considered to be writable.
 *
 * Allocations are made sequentially in the `bump` chunk. Lightweight write
 * transactions can re-use the `bump` chunk, so its prefix before `budding`
 * is immutable, and the rest is mutable even though its generation number
 * does not match the current generation.
 *
 * To decide when to compact and reclaim space, QP_MAX_GARBAGE() examines
 * the values of `used_count`, `free_count`, and `hold_count`. The
 * `hold_count` tracks nodes that need to be retained while readers are
 * using them; they are free but cannot be reclaimed until the transaction
 * has committed, so the `hold_count` is discounted from QP_MAX_GARBAGE()
 * during a transaction.
 *
 * There are some flags that alter the behaviour of write transactions.
 *
 *  - The `transaction_mode` indicates whether the current transaction is a
 *    light write or a heavy update, or (between transactions) the previous
 *    transaction's mode, because the setup for the next transaction
 *    depends on how the previous one committed. The mode is set at the
 *    start of each transaction. It is QP_NONE in a single-threaded qp-trie
 *    to detect if part of a `dns_qpmulti_t` is passed to dns_qp_destroy().
 *
 *  - The `compact_all` flag is used when every node in the trie should be
 *    copied. (Usually compation aims to avoid moving nodes out of
 *    unfragmented chunks.) It is used when compaction is explicitly
 *    requested via `dns_qp_compact()`, and as an emergency mechanism if
 *    normal compaction failed to clear the QP_MAX_GARBAGE() condition.
 *    (This emergency is a bug even tho we have a rescue mechanism.)
 *
 *  - The `shared_arrays` flag indicates that the chunk `base` and `usage`
 *    arrays are shared by both `phase`s in this trie's `dns_qpmulti_t`.
 *    This allows us to delay allocating copies of the arrays during a
 *    write transaction, until we definitely need to resize them.
 *
 *  - When built with fuzzing support, we can use mprotect() and munmap()
 *    to ensure that incorrect memory accesses cause fatal errors. The
 *    `write_protect` flag must be set straight after the `dns_qpmulti_t`
 *    is created, then left unchanged.
 *
 * Some of the dns_qp_t fields are only used for multithreaded transactions
 * (marked [MT] below) but the same code paths are also used for single-
 * threaded writes. To reduce the size of a dns_qp_t, these fields could
 * perhaps be moved into the dns_qpmulti_t, but that would require some kind
 * of conditional runtime downcast from dns_qp_t to dns_multi_t, which is
 * likely to be ugly. It is probably best to keep things simple if most tries
 * need multithreaded access (XXXFANF do they? e.g. when there are many auth
 * zones),
 */
struct dns_qp {
	DNS_QPREAD_COMMON;
	isc_mem_t *mctx;
	/*% array of per-chunk allocation counters */
	struct {
		/*% the allocation point, increases monotonically */
		qp_cell used;
		/*% count of nodes no longer needed, also monotonic */
		qp_cell free;
		/*% when was this chunk allocated? */
		uint32_t generation;
	} *usage;
	/*% transaction counter [MT] */
	uint32_t generation;
	/*% number of slots in `chunk` and `usage` arrays */
	qp_chunk chunk_max;
	/*% which chunk is used for allocations */
	qp_chunk bump;
	/*% twigs in the `bump` chunk below `budding` are read only [MT] */
	qp_cell budding;
	/*% number of leaf nodes */
	qp_cell leaf_count;
	/*% total of all usage[] counters */
	qp_cell used_count, free_count;
	/*% cells that cannot be recovered right now */
	qp_cell hold_count;
	/*% what kind of transaction was most recently started [MT] */
	enum { QP_NONE, QP_WRITE, QP_UPDATE } transaction_mode : 2;
	/*% compact the entire trie [MT] */
	bool compact_all : 1;
	/*% chunk arrays are shared with a readonly qp-trie [MT] */
	bool shared_arrays : 1;
	/*% optionally when compiled with fuzzing support [MT] */
	bool write_protect : 1;
};

/*
 * Concurrent access to a qp-trie.
 *
 * The `read` pointer is used for read queries. It points to one of the
 * `phase` elements. During a transaction, the other `phase` (see
 * `write_phase()` below) is modified incrementally in copy-on-write
 * style. On commit the `read` pointer is swapped to the altered phase.
 */
struct dns_qpmulti {
	uint32_t magic;
	/*% controls access to the `read` pointer and its target phase */
	isc_rwlock_t rwlock;
	/*% points to phase[r] and swaps on commit */
	dns_qp_t *read;
	/*% protects the snapshot counter and `write_phase()` */
	isc_mutex_t mutex;
	/*% so we know when old chunks are still shared */
	unsigned int snapshots;
	/*% one is read-only, one is mutable */
	dns_qp_t phase[2];
};

/*
 * Get a pointer to the phase that isn't read-only.
 */
static inline dns_qp_t *
write_phase(dns_qpmulti_t *multi) {
	bool read0 = multi->read == &multi->phase[0];
	return (read0 ? &multi->phase[1] : &multi->phase[0]);
}

#define QPMULTI_MAGIC	  ISC_MAGIC('q', 'p', 'm', 'v')
#define VALID_QPMULTI(qp) ISC_MAGIC_VALID(qp, QPMULTI_MAGIC)

/***********************************************************************
 *
 *  interior node constructors and accessors
 */

/*
 * See the comments under "interior node basics" above, which explain the
 * layout of nodes as implemented by the following functions.
 */

static inline void
twigmove(qp_node *to, qp_node *from, qp_weight size) {
	memmove(to, from, size * sizeof(qp_node));
}

static inline void
twigzero(qp_node *twigs, qp_weight size) {
	memset(twigs, 0, size * sizeof(qp_node));
}

/*
 * Test a node's tag bit.
 */
static inline bool
isbranch(qp_node *n) {
	return (n->biglo & BRANCH_TAG);
}

/*
 * Get the 64-bit word of a node.
 */
static inline uint64_t
node64(qp_node *n) {
	uint64_t lo = n->biglo;
	uint64_t hi = n->bighi;
	return (lo | (hi << 32));
}

/*
 * Get the 32-bit word of a node.
 */
static inline uint32_t
node32(qp_node *n) {
	return (n->small);
}

/*
 * Create a node from its parts
 */
static inline qp_node
newnode(uint64_t big, uint32_t small) {
	return ((qp_node){
		.biglo = (uint32_t)(big),
		.bighi = (uint32_t)(big >> 32),
		.small = small,
	});
}

/*
 * Get a leaf's pointer value. The double cast is to avoid a warning
 * about mismatched pointer/integer sizes on 32 bit systems.
 */
static inline void *
leaf_pval(qp_node *n) {
	return ((void *)(uintptr_t)node64(n));
}

/*
 * Get a leaf's integer value
 */
static inline uint32_t
leaf_ival(qp_node *n) {
	return (node32(n));
}

/*
 * Create a leaf node from its parts
 */
static inline qp_node
newleaf(const void *pval, uint32_t ival) {
	qp_node leaf = newnode((uintptr_t)pval, ival);
	REQUIRE(!isbranch(&leaf) && pval != NULL);
	return (leaf);
}

/*
 * Get a branch node's index word
 */
static inline uint64_t
branch_index(qp_node *n) {
	return (node64(n));
}

/*
 * Get a reference to a branch node's child twigs.
 */
static inline qp_ref
twigref(qp_node *n) {
	return (node32(n));
}

/*
 * Extract a branch node's offset field.
 */
static inline size_t
keyoff(qp_node *n) {
	return ((size_t)(branch_index(n) >> SHIFT_OFFSET));
}

/*
 * The bit position for an offset into a key
 */
static inline qp_shift
keybit(const dns_qpkey_t key, size_t len, size_t off) {
	if (off < len) {
		return (key[off]);
	} else {
		return (SHIFT_NOBYTE);
	}
}

/*
 * Which bit identifies the twig of this node for this key?
 */
static inline qp_shift
twigbit(qp_node *n, const dns_qpkey_t key, size_t len) {
	return (keybit(key, len, keyoff(n)));
}

/*
 * Is the twig identified by this bit present?
 */
static inline bool
hastwig(qp_node *n, qp_shift bit) {
	return (branch_index(n) & (1ULL << bit));
}

/***********************************************************************
 *
 *  bitmap popcount shenanigans
 */

/*
 * Get the popcount of part of a node's bitmap.
 *
 * To calculate a mask that covers the lesser bits in the bitmap, we
 * subtract 1 to set the bits, and subtract the branch tag because it
 * is not part of the bitmap.
 */
static inline qp_weight
bmpcount(qp_node *n, qp_shift bit) {
	uint64_t mask = (1ULL << bit) - 1 - BRANCH_TAG;
	uint64_t bmp = branch_index(n) & mask;
	return ((qp_weight)__builtin_popcountll(bmp));
}

/*
 * How many twigs does this node have?
 *
 * The offset is directly after the bitmap so the offset's lesser bits
 * covers the whole bitmap, and the bitmap's weight is the number of twigs.
 */
static inline qp_weight
twigmax(qp_node *n) {
	return (bmpcount(n, SHIFT_OFFSET));
}

/*
 * Position of a twig within the packed sparse vector.
 */
static inline qp_weight
twigpos(qp_node *n, qp_shift bit) {
	return (bmpcount(n, bit));
}

/*
 * Convert a twig reference into a pointer.
 */
static inline qp_node *
refptr(dns_qpreadable_t qpr, qp_ref ref) {
	dns_qpread_t *qp = dns_qpreadable_cast(qpr);
	return (qp->base[refchunk(ref)] + refcell(ref));
}

/*
 * Get a pointer to the twig at the given position.
 */
static inline qp_node *
twig(dns_qpreadable_t qpr, qp_node *n, qp_weight pos) {
	dns_qpread_t *qp = dns_qpreadable_cast(qpr);
	return (refptr(qp, twigref(n)) + pos);
}

/***********************************************************************
 *
 *  method invocation helpers
 */

static inline void
attach_leaf(dns_qpreadable_t qpr, qp_node *n) {
	dns_qpread_t *qp = dns_qpreadable_cast(qpr);
	qp->methods->attach(qp->ctx, leaf_pval(n), leaf_ival(n));
}

static inline void
detach_leaf(dns_qpreadable_t qpr, qp_node *n) {
	dns_qpread_t *qp = dns_qpreadable_cast(qpr);
	qp->methods->detach(qp->ctx, leaf_pval(n), leaf_ival(n));
}

static inline size_t
leaf_key(dns_qpreadable_t qpr, qp_node *n, dns_qpkey_t key) {
	dns_qpread_t *qp = dns_qpreadable_cast(qpr);
	return (qp->methods->makekey(key, qp->ctx, leaf_pval(n), leaf_ival(n)));
}

static inline char *
triename(dns_qpreadable_t qpr, char *buf, size_t size) {
	dns_qpread_t *qp = dns_qpreadable_cast(qpr);
	qp->methods->triename(qp->ctx, buf, size);
	return (buf);
}

/***********************************************************************
 *
 *  converting DNS names to trie keys
 */

/*
 * This is a deliberate simplification of the hostname characters,
 * because it doesn't matter much if we treat a few extra characters
 * favourably: there is plenty of space in the index word for a
 * slightly larger bitmap.
 */
static inline bool
qp_common_character(uint8_t byte) {
	return (('-' <= byte && byte <= '9') || ('_' <= byte && byte <= 'z'));
}

/*
 * Lookup table mapping bytes in DNS names to bit positions
 *
 * For common hostname characters, the top byte is zero.
 *
 * For others, the bottom byte is the escape bit, and the upper byte
 * is the position of the character within the escaped range.
 */
extern uint16_t dns_qp_bits_for_byte[256];

/*
 * And the reverse, mapping bit positions to characters.
 *
 * This table only handles the first bit in an escape sequence; we
 * arrange that we can calculate the byte value for both bits by
 * adding the the second bit to the first bit's byte value.
 */
extern uint8_t dns_qp_byte_for_bit[SHIFT_OFFSET];

/**********************************************************************/
