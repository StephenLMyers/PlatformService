/*
 * Sharded in-memory token-bucket rate limiter (plan 3.5, 7.4, 7.7-adjacent):
 * the only genuinely shared, mutable, per-request structure in the service
 * besides the KDF semaphore. Bounds login and registration attempts by
 * IP/username/a fixed global key before either endpoint ever reaches its
 * (expensive, PBKDF2-backed) real work.
 *
 * Sharded 16 ways by key hash, one pthread_mutex_t per shard, so
 * contention stays proportional to key spread rather than serializing
 * every request through one lock. Each shard is a fixed-capacity,
 * open-addressed hash table -- bounded so an attacker cycling source IPs
 * cannot turn the defense itself into a memory-exhaustion vector (plan
 * 3.5). Eviction happens only in the rare case a shard is completely full
 * when a brand-new key arrives: the entry with the oldest last-used time
 * in that shard is evicted to make room, via a full shard scan -- simpler
 * than an intrusive LRU list, and correct since eviction is the
 * uncommon path (most requests hit a key already in the table).
 */
#ifndef PS_PLATFORM_RATELIMIT_H
#define PS_PLATFORM_RATELIMIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Room for an IPv6 literal in brackets ("[xxxx:...:xxxx]", up to 45 chars)
 * or a username (32 chars, plan 7.6) with a small prefix, plus NUL. */
#define PS_RATELIMIT_KEY_MAX 64

typedef struct ps_ratelimiter ps_ratelimiter_t;

/*
 * max_entries is the total number of distinct keys tracked across every
 * shard combined (plan 3.5's "bounded entry count"), divided evenly
 * across the 16 shards -- values under 16 still get at least one slot per
 * shard. Returns NULL and writes a reason into err on failure (allocation
 * failure only; there is no other way for this to fail).
 */
ps_ratelimiter_t *ps_ratelimiter_create(int max_entries, char *err, size_t errlen);

void ps_ratelimiter_destroy(ps_ratelimiter_t *rl);

/*
 * True if a request identified by key is allowed under a token bucket
 * refilling per_minute tokens/minute, capacity per_minute (a bucket seen
 * for the first time starts full and this call's own consumption is the
 * very first token taken from it, so a brand-new key's first request is
 * always allowed). False means the caller should respond 429
 * RATE_LIMITED without doing whatever expensive work the limiter is
 * guarding. per_minute <= 0 always denies (a limiter with no budget
 * configured should fail closed, not open).
 *
 * key is copied internally (bounded to PS_RATELIMIT_KEY_MAX - 1 bytes,
 * truncated if longer -- callers should keep keys well under that, e.g.
 * an IP literal or a lowercased username, never anything attacker-sized).
 */
bool ps_ratelimiter_allow(ps_ratelimiter_t *rl, const char *key, int per_minute);

/*
 * Same as ps_ratelimiter_allow but takes an explicit monotonic timestamp
 * (nanoseconds) instead of reading the real clock -- exists purely so
 * this module's own unit tests can exercise refill/eviction/expiry
 * behavior deterministically without a real sleep(); ps_ratelimiter_allow
 * is a thin wrapper calling this with CLOCK_MONOTONIC's current value.
 * Not a general clock-injection facility for the rest of the service
 * (discussed with the user, documented in gotchas.md) -- scoped entirely
 * to this one new, self-contained module.
 */
bool ps_ratelimiter_allow_at(ps_ratelimiter_t *rl, const char *key, int per_minute,
                             int64_t now_ns);

#endif /* PS_PLATFORM_RATELIMIT_H */
