# K/V — Core Redis Command Coverage

## Core Redis command coverage

"Core" = Redis's built-in command groups. Module/specialized families (RedisJSON
`JSON.*`, bitmaps, HyperLogLog `PF*`, Geo `GEO*`, scripting, search/timeseries)
are **not** core and are listed under "out of scope" below. Within each core
group we implement the primary read/write verbs; the ✗ entries are the gaps.

| Group | Have ✓ | Missing ✗ |
|-------|--------|-----------|
| Connection / server | PING, AUTH, HELLO, QUIT, CLIENT (SETNAME/SETINFO), COMMAND (stub), INFO, CONFIG GET/SET | SELECT, ECHO, RESET, DBSIZE, FLUSHDB/FLUSHALL, SWAPDB, WAIT, DEBUG, ACL, MEMORY, SLOWLOG, PUBSUB (introspection) |
| Generic / keys | DEL, UNLINK, EXISTS, EXPIRE, TTL, PTTL, PERSIST, TYPE, KEYS, SCAN, RENAME | RENAMENX, EXPIREAT, PEXPIRE, PEXPIREAT, EXPIRETIME, PEXPIRETIME, COPY, MOVE, TOUCH, DUMP/RESTORE, OBJECT, SORT, MIGRATE, RANDOMKEY |
| Strings | GET, SET (EX/PX/NX/XX), SETEX, SETNX, GETSET, GETDEL, APPEND, STRLEN, MGET, MSET, INCR, DECR, INCRBY, DECRBY | PSETEX, GETEX, MSETNX, INCRBYFLOAT, SETRANGE, GETRANGE, all bitmap ops (SETBIT/GETBIT/BITCOUNT/BITOP/BITPOS/BITFIELD) |
| Hashes | HSET, HMSET, HSETNX, HGET, HMGET, HDEL, HGETALL, HKEYS, HVALS, HLEN, HEXISTS, HINCRBY | HINCRBYFLOAT, HSTRLEN, HRANDFIELD, HSCAN |
| Lists | LPUSH, RPUSH, LPOP, RPOP, LLEN, LRANGE, LINDEX, LSET, LREM, LTRIM | LPUSHX/RPUSHX, LINSERT, LPOS, RPOPLPUSH/LMOVE, LMPOP, blocking (BLPOP/BRPOP/BLMOVE/BLMPOP) |
| Sets | SADD, SREM, SMEMBERS, SISMEMBER, SCARD, SPOP, SUNION, SINTER, SDIFF | SMISMEMBER, SRANDMEMBER, SMOVE, SINTERCARD, SUNIONSTORE/SINTERSTORE/SDIFFSTORE, SSCAN |
| Sorted sets | ZADD, ZSCORE, ZRANK, ZREM, ZCARD, ZINCRBY, ZRANGE, ZRANGEBYSCORE | ZREVRANGE, ZREVRANGEBYSCORE, ZREVRANK, ZCOUNT, ZMSCORE, ZRANGEBYLEX/ZLEXCOUNT, ZPOPMIN/ZPOPMAX (+ blocking), ZREMRANGEBY*, ZUNION/ZINTER/ZDIFF (+STORE), ZRANDMEMBER, ZSCAN |
| Streams | XADD, XLEN, XRANGE, XREAD | XREVRANGE, XDEL, XTRIM, XINFO, XSETID, consumer groups (XGROUP/XREADGROUP/XACK/XCLAIM/XAUTOCLAIM/XPENDING) |
| Transactions | MULTI, EXEC, DISCARD, WATCH, UNWATCH (sequential, optimistic) | — (atomicity caveat below) |
| Pub/Sub | SUBSCRIBE, PSUBSCRIBE, PUBLISH, UNSUBSCRIBE, PUNSUBSCRIBE | PUBSUB introspection, sharded (SSUBSCRIBE/SPUBLISH) |

The ✗ entries split into:
1. **Variant/convenience commands** of types we already support (REVRANGE, *STORE,
   *SCAN, RANDMEMBER, LINSERT, …) — cheap to add incrementally, same blob pattern.
2. **Blocking ops** — real friction (no "wait for change" in DynamoDB; see below).
3. **Multi-DB / admin** (SELECT, FLUSHDB, DBSIZE) — we are single-keyspace by design.

## Remaining / out of scope

### Deliberately out of scope (per design decisions)
- **Lua scripting** (`EVAL`/`EVALSHA`/`FUNCTION`) — redcon provides no scripting
  engine; it would mean embedding a Lua VM and a `redis.call()` bridge.
- **Blocking ops** (`BLPOP`/`BRPOP`/`WAIT`) and `OBJECT` — DynamoDB has no "wait
  for change", so blocking would mean polling or in-process waiters that only
  coordinate within a single enclave instance.
- **Non-core / module families** — RedisJSON (`JSON.*`), bitmaps
  (`SETBIT`/`BITFIELD`/…), HyperLogLog (`PF*`), Geo (`GEO*`), and
  search/timeseries/bloom. These aren't core Redis; each is a self-contained
  feature. RedisJSON in particular is a clean future addition (type-tagged sealed
  document + a path navigator, no new dependencies) if a client needs it.
- **Cross-key transaction atomicity** — `EXEC` runs sequentially; `WATCH` gives
  optimistic CAS, but true isolation isn't achievable over the per-key DynamoDB
  model. Documented in the code.

### Known characteristics (not bugs)
- Collections are stored as one sealed CBOR blob, so ops are O(collection) rather
  than Redis's O(1)/O(log n) — fine for confidential, modest-sized collections.
- SCAN/boot-gate cost scales with stored bytes (a filtered DynamoDB Scan reads
  chunk items too); fine at the target low write rate.
