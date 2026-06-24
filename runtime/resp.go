package runtime

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/tidwall/redcon"
)

// RESP server: Redis-protocol front-end (redcon) over attestation-bound TLS, backed by KVStore.

// kvEngine is the subset of *KVStore the RESP layer drives.
type kvEngine interface {
	Get(ctx context.Context, key string) ([]byte, uint64, error)
	SetMode(ctx context.Context, key string, value []byte, ttlSeconds int64, mode setMode) (uint64, bool, error)
	Exists(ctx context.Context, key string) (bool, error)
	Del(ctx context.Context, key string) (bool, uint64, error)
	TTL(ctx context.Context, key string) (int64, error)
	Expire(ctx context.Context, key string, ttlSeconds int64) (bool, uint64, error)
	Incr(ctx context.Context, key string, delta int64) (int64, uint64, error)
	Append(ctx context.Context, key string, suffix []byte) (int, error)
	GetSet(ctx context.Context, key string, value []byte) (old []byte, existed bool, err error)
	Rename(ctx context.Context, src, dst string) error
	Persist(ctx context.Context, key string) (bool, error)
	ScanKeys(ctx context.Context, cursor string, count int) ([]kvKeyInfo, string, error)
	Version(ctx context.Context, key string) (uint64, error)
	TypeOf(ctx context.Context, key string) (string, error)
	ReadTyped(ctx context.Context, key, kvType string) ([]byte, bool, error)
	ModifyTyped(ctx context.Context, key, kvType string, fn func(cur []byte) ([]byte, bool, error)) (uint64, error)
}

// RESPServer dispatches RESP commands to the KV engine.
type RESPServer struct {
	kv         kvEngine
	authToken  string // runtime bearer token; every connection must AUTH with it
	cmdTimeout time.Duration
	halt       *atomic.Bool  // when set (rollback detected), data-plane commands are refused
	pubsub     redcon.PubSub // shared SUBSCRIBE/PUBLISH state
}

// connState is per-connection state: auth status and any in-flight MULTI transaction.
type connState struct {
	authed  bool
	inMulti bool              // a MULTI is open; non-control commands queue
	queued  []redcon.Command  // commands queued since MULTI (deep-copied)
	watched map[string]uint64 // WATCHed key → version at WATCH time
}

// zEntry is one sorted-set member with its score.
type zEntry struct {
	member string
	score  float64
}

// streamEntry is one stream entry: an ID plus flat field/value pairs.
type streamEntry struct {
	ID     string   `cbor:"id"`
	Fields []string `cbor:"f"`
}

// streamID is a parsed stream ID ("{ms}-{seq}").
type streamID struct{ ms, seq uint64 }

func (a streamID) cmp(b streamID) int {
	switch {
	case a.ms != b.ms && a.ms < b.ms, a.ms == b.ms && a.seq < b.seq:
		return -1
	case a == b:
		return 0
	default:
		return 1
	}
}

func (id streamID) String() string { return fmt.Sprintf("%d-%d", id.ms, id.seq) }

// Serve runs the RESP protocol on ln; blocks until the listener closes.
func (s *RESPServer) Serve(ln net.Listener) error {
	return redcon.Serve(ln, s.handle, s.accept, s.closed)
}

func (s *RESPServer) accept(conn redcon.Conn) bool {
	conn.SetContext(&connState{})
	return true
}

func (s *RESPServer) closed(_ redcon.Conn, _ error) {}

func (s *RESPServer) handle(conn redcon.Conn, cmd redcon.Command) {
	name := strings.ToUpper(string(cmd.Args[0]))
	st, _ := conn.Context().(*connState)

	switch name {
	case "PING":
		if len(cmd.Args) > 1 {
			conn.WriteBulk(cmd.Args[1])
		} else {
			conn.WriteString("PONG")
		}
		return
	case "QUIT":
		conn.WriteString("OK")
		conn.Close()
		return
	case "AUTH":
		s.cmdAuth(conn, st, cmd)
		return
	case "HELLO":
		s.cmdHello(conn, st, cmd)
		return
	case "COMMAND":
		// No command table advertised; empty array keeps redis-cli happy.
		conn.WriteArray(0)
		return
	case "CLIENT":
		// CLIENT SETINFO/SETNAME expect a status reply; anything but +OK desyncs go-redis.
		conn.WriteString("OK")
		return
	}

	if st == nil || !st.authed {
		conn.WriteError("NOAUTH Authentication required.")
		return
	}

	if s.halt != nil && s.halt.Load() {
		conn.WriteError("ERR storage halted: rollback detected")
		return
	}

	// Pub/Sub: SUBSCRIBE/PSUBSCRIBE detach into redcon's PubSub loop; PUBLISH stays on the normal path.
	switch name {
	case "SUBSCRIBE", "PSUBSCRIBE":
		if len(cmd.Args) < 2 {
			conn.WriteError("ERR wrong number of arguments for '" + strings.ToLower(name) + "' command")
			return
		}
		for _, ch := range cmd.Args[1:] {
			if name == "PSUBSCRIBE" {
				s.pubsub.Psubscribe(conn, string(ch))
			} else {
				s.pubsub.Subscribe(conn, string(ch))
			}
		}
		return
	case "PUBLISH":
		if len(cmd.Args) != 3 {
			conn.WriteError("ERR wrong number of arguments for 'publish' command")
			return
		}
		conn.WriteInt(s.pubsub.Publish(string(cmd.Args[1]), string(cmd.Args[2])))
		return
	case "UNSUBSCRIBE", "PUNSUBSCRIBE":
		// Only fires for a non-subscribed conn; reply with the empty confirmation.
		conn.WriteArray(3)
		conn.WriteBulkString(strings.ToLower(name))
		conn.WriteNull()
		conn.WriteInt(0)
		return
	}

	// Transaction control commands are never queued.
	switch name {
	case "MULTI":
		s.cmdMulti(conn, st)
		return
	case "EXEC":
		s.cmdExec(conn, st)
		return
	case "DISCARD":
		s.cmdDiscard(conn, st)
		return
	case "WATCH":
		s.cmdWatch(conn, st, cmd)
		return
	case "UNWATCH":
		st.watched = nil
		conn.WriteString("OK")
		return
	}

	// Inside a MULTI, queue everything else rather than running it.
	if st.inMulti {
		st.queued = append(st.queued, copyCommand(cmd))
		conn.WriteString("QUEUED")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.cmdTimeout)
	defer cancel()
	s.dispatchData(ctx, conn, name, cmd)
}

// dispatchData runs a single data-plane command (live path and EXEC replay).
func (s *RESPServer) dispatchData(ctx context.Context, conn redcon.Conn, name string, cmd redcon.Command) {
	switch name {
	// Strings and generic key ops.
	case "GET": // get the string value, or nil if absent
		s.cmdGet(ctx, conn, cmd)
	case "SET": // set value; EX/PX = expire secs/ms, NX/XX = only if absent/present
		s.cmdSet(ctx, conn, cmd)
	case "SETEX": // SET with EXpiry: set value + TTL in seconds
		s.cmdSetEx(ctx, conn, cmd)
	case "SETNX": // SET if Not eXists → 1 if set, 0 if already present
		s.cmdSetNx(ctx, conn, cmd)
	case "DEL", "UNLINK": // DELete keys → count removed
		s.cmdDel(ctx, conn, cmd)
	case "EXISTS": // count how many of the given keys exist
		s.cmdExists(ctx, conn, cmd)
	case "EXPIRE": // set a TTL on a key, in seconds
		s.cmdExpire(ctx, conn, cmd)
	case "TTL": // Time-To-Live → seconds left, -1 (no expiry), -2 (missing)
		s.cmdTTL(ctx, conn, cmd)
	case "INCR": // INCRement the integer value by 1
		s.cmdIncrBy(ctx, conn, cmd, 1, false)
	case "DECR": // DECRement the integer value by 1
		s.cmdIncrBy(ctx, conn, cmd, -1, false)
	case "INCRBY": // INCRement BY a given delta
		s.cmdIncrBy(ctx, conn, cmd, 0, true)
	case "DECRBY": // DECRement BY a given delta
		s.cmdIncrBy(ctx, conn, cmd, 0, true)
	case "MGET": // Multi-GET → one value per key (nil for missing)
		s.cmdMGet(ctx, conn, cmd)
	case "MSET": // Multi-SET → set many key/value pairs
		s.cmdMSet(ctx, conn, cmd)
	case "GETDEL": // GET the value, then DELete the key
		s.cmdGetDel(ctx, conn, cmd)
	case "GETSET": // GET the old value, then SET a new one
		s.cmdGetSet(ctx, conn, cmd)
	case "APPEND": // APPEND to the string value → new length
		s.cmdAppend(ctx, conn, cmd)
	case "STRLEN": // STRing LENgth of the value
		s.cmdStrlen(ctx, conn, cmd)
	case "RENAME": // RENAME a key (any type), preserving its TTL
		s.cmdRename(ctx, conn, cmd)
	case "KEYS": // all KEYS matching a glob (full scan; prefer SCAN)
		s.cmdKeys(ctx, conn, cmd)
	case "TYPE": // the key's data type → string/hash/list/set/zset/stream/none
		s.cmdType(ctx, conn, cmd)
	case "PERSIST": // remove a key's TTL → 1 if one was removed
		s.cmdPersist(ctx, conn, cmd)
	case "PTTL": // TTL in milliseconds (P = ms) → ms left, -1, -2
		s.cmdPTTL(ctx, conn, cmd)
	// Server / introspection.
	case "SCAN": // incrementally iterate keys: SCAN cursor [MATCH][COUNT][TYPE]
		s.cmdScan(ctx, conn, cmd)
	case "INFO": // server info text
		s.cmdInfo(conn)
	case "CONFIG": // CONFIG GET/SET — minimal
		cmdConfig(conn, cmd)
	// Hashes (field→value maps; H = hash).
	case "HSET", "HMSET": // Hash SET fields → number of new fields
		s.cmdHSet(ctx, conn, cmd)
	case "HSETNX": // Hash SET if Not eXists → 1 if set
		s.cmdHSetNX(ctx, conn, cmd)
	case "HGET": // Hash GET one field's value, or nil
		s.cmdHGet(ctx, conn, cmd)
	case "HMGET": // Hash Multi-GET several fields' values
		s.cmdHMGet(ctx, conn, cmd)
	case "HDEL": // Hash DELete fields → count removed
		s.cmdHDel(ctx, conn, cmd)
	case "HGETALL": // Hash GET ALL field/value pairs
		s.cmdHGetAll(ctx, conn, cmd)
	case "HKEYS": // Hash field names (KEYS)
		s.cmdHKeys(ctx, conn, cmd)
	case "HVALS": // Hash field VALueS
		s.cmdHVals(ctx, conn, cmd)
	case "HLEN": // Hash LENgth → number of fields
		s.cmdHLen(ctx, conn, cmd)
	case "HEXISTS": // does a Hash field EXIST → 0/1
		s.cmdHExists(ctx, conn, cmd)
	case "HINCRBY": // Hash INCRement a field BY a delta → new value
		s.cmdHIncrBy(ctx, conn, cmd)
	// Lists (ordered; L/R = from the left/right end).
	case "LPUSH": // Left PUSH: prepend value(s) → new length
		s.cmdPush(ctx, conn, cmd, true)
	case "RPUSH": // Right PUSH: append value(s) → new length
		s.cmdPush(ctx, conn, cmd, false)
	case "LPOP": // Left POP: remove from the head [count]
		s.cmdPop(ctx, conn, cmd, true)
	case "RPOP": // Right POP: remove from the tail [count]
		s.cmdPop(ctx, conn, cmd, false)
	case "LLEN": // List LENgth
		s.cmdLLen(ctx, conn, cmd)
	case "LRANGE": // List RANGE: elements from start..stop
		s.cmdLRange(ctx, conn, cmd)
	case "LINDEX": // List element at INDEX, or nil
		s.cmdLIndex(ctx, conn, cmd)
	case "LSET": // List SET the element at an index
		s.cmdLSet(ctx, conn, cmd)
	case "LREM": // List REMove occurrences of a value → count removed
		s.cmdLRem(ctx, conn, cmd)
	case "LTRIM": // List TRIM to a start..stop range
		s.cmdLTrim(ctx, conn, cmd)
	// Sets (unordered, unique; S = set).
	case "SADD": // Set ADD members → number of new members
		s.cmdSAdd(ctx, conn, cmd)
	case "SREM": // Set REMove members → count removed
		s.cmdSRem(ctx, conn, cmd)
	case "SMEMBERS": // all Set MEMBERS
		s.cmdSMembers(ctx, conn, cmd)
	case "SISMEMBER": // Set IS-MEMBER → 0/1
		s.cmdSIsMember(ctx, conn, cmd)
	case "SCARD": // Set CARDinality → member count
		s.cmdSCard(ctx, conn, cmd)
	case "SPOP": // Set POP: remove & return random member(s)
		s.cmdSPop(ctx, conn, cmd)
	case "SUNION": // Set UNION across keys
		s.cmdSetOp(ctx, conn, cmd, "union")
	case "SINTER": // Set INTERsection across keys
		s.cmdSetOp(ctx, conn, cmd, "inter")
	case "SDIFF": // Set DIFFerence: first key minus the rest
		s.cmdSetOp(ctx, conn, cmd, "diff")
	// Sorted sets (members ordered by score; Z = sorted set).
	case "ZADD": // sorted-set ADD score/member pairs → new members
		s.cmdZAdd(ctx, conn, cmd)
	case "ZSCORE": // sorted-set SCORE of a member, or nil
		s.cmdZScore(ctx, conn, cmd)
	case "ZRANK": // sorted-set RANK (0-based position by score), or nil
		s.cmdZRank(ctx, conn, cmd)
	case "ZREM": // sorted-set REMove members → count removed
		s.cmdZRem(ctx, conn, cmd)
	case "ZCARD": // sorted-set CARDinality → member count
		s.cmdZCard(ctx, conn, cmd)
	case "ZINCRBY": // sorted-set INCRement a member's score BY a delta
		s.cmdZIncrBy(ctx, conn, cmd)
	case "ZRANGE": // sorted-set RANGE by rank [WITHSCORES]
		s.cmdZRange(ctx, conn, cmd)
	case "ZRANGEBYSCORE": // sorted-set RANGE BY SCORE min..max [WITHSCORES]
		s.cmdZRangeByScore(ctx, conn, cmd)
	// Streams (append-only logs; X = stream).
	case "XADD": // stream ADD an entry (ID or * to auto-generate)
		s.cmdXAdd(ctx, conn, cmd)
	case "XLEN": // stream LENgth → entry count
		s.cmdXLen(ctx, conn, cmd)
	case "XRANGE": // stream RANGE of entries by ID [COUNT n]
		s.cmdXRange(ctx, conn, cmd)
	case "XREAD": // stream READ entries after given IDs
		s.cmdXRead(ctx, conn, cmd)
	default:
		conn.WriteError("ERR unknown command '" + string(cmd.Args[0]) + "'")
	}
}

// Transactions: MULTI/EXEC/DISCARD/WATCH. EXEC runs queued commands sequentially (not atomic); WATCH aborts EXEC if a watched key's version changed.

func (s *RESPServer) cmdMulti(conn redcon.Conn, st *connState) {
	if st.inMulti {
		conn.WriteError("ERR MULTI calls can not be nested")
		return
	}
	st.inMulti = true
	st.queued = nil
	conn.WriteString("OK")
}

func (s *RESPServer) cmdDiscard(conn redcon.Conn, st *connState) {
	if !st.inMulti {
		conn.WriteError("ERR DISCARD without MULTI")
		return
	}
	st.inMulti = false
	st.queued = nil
	st.watched = nil
	conn.WriteString("OK")
}

func (s *RESPServer) cmdWatch(conn redcon.Conn, st *connState, cmd redcon.Command) {
	if st.inMulti {
		conn.WriteError("ERR WATCH inside MULTI is not allowed")
		return
	}
	if len(cmd.Args) < 2 {
		conn.WriteError("ERR wrong number of arguments for 'watch' command")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cmdTimeout)
	defer cancel()
	if st.watched == nil {
		st.watched = map[string]uint64{}
	}
	for _, k := range cmd.Args[1:] {
		ver, err := s.kv.Version(ctx, string(k))
		if err != nil {
			writeKVErr(conn, err)
			return
		}
		st.watched[string(k)] = ver
	}
	conn.WriteString("OK")
}

func (s *RESPServer) cmdExec(conn redcon.Conn, st *connState) {
	if !st.inMulti {
		conn.WriteError("ERR EXEC without MULTI")
		return
	}
	queued, watched := st.queued, st.watched
	st.inMulti, st.queued, st.watched = false, nil, nil

	ctx, cancel := context.WithTimeout(context.Background(), s.cmdTimeout)
	defer cancel()

	// Optimistic concurrency: abort (null array) if any watched key changed.
	for key, ver := range watched {
		cur, err := s.kv.Version(ctx, key)
		if err != nil {
			writeKVErr(conn, err)
			return
		}
		if cur != ver {
			conn.WriteRaw([]byte("*-1\r\n"))
			return
		}
	}

	conn.WriteArray(len(queued))
	for _, qcmd := range queued {
		s.dispatchData(ctx, conn, strings.ToUpper(string(qcmd.Args[0])), qcmd)
	}
}

func (s *RESPServer) cmdAuth(conn redcon.Conn, st *connState, cmd redcon.Command) {
	// AUTH [user] password — the last arg is the password.
	pw := cmd.Args[len(cmd.Args)-1]
	if subtle.ConstantTimeCompare(pw, []byte(s.authToken)) != 1 {
		conn.WriteError("WRONGPASS invalid username-password pair")
		return
	}
	if st != nil {
		st.authed = true
	}
	conn.WriteString("OK")
}

func (s *RESPServer) cmdGet(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'get' command")
		return
	}
	val, _, err := s.kv.Get(ctx, string(cmd.Args[1]))
	switch {
	case errors.Is(err, ErrKVNotFound):
		conn.WriteNull()
	case err != nil:
		writeKVErr(conn, err)
	default:
		conn.WriteBulk(val)
	}
}

func (s *RESPServer) cmdSet(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 3 {
		conn.WriteError("ERR wrong number of arguments for 'set' command")
		return
	}
	key, val := string(cmd.Args[1]), cmd.Args[2]
	var ttl int64
	var nx, xx bool
	for i := 3; i < len(cmd.Args); i++ {
		switch strings.ToUpper(string(cmd.Args[i])) {
		case "EX":
			i++
			if i >= len(cmd.Args) || !parseSeconds(cmd.Args[i], &ttl) {
				conn.WriteError("ERR value is not an integer or out of range")
				return
			}
		case "PX":
			i++
			var ms int64
			if i >= len(cmd.Args) || !parseSeconds(cmd.Args[i], &ms) {
				conn.WriteError("ERR value is not an integer or out of range")
				return
			}
			ttl = (ms + 999) / 1000
		case "NX":
			nx = true
		case "XX":
			xx = true
		default:
			conn.WriteError("ERR syntax error")
			return
		}
	}
	if nx && xx {
		conn.WriteError("ERR syntax error")
		return
	}
	mode := setAlways
	switch {
	case nx:
		mode = setNX
	case xx:
		mode = setXX
	}
	_, ok, err := s.kv.SetMode(ctx, key, val, ttl, mode)
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	if !ok {
		conn.WriteNull() // NX/XX condition not met
		return
	}
	conn.WriteString("OK")
}

func (s *RESPServer) cmdSetEx(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 4 {
		conn.WriteError("ERR wrong number of arguments for 'setex' command")
		return
	}
	var ttl int64
	if !parseSeconds(cmd.Args[2], &ttl) || ttl <= 0 {
		conn.WriteError("ERR invalid expire time in 'setex' command")
		return
	}
	_, _, err := s.kv.SetMode(ctx, string(cmd.Args[1]), cmd.Args[3], ttl, setAlways)
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteString("OK")
}

func (s *RESPServer) cmdSetNx(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for 'setnx' command")
		return
	}
	_, ok, err := s.kv.SetMode(ctx, string(cmd.Args[1]), cmd.Args[2], 0, setNX)
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	if !ok {
		conn.WriteInt(0)
		return
	}
	conn.WriteInt(1)
}

func (s *RESPServer) cmdDel(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 2 {
		conn.WriteError("ERR wrong number of arguments for 'del' command")
		return
	}
	n := 0
	for _, k := range cmd.Args[1:] {
		existed, _, err := s.kv.Del(ctx, string(k))
		if err != nil {
			writeKVErr(conn, err)
			return
		}
		if existed {
			n++
		}
	}
	conn.WriteInt(n)
}

func (s *RESPServer) cmdExists(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 2 {
		conn.WriteError("ERR wrong number of arguments for 'exists' command")
		return
	}
	n := 0
	for _, k := range cmd.Args[1:] {
		ok, err := s.kv.Exists(ctx, string(k))
		if err != nil {
			writeKVErr(conn, err)
			return
		}
		if ok {
			n++
		}
	}
	conn.WriteInt(n)
}

func (s *RESPServer) cmdExpire(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for 'expire' command")
		return
	}
	var ttl int64
	if !parseSeconds(cmd.Args[2], &ttl) {
		conn.WriteError("ERR value is not an integer or out of range")
		return
	}
	ok, _, err := s.kv.Expire(ctx, string(cmd.Args[1]), ttl)
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(boolToInt(ok))
}

func (s *RESPServer) cmdTTL(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'ttl' command")
		return
	}
	ttl, err := s.kv.TTL(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt64(ttl)
}

// cmdIncrBy handles INCR/DECR (fixed delta) and INCRBY/DECRBY (arg delta).
func (s *RESPServer) cmdIncrBy(ctx context.Context, conn redcon.Conn, cmd redcon.Command, delta int64, fromArg bool) {
	want := 2
	if fromArg {
		want = 3
	}
	if len(cmd.Args) != want {
		conn.WriteError("ERR wrong number of arguments")
		return
	}
	if fromArg {
		n, err := strconv.ParseInt(string(cmd.Args[2]), 10, 64)
		if err != nil {
			conn.WriteError("ERR value is not an integer or out of range")
			return
		}
		delta = n
		if strings.EqualFold(string(cmd.Args[0]), "DECRBY") {
			delta = -delta
		}
	}
	v, _, err := s.kv.Incr(ctx, string(cmd.Args[1]), delta)
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt64(v)
}

func (s *RESPServer) cmdMGet(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 2 {
		conn.WriteError("ERR wrong number of arguments for 'mget' command")
		return
	}
	conn.WriteArray(len(cmd.Args) - 1)
	for _, k := range cmd.Args[1:] {
		val, _, err := s.kv.Get(ctx, string(k))
		if err != nil {
			conn.WriteNull() // missing/error → nil element, per Redis MGET
			continue
		}
		conn.WriteBulk(val)
	}
}

func (s *RESPServer) cmdMSet(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 3 || len(cmd.Args)%2 != 1 {
		conn.WriteError("ERR wrong number of arguments for 'mset' command")
		return
	}
	for i := 1; i < len(cmd.Args); i += 2 {
		if _, _, err := s.kv.SetMode(ctx, string(cmd.Args[i]), cmd.Args[i+1], 0, setAlways); err != nil {
			writeKVErr(conn, err)
			return
		}
	}
	conn.WriteString("OK")
}

func (s *RESPServer) cmdGetDel(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'getdel' command")
		return
	}
	key := string(cmd.Args[1])
	val, _, err := s.kv.Get(ctx, key)
	switch {
	case errors.Is(err, ErrKVNotFound):
		conn.WriteNull()
		return
	case err != nil:
		writeKVErr(conn, err)
		return
	}
	if _, _, err := s.kv.Del(ctx, key); err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteBulk(val)
}

func (s *RESPServer) cmdAppend(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for 'append' command")
		return
	}
	n, err := s.kv.Append(ctx, string(cmd.Args[1]), cmd.Args[2])
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(n)
}

func (s *RESPServer) cmdGetSet(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for 'getset' command")
		return
	}
	old, existed, err := s.kv.GetSet(ctx, string(cmd.Args[1]), cmd.Args[2])
	switch {
	case err != nil:
		writeKVErr(conn, err)
	case !existed:
		conn.WriteNull()
	default:
		conn.WriteBulk(old)
	}
}

func (s *RESPServer) cmdRename(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for 'rename' command")
		return
	}
	err := s.kv.Rename(ctx, string(cmd.Args[1]), string(cmd.Args[2]))
	switch {
	case errors.Is(err, ErrKVNotFound):
		conn.WriteError("ERR no such key")
	case err != nil:
		writeKVErr(conn, err)
	default:
		conn.WriteString("OK")
	}
}

// cmdKeys returns every key matching the pattern in one full scan; prefer SCAN.
func (s *RESPServer) cmdKeys(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'keys' command")
		return
	}
	pattern := string(cmd.Args[1])
	var matched []string
	cursor := "0"
	for {
		page, next, err := s.kv.ScanKeys(ctx, cursor, 1000)
		if err != nil {
			writeKVErr(conn, err)
			return
		}
		for _, ki := range page {
			if globMatch(pattern, ki.Key) {
				matched = append(matched, ki.Key)
			}
		}
		if next == "0" {
			break
		}
		cursor = next
	}
	conn.WriteArray(len(matched))
	for _, k := range matched {
		conn.WriteBulkString(k)
	}
}

func (s *RESPServer) cmdStrlen(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'strlen' command")
		return
	}
	val, _, err := s.kv.Get(ctx, string(cmd.Args[1]))
	switch {
	case errors.Is(err, ErrKVNotFound):
		conn.WriteInt(0)
	case err != nil:
		writeKVErr(conn, err)
	default:
		conn.WriteInt(len(val))
	}
}

func (s *RESPServer) cmdType(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'type' command")
		return
	}
	t, err := s.kv.TypeOf(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteString(t)
}

func (s *RESPServer) cmdPersist(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'persist' command")
		return
	}
	ok, err := s.kv.Persist(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(boolToInt(ok))
}

func (s *RESPServer) cmdPTTL(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'pttl' command")
		return
	}
	ttl, err := s.kv.TTL(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	if ttl < 0 {
		conn.WriteInt64(ttl) // -1 no expiry, -2 missing
		return
	}
	conn.WriteInt64(ttl * 1000)
}

// cmdScan incrementally iterates: SCAN cursor [MATCH pattern] [COUNT n] [TYPE t].
func (s *RESPServer) cmdScan(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 2 {
		conn.WriteError("ERR wrong number of arguments for 'scan' command")
		return
	}
	cursor := string(cmd.Args[1])
	pattern, typeFilter, count := "*", "", 10
	for i := 2; i < len(cmd.Args); i += 2 {
		if i+1 >= len(cmd.Args) {
			conn.WriteError("ERR syntax error")
			return
		}
		switch strings.ToUpper(string(cmd.Args[i])) {
		case "MATCH":
			pattern = string(cmd.Args[i+1])
		case "TYPE":
			typeFilter = strings.ToLower(string(cmd.Args[i+1]))
		case "COUNT":
			n, err := strconv.Atoi(string(cmd.Args[i+1]))
			if err != nil || n < 1 {
				conn.WriteError("ERR value is not an integer or out of range")
				return
			}
			count = n
		default:
			conn.WriteError("ERR syntax error")
			return
		}
	}
	keys, next, err := s.kv.ScanKeys(ctx, cursor, count)
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	var matched []string
	for _, ki := range keys {
		if typeFilter != "" && ki.Type != typeFilter {
			continue
		}
		if globMatch(pattern, ki.Key) {
			matched = append(matched, ki.Key)
		}
	}
	conn.WriteArray(2)
	conn.WriteBulkString(next)
	conn.WriteArray(len(matched))
	for _, k := range matched {
		conn.WriteBulkString(k)
	}
}

func (s *RESPServer) cmdInfo(conn redcon.Conn) {
	conn.WriteBulkString("# Server\r\n" +
		"redis_version:7.0.0-introspector-enclave\r\n" +
		"redis_mode:standalone\r\n" +
		"# Clients\r\nconnected_clients:1\r\n" +
		"# Keyspace\r\n")
}

// helpers

// cmdHello negotiates protocol version and optionally authenticates: HELLO <ver> [AUTH user pass] [SETNAME name].
func (s *RESPServer) cmdHello(conn redcon.Conn, st *connState, cmd redcon.Command) {
	args := cmd.Args[1:]
	proto := "2"
	i := 0
	if i < len(args) {
		switch string(args[i]) {
		case "2", "3":
			proto = string(args[i])
			i++
		default:
			conn.WriteError("NOPROTO unsupported protocol version")
			return
		}
	}
	for i < len(args) {
		switch strings.ToUpper(string(args[i])) {
		case "AUTH":
			if i+2 >= len(args) {
				conn.WriteError("ERR syntax error in HELLO")
				return
			}
			if subtle.ConstantTimeCompare(args[i+2], []byte(s.authToken)) != 1 {
				conn.WriteError("WRONGPASS invalid username-password pair")
				return
			}
			if st != nil {
				st.authed = true
			}
			i += 3
		case "SETNAME":
			if i+1 >= len(args) {
				conn.WriteError("ERR syntax error in HELLO")
				return
			}
			i += 2
		default:
			conn.WriteError("ERR syntax error in HELLO")
			return
		}
	}
	fields := [][2]string{
		{"server", "enclave-kv"},
		{"version", Version},
		{"mode", "standalone"},
		{"role", "master"},
	}
	var b strings.Builder
	if proto == "3" {
		b.WriteString(fmt.Sprintf("%%%d\r\n", len(fields)+2))
	} else {
		b.WriteString(fmt.Sprintf("*%d\r\n", (len(fields)+2)*2))
	}
	for _, f := range fields {
		b.WriteString(respBulk(f[0]))
		b.WriteString(respBulk(f[1]))
	}
	b.WriteString(respBulk("proto"))
	b.WriteString(":")
	b.WriteString(proto)
	b.WriteString("\r\n")
	b.WriteString(respBulk("modules"))
	b.WriteString("*0\r\n")
	conn.WriteRaw([]byte(b.String()))
}

// Data types (hash/list/set/zset/stream) are each one AEAD-sealed CBOR blob per key; every op is a read-modify-write on the whole collection.

// Hash — map[string]string

// hashField reads one field from key, or returns ok=false (absent key or field).
func (s *RESPServer) hashField(ctx context.Context, key, field string) (string, bool, error) {
	b, exists, err := s.kv.ReadTyped(ctx, key, typeHash)
	if err != nil || !exists {
		return "", false, err
	}
	m, err := decodeHash(b)
	if err != nil {
		return "", false, err
	}
	v, ok := m[field]
	return v, ok, nil
}

func (s *RESPServer) cmdHSet(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 4 || len(cmd.Args)%2 != 0 {
		conn.WriteError("ERR wrong number of arguments for 'hset' command")
		return
	}
	var added int
	_, err := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeHash, func(cur []byte) ([]byte, bool, error) {
		added = 0
		m, err := decodeHash(cur)
		if err != nil {
			return nil, false, err
		}
		for i := 2; i < len(cmd.Args); i += 2 {
			f := string(cmd.Args[i])
			if _, ok := m[f]; !ok {
				added++
			}
			m[f] = string(cmd.Args[i+1])
		}
		b, err := cbor.Marshal(m)
		return b, false, err
	})
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	if strings.EqualFold(string(cmd.Args[0]), "HMSET") {
		conn.WriteString("OK") // legacy HMSET replies +OK, not the added count
		return
	}
	conn.WriteInt(added)
}

func (s *RESPServer) cmdHSetNX(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 4 {
		conn.WriteError("ERR wrong number of arguments for 'hsetnx' command")
		return
	}
	var set bool
	_, err := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeHash, func(cur []byte) ([]byte, bool, error) {
		set = false
		m, err := decodeHash(cur)
		if err != nil {
			return nil, false, err
		}
		if _, ok := m[string(cmd.Args[2])]; ok {
			return cur, false, nil // field exists → no-op
		}
		set = true
		m[string(cmd.Args[2])] = string(cmd.Args[3])
		b, err := cbor.Marshal(m)
		return b, false, err
	})
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(boolToInt(set))
}

func (s *RESPServer) cmdHGet(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for 'hget' command")
		return
	}
	v, ok, err := s.hashField(ctx, string(cmd.Args[1]), string(cmd.Args[2]))
	switch {
	case err != nil:
		writeKVErr(conn, err)
	case !ok:
		conn.WriteNull()
	default:
		conn.WriteBulkString(v)
	}
}

func (s *RESPServer) cmdHMGet(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 3 {
		conn.WriteError("ERR wrong number of arguments for 'hmget' command")
		return
	}
	b, _, err := s.kv.ReadTyped(ctx, string(cmd.Args[1]), typeHash)
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	m, err := decodeHash(b)
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteArray(len(cmd.Args) - 2)
	for _, f := range cmd.Args[2:] {
		if v, ok := m[string(f)]; ok {
			conn.WriteBulkString(v)
		} else {
			conn.WriteNull()
		}
	}
}

func (s *RESPServer) cmdHDel(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 3 {
		conn.WriteError("ERR wrong number of arguments for 'hdel' command")
		return
	}
	var removed int
	_, err := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeHash, func(cur []byte) ([]byte, bool, error) {
		removed = 0
		m, err := decodeHash(cur)
		if err != nil {
			return nil, false, err
		}
		for _, f := range cmd.Args[2:] {
			if _, ok := m[string(f)]; ok {
				delete(m, string(f))
				removed++
			}
		}
		if len(m) == 0 {
			return nil, true, nil // last field gone → delete the key
		}
		b, err := cbor.Marshal(m)
		return b, false, err
	})
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(removed)
}

func (s *RESPServer) cmdHGetAll(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'hgetall' command")
		return
	}
	m, err := s.readHash(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteArray(len(m) * 2)
	for f, v := range m {
		conn.WriteBulkString(f)
		conn.WriteBulkString(v)
	}
}

func (s *RESPServer) cmdHKeys(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'hkeys' command")
		return
	}
	m, err := s.readHash(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteArray(len(m))
	for f := range m {
		conn.WriteBulkString(f)
	}
}

func (s *RESPServer) cmdHVals(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'hvals' command")
		return
	}
	m, err := s.readHash(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteArray(len(m))
	for _, v := range m {
		conn.WriteBulkString(v)
	}
}

func (s *RESPServer) cmdHLen(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'hlen' command")
		return
	}
	m, err := s.readHash(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(len(m))
}

func (s *RESPServer) cmdHExists(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for 'hexists' command")
		return
	}
	_, ok, err := s.hashField(ctx, string(cmd.Args[1]), string(cmd.Args[2]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(boolToInt(ok))
}

func (s *RESPServer) cmdHIncrBy(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 4 {
		conn.WriteError("ERR wrong number of arguments for 'hincrby' command")
		return
	}
	delta, err := strconv.ParseInt(string(cmd.Args[3]), 10, 64)
	if err != nil {
		conn.WriteError("ERR value is not an integer or out of range")
		return
	}
	field := string(cmd.Args[2])
	var result int64
	_, err = s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeHash, func(cur []byte) ([]byte, bool, error) {
		m, err := decodeHash(cur)
		if err != nil {
			return nil, false, err
		}
		base := int64(0)
		if existing, ok := m[field]; ok {
			if base, err = strconv.ParseInt(existing, 10, 64); err != nil {
				return nil, false, ErrNotInteger
			}
		}
		result = base + delta
		m[field] = strconv.FormatInt(result, 10)
		b, err := cbor.Marshal(m)
		return b, false, err
	})
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt64(result)
}

// readHash returns the decoded hash at key (empty if absent), enforcing the type.
func (s *RESPServer) readHash(ctx context.Context, key string) (map[string]string, error) {
	b, _, err := s.kv.ReadTyped(ctx, key, typeHash)
	if err != nil {
		return nil, err
	}
	return decodeHash(b)
}

// List — ordered []string

func (s *RESPServer) readList(ctx context.Context, key string) ([]string, error) {
	b, _, err := s.kv.ReadTyped(ctx, key, typeList)
	if err != nil {
		return nil, err
	}
	return decodeList(b)
}

// cmdPush handles LPUSH (left=true) and RPUSH. Returns the new length.
func (s *RESPServer) cmdPush(ctx context.Context, conn redcon.Conn, cmd redcon.Command, left bool) {
	if len(cmd.Args) < 3 {
		conn.WriteError("ERR wrong number of arguments")
		return
	}
	var n int
	_, err := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeList, func(cur []byte) ([]byte, bool, error) {
		l, err := decodeList(cur)
		if err != nil {
			return nil, false, err
		}
		for _, v := range cmd.Args[2:] {
			if left {
				l = append([]string{string(v)}, l...)
			} else {
				l = append(l, string(v))
			}
		}
		n = len(l)
		b, err := cbor.Marshal(l)
		return b, false, err
	})
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(n)
}

// cmdPop handles LPOP (left=true) and RPOP, with an optional count.
func (s *RESPServer) cmdPop(ctx context.Context, conn redcon.Conn, cmd redcon.Command, left bool) {
	if len(cmd.Args) < 2 || len(cmd.Args) > 3 {
		conn.WriteError("ERR wrong number of arguments")
		return
	}
	count, hasCount := 1, false
	if len(cmd.Args) == 3 {
		c, err := strconv.Atoi(string(cmd.Args[2]))
		if err != nil || c < 0 {
			conn.WriteError("ERR value is out of range, must be positive")
			return
		}
		count, hasCount = c, true
	}
	var popped []string
	_, err := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeList, func(cur []byte) ([]byte, bool, error) {
		popped = nil
		l, err := decodeList(cur)
		if err != nil {
			return nil, false, err
		}
		k := min(count, len(l))
		if left {
			popped = append(popped, l[:k]...)
			l = l[k:]
		} else {
			for i := 0; i < k; i++ {
				popped = append(popped, l[len(l)-1-i])
			}
			l = l[:len(l)-k]
		}
		if len(l) == 0 {
			return nil, true, nil
		}
		b, err := cbor.Marshal(l)
		return b, false, err
	})
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	if !hasCount {
		if len(popped) == 0 {
			conn.WriteNull()
		} else {
			conn.WriteBulkString(popped[0])
		}
		return
	}
	if len(popped) == 0 {
		conn.WriteNull() // null array for an empty/missing list
		return
	}
	conn.WriteArray(len(popped))
	for _, v := range popped {
		conn.WriteBulkString(v)
	}
}

func (s *RESPServer) cmdLLen(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'llen' command")
		return
	}
	l, err := s.readList(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(len(l))
}

func (s *RESPServer) cmdLRange(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 4 {
		conn.WriteError("ERR wrong number of arguments for 'lrange' command")
		return
	}
	start, err1 := strconv.Atoi(string(cmd.Args[2]))
	stop, err2 := strconv.Atoi(string(cmd.Args[3]))
	if err1 != nil || err2 != nil {
		conn.WriteError("ERR value is not an integer or out of range")
		return
	}
	l, err := s.readList(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	lo, hi := clampRange(start, stop, len(l))
	if lo > hi {
		conn.WriteArray(0)
		return
	}
	conn.WriteArray(hi - lo + 1)
	for _, v := range l[lo : hi+1] {
		conn.WriteBulkString(v)
	}
}

func (s *RESPServer) cmdLIndex(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for 'lindex' command")
		return
	}
	idx, err := strconv.Atoi(string(cmd.Args[2]))
	if err != nil {
		conn.WriteError("ERR value is not an integer or out of range")
		return
	}
	l, rerr := s.readList(ctx, string(cmd.Args[1]))
	if rerr != nil {
		writeKVErr(conn, rerr)
		return
	}
	if idx < 0 {
		idx += len(l)
	}
	if idx < 0 || idx >= len(l) {
		conn.WriteNull()
		return
	}
	conn.WriteBulkString(l[idx])
}

func (s *RESPServer) cmdLSet(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 4 {
		conn.WriteError("ERR wrong number of arguments for 'lset' command")
		return
	}
	idx, err := strconv.Atoi(string(cmd.Args[2]))
	if err != nil {
		conn.WriteError("ERR value is not an integer or out of range")
		return
	}
	var noKey, oob bool
	_, merr := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeList, func(cur []byte) ([]byte, bool, error) {
		noKey, oob = false, false
		l, err := decodeList(cur)
		if err != nil {
			return nil, false, err
		}
		if len(l) == 0 {
			noKey = true
			return cur, false, nil
		}
		i := idx
		if i < 0 {
			i += len(l)
		}
		if i < 0 || i >= len(l) {
			oob = true
			return cur, false, nil
		}
		l[i] = string(cmd.Args[3])
		b, err := cbor.Marshal(l)
		return b, false, err
	})
	switch {
	case merr != nil:
		writeKVErr(conn, merr)
	case noKey:
		conn.WriteError("ERR no such key")
	case oob:
		conn.WriteError("ERR index out of range")
	default:
		conn.WriteString("OK")
	}
}

func (s *RESPServer) cmdLRem(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 4 {
		conn.WriteError("ERR wrong number of arguments for 'lrem' command")
		return
	}
	count, err := strconv.Atoi(string(cmd.Args[2]))
	if err != nil {
		conn.WriteError("ERR value is not an integer or out of range")
		return
	}
	target := string(cmd.Args[3])
	var removed int
	_, merr := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeList, func(cur []byte) ([]byte, bool, error) {
		removed = 0
		l, err := decodeList(cur)
		if err != nil {
			return nil, false, err
		}
		l, removed = listRem(l, target, count)
		if len(l) == 0 {
			return nil, true, nil
		}
		b, err := cbor.Marshal(l)
		return b, false, err
	})
	if merr != nil {
		writeKVErr(conn, merr)
		return
	}
	conn.WriteInt(removed)
}

func (s *RESPServer) cmdLTrim(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 4 {
		conn.WriteError("ERR wrong number of arguments for 'ltrim' command")
		return
	}
	start, err1 := strconv.Atoi(string(cmd.Args[2]))
	stop, err2 := strconv.Atoi(string(cmd.Args[3]))
	if err1 != nil || err2 != nil {
		conn.WriteError("ERR value is not an integer or out of range")
		return
	}
	_, merr := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeList, func(cur []byte) ([]byte, bool, error) {
		l, err := decodeList(cur)
		if err != nil {
			return nil, false, err
		}
		lo, hi := clampRange(start, stop, len(l))
		if lo > hi {
			return nil, true, nil // trimmed to empty → delete
		}
		l = append([]string(nil), l[lo:hi+1]...)
		b, err := cbor.Marshal(l)
		return b, false, err
	})
	if merr != nil {
		writeKVErr(conn, merr)
		return
	}
	conn.WriteString("OK")
}

// Set — unordered unique strings (CBOR []string members, used as a map)

func (s *RESPServer) readSet(ctx context.Context, key string) (map[string]struct{}, error) {
	b, _, err := s.kv.ReadTyped(ctx, key, typeSet)
	if err != nil {
		return nil, err
	}
	return decodeSet(b)
}

func (s *RESPServer) cmdSAdd(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 3 {
		conn.WriteError("ERR wrong number of arguments for 'sadd' command")
		return
	}
	var added int
	_, err := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeSet, func(cur []byte) ([]byte, bool, error) {
		added = 0
		m, err := decodeSet(cur)
		if err != nil {
			return nil, false, err
		}
		for _, v := range cmd.Args[2:] {
			if _, ok := m[string(v)]; !ok {
				m[string(v)] = struct{}{}
				added++
			}
		}
		b, err := encodeSet(m)
		return b, false, err
	})
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(added)
}

func (s *RESPServer) cmdSRem(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 3 {
		conn.WriteError("ERR wrong number of arguments for 'srem' command")
		return
	}
	var removed int
	_, err := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeSet, func(cur []byte) ([]byte, bool, error) {
		removed = 0
		m, err := decodeSet(cur)
		if err != nil {
			return nil, false, err
		}
		for _, v := range cmd.Args[2:] {
			if _, ok := m[string(v)]; ok {
				delete(m, string(v))
				removed++
			}
		}
		if len(m) == 0 {
			return nil, true, nil
		}
		b, err := encodeSet(m)
		return b, false, err
	})
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(removed)
}

func (s *RESPServer) cmdSMembers(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'smembers' command")
		return
	}
	m, err := s.readSet(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	writeStringSet(conn, m)
}

func (s *RESPServer) cmdSIsMember(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for 'sismember' command")
		return
	}
	m, err := s.readSet(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	_, ok := m[string(cmd.Args[2])]
	conn.WriteInt(boolToInt(ok))
}

func (s *RESPServer) cmdSCard(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'scard' command")
		return
	}
	m, err := s.readSet(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(len(m))
}

func (s *RESPServer) cmdSPop(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 2 || len(cmd.Args) > 3 {
		conn.WriteError("ERR wrong number of arguments for 'spop' command")
		return
	}
	count, hasCount := 1, false
	if len(cmd.Args) == 3 {
		c, err := strconv.Atoi(string(cmd.Args[2]))
		if err != nil || c < 0 {
			conn.WriteError("ERR value is out of range, must be positive")
			return
		}
		count, hasCount = c, true
	}
	var popped []string
	_, err := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeSet, func(cur []byte) ([]byte, bool, error) {
		popped = nil
		m, err := decodeSet(cur)
		if err != nil {
			return nil, false, err
		}
		for v := range m { // Go randomizes map iteration → effectively random
			if len(popped) >= count {
				break
			}
			popped = append(popped, v)
			delete(m, v)
		}
		if len(m) == 0 {
			return nil, true, nil
		}
		b, err := encodeSet(m)
		return b, false, err
	})
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	if !hasCount {
		if len(popped) == 0 {
			conn.WriteNull()
		} else {
			conn.WriteBulkString(popped[0])
		}
		return
	}
	conn.WriteArray(len(popped))
	for _, v := range popped {
		conn.WriteBulkString(v)
	}
}

// cmdSetOp handles SUNION/SINTER/SDIFF over one or more set keys.
func (s *RESPServer) cmdSetOp(ctx context.Context, conn redcon.Conn, cmd redcon.Command, op string) {
	if len(cmd.Args) < 2 {
		conn.WriteError("ERR wrong number of arguments")
		return
	}
	first, err := s.readSet(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	result := make(map[string]struct{}, len(first))
	for v := range first {
		result[v] = struct{}{}
	}
	for _, k := range cmd.Args[2:] {
		other, err := s.readSet(ctx, string(k))
		if err != nil {
			writeKVErr(conn, err)
			return
		}
		switch op {
		case "union":
			for v := range other {
				result[v] = struct{}{}
			}
		case "inter":
			for v := range result {
				if _, ok := other[v]; !ok {
					delete(result, v)
				}
			}
		case "diff":
			for v := range other {
				delete(result, v)
			}
		}
	}
	writeStringSet(conn, result)
}

// Sorted set — member→score (CBOR map[string]float64), ordered by (score, member)

func (s *RESPServer) readZSet(ctx context.Context, key string) (map[string]float64, error) {
	b, _, err := s.kv.ReadTyped(ctx, key, typeZSet)
	if err != nil {
		return nil, err
	}
	return decodeZSet(b)
}

func (s *RESPServer) cmdZAdd(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 4 || len(cmd.Args)%2 != 0 {
		conn.WriteError("ERR wrong number of arguments for 'zadd' command")
		return
	}
	scores := make([]float64, 0, (len(cmd.Args)-2)/2)
	for i := 2; i < len(cmd.Args); i += 2 {
		v, err := strconv.ParseFloat(string(cmd.Args[i]), 64)
		if err != nil {
			conn.WriteError("ERR value is not a valid float")
			return
		}
		scores = append(scores, v)
	}
	var added int
	_, err := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeZSet, func(cur []byte) ([]byte, bool, error) {
		added = 0
		m, err := decodeZSet(cur)
		if err != nil {
			return nil, false, err
		}
		for i := 2; i < len(cmd.Args); i += 2 {
			member := string(cmd.Args[i+1])
			if _, ok := m[member]; !ok {
				added++
			}
			m[member] = scores[(i-2)/2]
		}
		b, err := encodeZSet(m)
		return b, false, err
	})
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(added)
}

func (s *RESPServer) cmdZScore(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for 'zscore' command")
		return
	}
	m, err := s.readZSet(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	if sc, ok := m[string(cmd.Args[2])]; ok {
		conn.WriteBulkString(formatScore(sc))
	} else {
		conn.WriteNull()
	}
}

func (s *RESPServer) cmdZRank(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for 'zrank' command")
		return
	}
	m, err := s.readZSet(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	member := string(cmd.Args[2])
	if _, ok := m[member]; !ok {
		conn.WriteNull()
		return
	}
	for rank, e := range sortedZ(m) {
		if e.member == member {
			conn.WriteInt(rank)
			return
		}
	}
}

func (s *RESPServer) cmdZRem(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 3 {
		conn.WriteError("ERR wrong number of arguments for 'zrem' command")
		return
	}
	var removed int
	_, err := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeZSet, func(cur []byte) ([]byte, bool, error) {
		removed = 0
		m, err := decodeZSet(cur)
		if err != nil {
			return nil, false, err
		}
		for _, member := range cmd.Args[2:] {
			if _, ok := m[string(member)]; ok {
				delete(m, string(member))
				removed++
			}
		}
		if len(m) == 0 {
			return nil, true, nil
		}
		b, err := encodeZSet(m)
		return b, false, err
	})
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(removed)
}

func (s *RESPServer) cmdZCard(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'zcard' command")
		return
	}
	m, err := s.readZSet(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(len(m))
}

func (s *RESPServer) cmdZIncrBy(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 4 {
		conn.WriteError("ERR wrong number of arguments for 'zincrby' command")
		return
	}
	delta, err := strconv.ParseFloat(string(cmd.Args[2]), 64)
	if err != nil {
		conn.WriteError("ERR value is not a valid float")
		return
	}
	member := string(cmd.Args[3])
	var result float64
	_, merr := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeZSet, func(cur []byte) ([]byte, bool, error) {
		m, err := decodeZSet(cur)
		if err != nil {
			return nil, false, err
		}
		result = m[member] + delta
		m[member] = result
		b, err := encodeZSet(m)
		return b, false, err
	})
	if merr != nil {
		writeKVErr(conn, merr)
		return
	}
	conn.WriteBulkString(formatScore(result))
}

func (s *RESPServer) cmdZRange(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 4 {
		conn.WriteError("ERR wrong number of arguments for 'zrange' command")
		return
	}
	start, err1 := strconv.Atoi(string(cmd.Args[2]))
	stop, err2 := strconv.Atoi(string(cmd.Args[3]))
	if err1 != nil || err2 != nil {
		conn.WriteError("ERR value is not an integer or out of range")
		return
	}
	withScores := len(cmd.Args) >= 5 && strings.EqualFold(string(cmd.Args[4]), "WITHSCORES")
	m, err := s.readZSet(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	entries := sortedZ(m)
	lo, hi := clampRange(start, stop, len(entries))
	if lo > hi {
		conn.WriteArray(0)
		return
	}
	writeZRange(conn, entries[lo:hi+1], withScores)
}

func (s *RESPServer) cmdZRangeByScore(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 4 {
		conn.WriteError("ERR wrong number of arguments for 'zrangebyscore' command")
		return
	}
	lo, loEx, err1 := parseScoreBound(string(cmd.Args[2]))
	hi, hiEx, err2 := parseScoreBound(string(cmd.Args[3]))
	if err1 != nil || err2 != nil {
		conn.WriteError("ERR min or max is not a float")
		return
	}
	withScores := len(cmd.Args) >= 5 && strings.EqualFold(string(cmd.Args[4]), "WITHSCORES")
	m, err := s.readZSet(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	var matched []zEntry
	for _, e := range sortedZ(m) {
		geMin := e.score > lo || (!loEx && e.score == lo)
		leMax := e.score < hi || (!hiEx && e.score == hi)
		if geMin && leMax {
			matched = append(matched, e)
		}
	}
	writeZRange(conn, matched, withScores)
}

// Stream — append-only log of {ID, field/value pairs}, ordered by ID

func (s *RESPServer) readStream(ctx context.Context, key string) ([]streamEntry, error) {
	b, _, err := s.kv.ReadTyped(ctx, key, typeStream)
	if err != nil {
		return nil, err
	}
	return decodeStream(b)
}

func (s *RESPServer) cmdXAdd(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	// XADD key ID field value [field value ...]
	if len(cmd.Args) < 5 || len(cmd.Args)%2 != 1 {
		conn.WriteError("ERR wrong number of arguments for 'xadd' command")
		return
	}
	idArg := string(cmd.Args[2])
	fields := make([]string, 0, len(cmd.Args)-3)
	for _, a := range cmd.Args[3:] {
		fields = append(fields, string(a))
	}
	nowMS := uint64(time.Now().UnixMilli())
	var newID string
	_, err := s.kv.ModifyTyped(ctx, string(cmd.Args[1]), typeStream, func(cur []byte) ([]byte, bool, error) {
		entries, err := decodeStream(cur)
		if err != nil {
			return nil, false, err
		}
		var last streamID
		hasLast := len(entries) > 0
		if hasLast {
			if last, err = parseStreamID(entries[len(entries)-1].ID, 0); err != nil {
				return nil, false, err
			}
		}
		id, err := nextStreamID(idArg, last, hasLast, nowMS)
		if err != nil {
			return nil, false, err
		}
		if hasLast && id.cmp(last) <= 0 {
			return nil, false, errors.New("The ID specified in XADD is equal or smaller than the target stream top item")
		}
		newID = id.String()
		entries = append(entries, streamEntry{ID: newID, Fields: fields})
		b, err := cbor.Marshal(entries)
		return b, false, err
	})
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteBulkString(newID)
}

func (s *RESPServer) cmdXLen(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for 'xlen' command")
		return
	}
	entries, err := s.readStream(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	conn.WriteInt(len(entries))
}

func (s *RESPServer) cmdXRange(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	// XRANGE key start end [COUNT n]
	if len(cmd.Args) != 4 && len(cmd.Args) != 6 {
		conn.WriteError("ERR wrong number of arguments for 'xrange' command")
		return
	}
	start, err1 := parseRangeID(string(cmd.Args[2]), false)
	end, err2 := parseRangeID(string(cmd.Args[3]), true)
	if err1 != nil || err2 != nil {
		conn.WriteError("ERR Invalid stream ID specified as stream command argument")
		return
	}
	count := -1
	if len(cmd.Args) == 6 && strings.EqualFold(string(cmd.Args[4]), "COUNT") {
		count, _ = strconv.Atoi(string(cmd.Args[5]))
	}
	entries, err := s.readStream(ctx, string(cmd.Args[1]))
	if err != nil {
		writeKVErr(conn, err)
		return
	}
	var matched []streamEntry
	for _, e := range entries {
		id, _ := parseStreamID(e.ID, 0)
		if id.cmp(start) >= 0 && id.cmp(end) <= 0 {
			matched = append(matched, e)
			if count >= 0 && len(matched) >= count {
				break
			}
		}
	}
	writeStreamEntries(conn, matched)
}

func (s *RESPServer) cmdXRead(ctx context.Context, conn redcon.Conn, cmd redcon.Command) {
	// XREAD [COUNT n] STREAMS key [key...] id [id...]  (non-blocking; no BLOCK)
	i := 1
	count := -1
	if i < len(cmd.Args) && strings.EqualFold(string(cmd.Args[i]), "COUNT") {
		if i+1 >= len(cmd.Args) {
			conn.WriteError("ERR syntax error")
			return
		}
		count, _ = strconv.Atoi(string(cmd.Args[i+1]))
		i += 2
	}
	if i >= len(cmd.Args) || !strings.EqualFold(string(cmd.Args[i]), "STREAMS") {
		conn.WriteError("ERR syntax error")
		return
	}
	i++
	rest := cmd.Args[i:]
	if len(rest) == 0 || len(rest)%2 != 0 {
		conn.WriteError("ERR Unbalanced XREAD list of streams: for each stream key an ID or '$' must be specified.")
		return
	}
	n := len(rest) / 2
	keys, ids := rest[:n], rest[n:]

	type streamResult struct {
		name    string
		entries []streamEntry
	}
	var results []streamResult
	for j := 0; j < n; j++ {
		entries, err := s.readStream(ctx, string(keys[j]))
		if err != nil {
			writeKVErr(conn, err)
			return
		}
		var after streamID
		if string(ids[j]) == "$" { // only entries newer than the current last
			if len(entries) > 0 {
				after, _ = parseStreamID(entries[len(entries)-1].ID, 0)
			}
		} else if after, err = parseStreamID(string(ids[j]), math.MaxUint64); err != nil {
			conn.WriteError("ERR Invalid stream ID specified as stream command argument")
			return
		}
		var matched []streamEntry
		for _, e := range entries {
			id, _ := parseStreamID(e.ID, 0)
			if id.cmp(after) > 0 {
				matched = append(matched, e)
				if count >= 0 && len(matched) >= count {
					break
				}
			}
		}
		if len(matched) > 0 {
			results = append(results, streamResult{string(keys[j]), matched})
		}
	}
	if len(results) == 0 {
		conn.WriteNull()
		return
	}
	conn.WriteArray(len(results))
	for _, r := range results {
		conn.WriteArray(2)
		conn.WriteBulkString(r.name)
		writeStreamEntries(conn, r.entries)
	}
}

// Free functions / helpers

// NewRESPServer builds the server; authToken gates every connection via AUTH.
func NewRESPServer(kv kvEngine, authToken string) *RESPServer {
	return &RESPServer{kv: kv, authToken: authToken, cmdTimeout: 10 * time.Second}
}

// copyCommand deep-copies a redcon.Command so it survives queuing (redcon reuses its read buffer).
func copyCommand(cmd redcon.Command) redcon.Command {
	out := redcon.Command{Raw: append([]byte(nil), cmd.Raw...)}
	out.Args = make([][]byte, len(cmd.Args))
	for i, a := range cmd.Args {
		out.Args[i] = append([]byte(nil), a...)
	}
	return out
}

func cmdConfig(conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) < 2 {
		conn.WriteError("ERR wrong number of arguments for 'config' command")
		return
	}
	switch strings.ToUpper(string(cmd.Args[1])) {
	case "GET":
		// No tunables exposed; answer commonly-probed params, empty map otherwise.
		out := map[string]string{}
		for _, p := range cmd.Args[2:] {
			switch strings.ToLower(string(p)) {
			case "maxmemory":
				out["maxmemory"] = "0"
			case "save":
				out["save"] = ""
			}
		}
		conn.WriteArray(len(out) * 2)
		for k, v := range out {
			conn.WriteBulkString(k)
			conn.WriteBulkString(v)
		}
	case "SET", "RESETSTAT", "REWRITE":
		conn.WriteString("OK")
	default:
		conn.WriteError("ERR Unknown CONFIG subcommand")
	}
}

// globMatch implements Redis-style key glob matching ('*', '?', '[...]' classes, '\' escaping; '*' spans '/').
func globMatch(pattern, s string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			for len(pattern) > 1 && pattern[1] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 1 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if globMatch(pattern[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			s, pattern = s[1:], pattern[1:]
		case '[':
			if len(s) == 0 {
				return false
			}
			matched, rest, ok := globClass(pattern, s[0])
			if !ok { // malformed class → literal '['
				if s[0] != '[' {
					return false
				}
				s, pattern = s[1:], pattern[1:]
				continue
			}
			if !matched {
				return false
			}
			s, pattern = s[1:], rest
		case '\\':
			if len(pattern) > 1 {
				pattern = pattern[1:]
			}
			if len(s) == 0 || s[0] != pattern[0] {
				return false
			}
			s, pattern = s[1:], pattern[1:]
		default:
			if len(s) == 0 || s[0] != pattern[0] {
				return false
			}
			s, pattern = s[1:], pattern[1:]
		}
	}
	return len(s) == 0
}

// globClass matches c against a '[...]' class, returning (matched, pattern-after-class, well-formed).
func globClass(pattern string, c byte) (bool, string, bool) {
	i := 1
	negate := false
	if i < len(pattern) && pattern[i] == '^' {
		negate = true
		i++
	}
	matched, first := false, true
	for i < len(pattern) && (pattern[i] != ']' || first) {
		first = false
		switch {
		case pattern[i] == '\\' && i+1 < len(pattern):
			if pattern[i+1] == c {
				matched = true
			}
			i += 2
		case i+2 < len(pattern) && pattern[i+1] == '-' && pattern[i+2] != ']':
			if pattern[i] <= c && c <= pattern[i+2] {
				matched = true
			}
			i += 3
		default:
			if pattern[i] == c {
				matched = true
			}
			i++
		}
	}
	if i >= len(pattern) || pattern[i] != ']' {
		return false, pattern, false
	}
	return matched != negate, pattern[i+1:], true
}

func parseSeconds(b []byte, out *int64) bool {
	n, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return false
	}
	*out = n
	return true
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// respBulk encodes s as a RESP bulk string.
func respBulk(s string) string {
	return "$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n"
}

func writeKVErr(conn redcon.Conn, err error) {
	switch {
	case errors.Is(err, ErrValueTooLarge):
		conn.WriteError("ERR value exceeds maximum size")
	case errors.Is(err, ErrKVDisabled):
		conn.WriteError("ERR storage not initialized")
	case errors.Is(err, ErrNotInteger):
		conn.WriteError("ERR value is not an integer or out of range")
	case errors.Is(err, ErrWrongType):
		conn.WriteError(ErrWrongType.Error())
	default:
		slog.Warn("kv command error", "error", err)
		conn.WriteError("ERR " + err.Error())
	}
}

func decodeHash(b []byte) (map[string]string, error) {
	m := map[string]string{}
	if len(b) == 0 {
		return m, nil
	}
	return m, cbor.Unmarshal(b, &m)
}

func decodeList(b []byte) ([]string, error) {
	var l []string
	if len(b) == 0 {
		return l, nil
	}
	return l, cbor.Unmarshal(b, &l)
}

// listRem removes occurrences of v (count>0 from head, count<0 from tail, 0 all); returns list and count removed.
func listRem(l []string, v string, count int) ([]string, int) {
	out := l[:0:0]
	removed := 0
	if count >= 0 {
		limit := count
		for _, e := range l {
			if e == v && (count == 0 || removed < limit) {
				removed++
				continue
			}
			out = append(out, e)
		}
		return out, removed
	}
	limit := -count
	keepRev := make([]string, 0, len(l))
	for i := len(l) - 1; i >= 0; i-- {
		if l[i] == v && removed < limit {
			removed++
			continue
		}
		keepRev = append(keepRev, l[i])
	}
	for i := len(keepRev) - 1; i >= 0; i-- {
		out = append(out, keepRev[i])
	}
	return out, removed
}

// clampRange normalizes Redis-style inclusive [start,stop] over a length-n list.
func clampRange(start, stop, n int) (int, int) {
	if start < 0 {
		start += n
	}
	if stop < 0 {
		stop += n
	}
	if start < 0 {
		start = 0
	}
	if stop >= n {
		stop = n - 1
	}
	return start, stop
}

func decodeSet(b []byte) (map[string]struct{}, error) {
	var members []string
	if len(b) > 0 {
		if err := cbor.Unmarshal(b, &members); err != nil {
			return nil, err
		}
	}
	m := make(map[string]struct{}, len(members))
	for _, x := range members {
		m[x] = struct{}{}
	}
	return m, nil
}

func encodeSet(m map[string]struct{}) ([]byte, error) {
	members := make([]string, 0, len(m))
	for x := range m {
		members = append(members, x)
	}
	return cbor.Marshal(members)
}

func writeStringSet(conn redcon.Conn, m map[string]struct{}) {
	conn.WriteArray(len(m))
	for v := range m {
		conn.WriteBulkString(v)
	}
}

func decodeZSet(b []byte) (map[string]float64, error) {
	m := map[string]float64{}
	if len(b) == 0 {
		return m, nil
	}
	return m, cbor.Unmarshal(b, &m)
}

// sortedZ returns the members ordered by score, then lexically for ties.
func sortedZ(m map[string]float64) []zEntry {
	out := make([]zEntry, 0, len(m))
	for mem, sc := range m {
		out = append(out, zEntry{mem, sc})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score < out[j].score
		}
		return out[i].member < out[j].member
	})
	return out
}

func formatScore(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	default:
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
}

func encodeZSet(m map[string]float64) ([]byte, error) { return cbor.Marshal(m) }

func writeZRange(conn redcon.Conn, entries []zEntry, withScores bool) {
	if withScores {
		conn.WriteArray(len(entries) * 2)
		for _, e := range entries {
			conn.WriteBulkString(e.member)
			conn.WriteBulkString(formatScore(e.score))
		}
		return
	}
	conn.WriteArray(len(entries))
	for _, e := range entries {
		conn.WriteBulkString(e.member)
	}
}

// parseScoreBound parses a ZRANGEBYSCORE bound: a float, "+inf"/"-inf", or "(" for exclusive.
func parseScoreBound(s string) (val float64, exclusive bool, err error) {
	if strings.HasPrefix(s, "(") {
		exclusive, s = true, s[1:]
	}
	switch strings.ToLower(s) {
	case "+inf", "inf":
		return math.Inf(1), exclusive, nil
	case "-inf":
		return math.Inf(-1), exclusive, nil
	}
	v, err := strconv.ParseFloat(s, 64)
	return v, exclusive, err
}

// parseStreamID parses "ms" or "ms-seq"; a missing seq defaults to defaultSeq.
func parseStreamID(s string, defaultSeq uint64) (streamID, error) {
	ms, rest, hasSeq := strings.Cut(s, "-")
	msv, err := strconv.ParseUint(ms, 10, 64)
	if err != nil {
		return streamID{}, errors.New("Invalid stream ID specified as stream command argument")
	}
	seq := defaultSeq
	if hasSeq {
		if seq, err = strconv.ParseUint(rest, 10, 64); err != nil {
			return streamID{}, errors.New("Invalid stream ID specified as stream command argument")
		}
	}
	return streamID{msv, seq}, nil
}

func decodeStream(b []byte) ([]streamEntry, error) {
	var entries []streamEntry
	if len(b) == 0 {
		return entries, nil
	}
	return entries, cbor.Unmarshal(b, &entries)
}

// nextStreamID resolves an XADD ID argument: "*" (full auto), "ms-*" (auto seq), or explicit "ms-seq".
func nextStreamID(arg string, last streamID, hasLast bool, nowMS uint64) (streamID, error) {
	if arg == "*" {
		ms := nowMS
		if hasLast && last.ms > ms {
			ms = last.ms
		}
		seq := uint64(0)
		if hasLast && ms == last.ms {
			seq = last.seq + 1
		}
		return streamID{ms, seq}, nil
	}
	ms, rest, hasSeq := strings.Cut(arg, "-")
	msv, err := strconv.ParseUint(ms, 10, 64)
	if err != nil {
		return streamID{}, errors.New("Invalid stream ID specified as stream command argument")
	}
	if hasSeq && rest == "*" {
		seq := uint64(0)
		if hasLast && msv == last.ms {
			seq = last.seq + 1
		}
		return streamID{msv, seq}, nil
	}
	return parseStreamID(arg, 0)
}

// parseRangeID parses an XRANGE bound: "-"/"+" for min/max, else an ID (missing seq defaults to 0 or max).
func parseRangeID(s string, isEnd bool) (streamID, error) {
	switch s {
	case "-":
		return streamID{0, 0}, nil
	case "+":
		return streamID{math.MaxUint64, math.MaxUint64}, nil
	}
	def := uint64(0)
	if isEnd {
		def = math.MaxUint64
	}
	return parseStreamID(s, def)
}

func writeStreamEntries(conn redcon.Conn, entries []streamEntry) {
	conn.WriteArray(len(entries))
	for _, e := range entries {
		conn.WriteArray(2)
		conn.WriteBulkString(e.ID)
		conn.WriteArray(len(e.Fields))
		for _, f := range e.Fields {
			conn.WriteBulkString(f)
		}
	}
}
