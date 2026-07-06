package runtime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const testRESPToken = "s3cret"

type respReply struct {
	typ   byte
	str   string
	null  bool
	elems []respReply
}

type respClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
}

func (c *respClient) cmd(args ...string) respReply {
	c.t.Helper()

	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	_, err := c.conn.Write([]byte(b.String()))
	require.NoError(c.t, err)
	return c.read()
}

func (c *respClient) read() respReply {
	c.t.Helper()

	line, err := c.br.ReadString('\n')
	require.NoError(c.t, err)
	line = strings.TrimRight(line, "\r\n")
	require.NotEmpty(c.t, line)

	switch line[0] {
	case '|': // RESP3 attribute; skip pairs, return real reply.
		n, err := strconv.Atoi(line[1:])
		require.NoError(c.t, err)
		for range n {
			_ = c.read()
			_ = c.read()
		}
		return c.read()
	case '+', '-', ':':
		return respReply{typ: line[0], str: line[1:]}
	case '_':
		return respReply{typ: '_', null: true}
	case '$':
		n, err := strconv.Atoi(line[1:])
		require.NoError(c.t, err)
		if n < 0 {
			return respReply{typ: '$', null: true}
		}
		buf := make([]byte, n+2)
		_, err = io.ReadFull(c.br, buf)
		require.NoError(c.t, err)
		require.Equal(c.t, "\r\n", string(buf[n:]))
		return respReply{typ: '$', str: string(buf[:n])}
	case '*', '%':
		n, err := strconv.Atoi(line[1:])
		require.NoError(c.t, err)
		if n < 0 {
			return respReply{typ: line[0], null: true}
		}
		count := n
		if line[0] == '%' {
			count *= 2
		}
		r := respReply{typ: line[0], elems: make([]respReply, 0, count)}
		for range count {
			r.elems = append(r.elems, c.read())
		}
		return r
	default:
		require.FailNow(c.t, "unknown RESP reply", line)
		return respReply{}
	}
}

func startRESPServer(t *testing.T, rt RuntimeState, kv KVStore) func() *respClient {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := NewRESPServer(rt, kv, testRESPToken)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })

	return func() *respClient {
		t.Helper()
		conn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return &respClient{t: t, conn: conn, br: bufio.NewReader(conn)}
	}
}

func newRESPDialer(
	t *testing.T,
	ctx context.Context,
) (*kvStore, *runtimeState, func() *respClient) {
	t.Helper()
	kv, _, _, rt := newTestKV(t, ctx, nil, nil)
	return kv, rt, startRESPServer(t, rt, kv)
}

func newAuthedRESP(t *testing.T, ctx context.Context) (*respClient, *kvStore, *runtimeState) {
	t.Helper()
	kv, rt, dial := newRESPDialer(t, ctx)
	c := dial()
	requireString(t, c.cmd("AUTH", testRESPToken), "OK")
	return c, kv, rt
}

func requireString(t *testing.T, r respReply, want string) {
	t.Helper()
	require.NotEqual(t, byte('-'), r.typ, r.str)
	require.Equal(t, want, r.str)
}

func requireInt(t *testing.T, r respReply, want int) {
	t.Helper()
	require.Equal(t, byte(':'), r.typ)
	require.Equal(t, strconv.Itoa(want), r.str)
}

func requirePositiveInt(t *testing.T, r respReply) {
	t.Helper()
	require.Equal(t, byte(':'), r.typ)
	n, err := strconv.Atoi(r.str)
	require.NoError(t, err)
	require.Greater(t, n, 0)
}

func requireNull(t *testing.T, r respReply) {
	t.Helper()
	require.True(t, r.null, "reply: type=%c str=%q", r.typ, r.str)
}

func requireErrorContains(t *testing.T, r respReply, want string) {
	t.Helper()
	require.Equal(t, byte('-'), r.typ)
	require.Contains(t, r.str, want)
}

func replyStrings(r respReply) []string {
	out := make([]string, 0, len(r.elems))
	for _, e := range r.elems {
		out = append(out, e.str)
	}
	return out
}

func replyMap(t *testing.T, r respReply) map[string]string {
	t.Helper()
	require.Equal(t, 0, len(r.elems)%2)
	out := map[string]string{}
	for i := 0; i < len(r.elems); i += 2 {
		out[r.elems[i].str] = r.elems[i+1].str
	}
	return out
}

func scanAll(t *testing.T, c *respClient, args ...string) []string {
	t.Helper()

	var out []string
	cursor := "0"
	for i := 0; ; i++ {
		r := c.cmd(append([]string{"SCAN", cursor}, args...)...)
		require.Equal(t, byte('*'), r.typ)
		require.Len(t, r.elems, 2)
		out = append(out, replyStrings(r.elems[1])...)
		cursor = r.elems[0].str
		if cursor == "0" {
			return out
		}
		require.Less(t, i, 1000, "SCAN cursor did not terminate")
	}
}

func TestRESP(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "unittest")
	t.Setenv("ENCLAVE_APP_NAME", "resp")

	ctx := context.Background()

	t.Run("auth gate", func(t *testing.T) {
		_, _, dial := newRESPDialer(t, ctx)
		c := dial()

		requireErrorContains(t, c.cmd("GET", "k"), "NOAUTH")
		requireErrorContains(t, c.cmd("AUTH", "wrong"), "WRONGPASS")
		requireString(t, c.cmd("AUTH", testRESPToken), "OK")
		requireNull(t, c.cmd("GET", "missing"))
	})

	t.Run("hello and client commands", func(t *testing.T) {
		_, _, dial := newRESPDialer(t, ctx)

		c := dial()
		require.Equal(t, byte('%'), c.cmd("HELLO", "3", "AUTH", "default", testRESPToken).typ)
		requireString(t, c.cmd("SET", "k", "v"), "OK")
		requireString(t, c.cmd("GET", "k"), "v")

		bad := dial()
		requireErrorContains(t, bad.cmd("HELLO", "3", "AUTH", "default", "nope"), "WRONGPASS")
		requireErrorContains(t, bad.cmd("GET", "k"), "NOAUTH")

		c2 := dial()
		requireString(t, c2.cmd("AUTH", testRESPToken), "OK")
		require.Equal(t, byte('*'), c2.cmd("HELLO", "2").typ)
		requireErrorContains(t, c2.cmd("HELLO", "9"), "NOPROTO")
		requireString(t, c2.cmd("CLIENT", "SETINFO", "lib-name", "go-redis"), "OK")
		requireString(t, c2.cmd("CLIENT", "SETINFO", "lib-ver", "9.21.0"), "OK")
		require.Equal(t, byte('*'), c2.cmd("COMMAND", "DOCS").typ)
		requireString(t, c2.cmd("SET", "after-client", "ok"), "OK")
	})

	t.Run("strings and keys", func(t *testing.T) {
		c, _, _ := newAuthedRESP(t, ctx)

		requireString(t, c.cmd("PING"), "PONG")
		requireString(t, c.cmd("PING", "hi"), "hi")
		requireErrorContains(t, c.cmd("BOGUS"), "unknown command")

		requireString(t, c.cmd("SET", "k", "v1"), "OK")
		requireString(t, c.cmd("GET", "k"), "v1")
		requireString(t, c.cmd("SET", "k", "v2"), "OK")
		requireString(t, c.cmd("GET", "k"), "v2")
		requireNull(t, c.cmd("GET", "missing"))

		requireString(t, c.cmd("SET", "nx", "a", "NX"), "OK")
		requireNull(t, c.cmd("SET", "nx", "b", "NX"))
		requireString(t, c.cmd("GET", "nx"), "a")
		requireString(t, c.cmd("SET", "nx", "c", "XX"), "OK")
		requireNull(t, c.cmd("SET", "absent", "x", "XX"))
		requireErrorContains(t, c.cmd("SET", "nx", "v", "NX", "XX"), "syntax error")

		requireInt(t, c.cmd("SETNX", "setnx", "a"), 1)
		requireInt(t, c.cmd("SETNX", "setnx", "b"), 0)
		requireString(t, c.cmd("SETEX", "ttl", "100", "v"), "OK")
		requirePositiveInt(t, c.cmd("TTL", "ttl"))

		requireString(t, c.cmd("SET", "d", "v"), "OK")
		requireInt(t, c.cmd("EXISTS", "d", "missing"), 1)
		requireInt(t, c.cmd("TTL", "d"), -1)
		requireInt(t, c.cmd("TTL", "missing"), -2)
		requireInt(t, c.cmd("DEL", "d", "missing"), 1)
		requireNull(t, c.cmd("GET", "d"))

		requireInt(t, c.cmd("INCR", "n"), 1)
		requireInt(t, c.cmd("INCRBY", "n", "5"), 6)
		requireInt(t, c.cmd("DECR", "n"), 5)
		requireInt(t, c.cmd("DECRBY", "n", "5"), 0)
		requireString(t, c.cmd("SET", "not-int", "nope"), "OK")
		requireErrorContains(t, c.cmd("INCR", "not-int"), "integer")

		requireInt(t, c.cmd("APPEND", "a", "foo"), 3)
		requireInt(t, c.cmd("APPEND", "a", "bar"), 6)
		requireString(t, c.cmd("GET", "a"), "foobar")
		requireString(t, c.cmd("GETSET", "a", "new"), "foobar")
		requireString(t, c.cmd("GET", "a"), "new")
		requireNull(t, c.cmd("GETSET", "fresh", "v"))

		requireString(t, c.cmd("MSET", "m1", "1", "m2", "hello", "m3", "x"), "OK")
		mget := c.cmd("MGET", "m1", "missing", "m2")
		require.Equal(t, byte('*'), mget.typ)
		require.Len(t, mget.elems, 3)
		require.Equal(t, "1", mget.elems[0].str)
		require.True(t, mget.elems[1].null)
		require.Equal(t, "hello", mget.elems[2].str)
		requireInt(t, c.cmd("STRLEN", "m2"), 5)
		requireInt(t, c.cmd("STRLEN", "missing"), 0)
		requireString(t, c.cmd("TYPE", "m2"), "string")
		requireString(t, c.cmd("TYPE", "missing"), "none")
		requireString(t, c.cmd("GETDEL", "m1"), "1")
		requireNull(t, c.cmd("GET", "m1"))

		requireString(t, c.cmd("SETEX", "persist", "100", "v"), "OK")
		requirePositiveInt(t, c.cmd("PTTL", "persist"))
		requireInt(t, c.cmd("PERSIST", "persist"), 1)
		requireInt(t, c.cmd("PTTL", "persist"), -1)
		requireInt(t, c.cmd("PTTL", "missing"), -2)

		requireString(t, c.cmd("RENAME", "a", "b"), "OK")
		requireNull(t, c.cmd("GET", "a"))
		requireString(t, c.cmd("GET", "b"), "new")
		requireErrorContains(t, c.cmd("RENAME", "missing", "x"), "no such key")

		requireString(t, c.cmd("MSET", "user:1", "a", "user:2", "b", "post:1", "c"), "OK")
		require.ElementsMatch(
			t,
			[]string{"user:1", "user:2"},
			replyStrings(c.cmd("KEYS", "user:*")),
		)
	})

	t.Run("scan", func(t *testing.T) {
		c, _, _ := newAuthedRESP(t, ctx)
		for i := range 7 {
			requireString(t, c.cmd("SET", "s"+strconv.Itoa(i), "v"), "OK")
		}
		requireInt(t, c.cmd("HSET", "h1", "f", "v"), 1)
		requireInt(t, c.cmd("HSET", "h2", "f", "v"), 1)

		require.ElementsMatch(
			t,
			[]string{"h1", "h2", "s0", "s1", "s2", "s3", "s4", "s5", "s6"},
			scanAll(t, c, "COUNT", "2"),
		)
		require.ElementsMatch(t, []string{"h1", "h2"}, scanAll(t, c, "COUNT", "2", "TYPE", "hash"))
		require.ElementsMatch(
			t,
			[]string{"s0", "s1", "s2", "s3", "s4", "s5", "s6"},
			scanAll(t, c, "TYPE", "string"),
		)
		require.ElementsMatch(t, []string{"s1", "s2"}, scanAll(t, c, "MATCH", "s[12]"))
	})

	t.Run("transactions", func(t *testing.T) {
		_, _, dial := newRESPDialer(t, ctx)
		c := dial()
		other := dial()
		requireString(t, c.cmd("AUTH", testRESPToken), "OK")
		requireString(t, other.cmd("AUTH", testRESPToken), "OK")

		requireString(t, c.cmd("MULTI"), "OK")
		requireString(t, c.cmd("SET", "a", "1"), "QUEUED")
		requireString(t, c.cmd("INCR", "a"), "QUEUED")
		requireString(t, c.cmd("GET", "a"), "QUEUED")
		exec := c.cmd("EXEC")
		require.Equal(t, byte('*'), exec.typ)
		require.Len(t, exec.elems, 3)
		require.Equal(t, []string{"OK", "2", "2"}, replyStrings(exec))
		requireString(t, c.cmd("GET", "a"), "2")

		requireString(t, c.cmd("MULTI"), "OK")
		requireString(t, c.cmd("SET", "discard", "queued"), "QUEUED")
		requireString(t, c.cmd("DISCARD"), "OK")
		requireNull(t, c.cmd("GET", "discard"))
		requireErrorContains(t, c.cmd("EXEC"), "without MULTI")

		requireString(t, c.cmd("SET", "watch", "1"), "OK")
		requireString(t, c.cmd("WATCH", "watch"), "OK")
		requireString(t, other.cmd("SET", "watch", "changed"), "OK")
		requireString(t, c.cmd("MULTI"), "OK")
		requireString(t, c.cmd("INCR", "watch"), "QUEUED")
		requireNull(t, c.cmd("EXEC"))

		requireString(t, c.cmd("WATCH", "watch"), "OK")
		requireString(t, c.cmd("MULTI"), "OK")
		requireString(t, c.cmd("SET", "watch", "final"), "QUEUED")
		exec = c.cmd("EXEC")
		require.Equal(t, byte('*'), exec.typ)
		require.Len(t, exec.elems, 1)
		requireString(t, c.cmd("GET", "watch"), "final")
	})

	t.Run("hashes", func(t *testing.T) {
		c, _, _ := newAuthedRESP(t, ctx)

		requireInt(t, c.cmd("HSET", "h", "a", "1", "b", "2"), 2)
		requireInt(t, c.cmd("HSET", "h", "a", "9", "c", "3"), 1)
		requireString(t, c.cmd("HGET", "h", "a"), "9")
		requireNull(t, c.cmd("HGET", "h", "missing"))
		requireInt(t, c.cmd("HLEN", "h"), 3)
		requireInt(t, c.cmd("HEXISTS", "h", "b"), 1)
		requireInt(t, c.cmd("HEXISTS", "h", "z"), 0)
		requireString(t, c.cmd("TYPE", "h"), "hash")
		requireInt(t, c.cmd("HSETNX", "h", "a", "x"), 0)
		requireInt(t, c.cmd("HSETNX", "h", "d", "4"), 1)

		mget := c.cmd("HMGET", "h", "a", "missing", "b")
		require.Len(t, mget.elems, 3)
		require.Equal(t, "9", mget.elems[0].str)
		require.True(t, mget.elems[1].null)
		require.Equal(t, "2", mget.elems[2].str)
		requireInt(t, c.cmd("HINCRBY", "h", "b", "5"), 7)

		require.ElementsMatch(t, []string{"a", "b", "c", "d"}, replyStrings(c.cmd("HKEYS", "h")))
		require.ElementsMatch(t, []string{"9", "7", "3", "4"}, replyStrings(c.cmd("HVALS", "h")))
		require.Equal(
			t,
			map[string]string{"a": "9", "b": "7", "c": "3", "d": "4"},
			replyMap(t, c.cmd("HGETALL", "h")),
		)
		requireInt(t, c.cmd("HDEL", "h", "a", "b", "missing"), 2)
		requireInt(t, c.cmd("HDEL", "h", "c", "d"), 2)
		requireString(t, c.cmd("TYPE", "h"), "none")
	})

	t.Run("lists", func(t *testing.T) {
		c, _, _ := newAuthedRESP(t, ctx)

		requireInt(t, c.cmd("RPUSH", "l", "b", "c", "d"), 3)
		requireInt(t, c.cmd("LPUSH", "l", "a"), 4)
		requireString(t, c.cmd("TYPE", "l"), "list")
		requireInt(t, c.cmd("LLEN", "l"), 4)
		require.Equal(
			t,
			[]string{"a", "b", "c", "d"},
			replyStrings(c.cmd("LRANGE", "l", "0", "-1")),
		)
		requireString(t, c.cmd("LINDEX", "l", "0"), "a")
		requireString(t, c.cmd("LINDEX", "l", "-1"), "d")
		requireNull(t, c.cmd("LINDEX", "l", "99"))
		requireString(t, c.cmd("LSET", "l", "1", "B"), "OK")
		requireString(t, c.cmd("LINDEX", "l", "1"), "B")
		requireErrorContains(t, c.cmd("LSET", "l", "99", "x"), "out of range")
		requireString(t, c.cmd("LPOP", "l"), "a")
		requireString(t, c.cmd("RPOP", "l"), "d")
		require.Equal(t, []string{"B", "c"}, replyStrings(c.cmd("LPOP", "l", "5")))
		requireString(t, c.cmd("TYPE", "l"), "none")

		requireInt(t, c.cmd("RPUSH", "l2", "a", "b", "a", "c", "a"), 5)
		requireInt(t, c.cmd("LREM", "l2", "2", "a"), 2)
		require.Equal(t, []string{"b", "c", "a"}, replyStrings(c.cmd("LRANGE", "l2", "0", "-1")))
		requireString(t, c.cmd("LTRIM", "l2", "0", "1"), "OK")
		requireInt(t, c.cmd("LLEN", "l2"), 2)
	})

	t.Run("sets", func(t *testing.T) {
		c, _, _ := newAuthedRESP(t, ctx)

		requireInt(t, c.cmd("SADD", "s", "a", "b", "c", "a"), 3)
		requireString(t, c.cmd("TYPE", "s"), "set")
		requireInt(t, c.cmd("SCARD", "s"), 3)
		requireInt(t, c.cmd("SISMEMBER", "s", "b"), 1)
		requireInt(t, c.cmd("SISMEMBER", "s", "z"), 0)
		require.ElementsMatch(t, []string{"a", "b", "c"}, replyStrings(c.cmd("SMEMBERS", "s")))
		requireInt(t, c.cmd("SREM", "s", "a", "z"), 1)
		popped := c.cmd("SPOP", "s")
		require.Contains(t, []string{"b", "c"}, popped.str)
		requireInt(t, c.cmd("SCARD", "s"), 1)

		requireInt(t, c.cmd("SADD", "s1", "a", "b", "c"), 3)
		requireInt(t, c.cmd("SADD", "s2", "b", "c", "d"), 3)
		require.ElementsMatch(
			t,
			[]string{"a", "b", "c", "d"},
			replyStrings(c.cmd("SUNION", "s1", "s2")),
		)
		require.ElementsMatch(t, []string{"b", "c"}, replyStrings(c.cmd("SINTER", "s1", "s2")))
		require.ElementsMatch(t, []string{"a"}, replyStrings(c.cmd("SDIFF", "s1", "s2")))
	})

	t.Run("sorted sets", func(t *testing.T) {
		c, _, _ := newAuthedRESP(t, ctx)

		requireInt(t, c.cmd("ZADD", "z", "1", "a", "3", "c", "2", "b"), 3)
		requireString(t, c.cmd("TYPE", "z"), "zset")
		requireInt(t, c.cmd("ZCARD", "z"), 3)
		requireString(t, c.cmd("ZSCORE", "z", "b"), "2")
		requireNull(t, c.cmd("ZSCORE", "z", "missing"))
		requireInt(t, c.cmd("ZRANK", "z", "a"), 0)
		requireInt(t, c.cmd("ZRANK", "z", "c"), 2)
		require.Equal(t, []string{"a", "b", "c"}, replyStrings(c.cmd("ZRANGE", "z", "0", "-1")))
		require.Equal(
			t,
			[]string{"a", "1"},
			replyStrings(c.cmd("ZRANGE", "z", "0", "0", "WITHSCORES")),
		)
		require.Equal(t, []string{"b", "c"}, replyStrings(c.cmd("ZRANGEBYSCORE", "z", "2", "+inf")))
		require.Equal(t, []string{"b", "c"}, replyStrings(c.cmd("ZRANGEBYSCORE", "z", "(1", "3")))
		requireString(t, c.cmd("ZINCRBY", "z", "5", "a"), "6")
		requireInt(t, c.cmd("ZRANK", "z", "a"), 2)
		requireInt(t, c.cmd("ZREM", "z", "a", "missing"), 1)
	})

	t.Run("streams", func(t *testing.T) {
		c, _, _ := newAuthedRESP(t, ctx)

		requireString(t, c.cmd("XADD", "st", "1-1", "f", "a"), "1-1")
		requireString(t, c.cmd("XADD", "st", "2-1", "f", "b"), "2-1")
		requireString(t, c.cmd("XADD", "st", "3-1", "g", "c"), "3-1")
		requireString(t, c.cmd("TYPE", "st"), "stream")
		requireInt(t, c.cmd("XLEN", "st"), 3)
		requireErrorContains(t, c.cmd("XADD", "st", "2-1", "f", "x"), "equal or smaller")

		rangeAll := c.cmd("XRANGE", "st", "-", "+")
		require.Len(t, rangeAll.elems, 3)
		require.Equal(t, "1-1", rangeAll.elems[0].elems[0].str)
		require.Equal(t, []string{"f", "a"}, replyStrings(rangeAll.elems[0].elems[1]))

		mid := c.cmd("XRANGE", "st", "2", "2")
		require.Len(t, mid.elems, 1)
		require.Equal(t, "2-1", mid.elems[0].elems[0].str)

		read := c.cmd("XREAD", "STREAMS", "st", "1-1")
		require.False(t, read.null)
		require.Len(t, read.elems, 1)
		require.Equal(t, "st", read.elems[0].elems[0].str)
		require.Len(t, read.elems[0].elems[1].elems, 2)
		requireNull(t, c.cmd("XREAD", "STREAMS", "st", "$"))

		auto := c.cmd("XADD", "st", "*", "f", "z")
		require.Equal(t, byte('$'), auto.typ)
		require.Contains(t, auto.str, "-")
	})

	t.Run("wrong type and halted runtime", func(t *testing.T) {
		c, _, rt := newAuthedRESP(t, ctx)

		requireString(t, c.cmd("SET", "s", "v"), "OK")
		requireErrorContains(t, c.cmd("HGET", "s", "f"), "WRONGTYPE")
		requireErrorContains(t, c.cmd("HSET", "s", "f", "v"), "WRONGTYPE")
		requireInt(t, c.cmd("HSET", "h", "f", "v"), 1)
		requireErrorContains(t, c.cmd("GET", "h"), "WRONGTYPE")

		rt.NotifyHalt()
		requireErrorContains(t, c.cmd("GET", "s"), "storage halted")
	})

	t.Run("pubsub", func(t *testing.T) {
		_, _, dial := newRESPDialer(t, ctx)
		sub := dial()
		pub := dial()
		requireString(t, sub.cmd("AUTH", testRESPToken), "OK")
		requireString(t, pub.cmd("AUTH", testRESPToken), "OK")

		r := sub.cmd("SUBSCRIBE", "news")
		require.Equal(t, byte('*'), r.typ)
		require.Equal(t, []string{"subscribe", "news", "1"}, replyStrings(r))
		requireInt(t, pub.cmd("PUBLISH", "news", "hello"), 1)

		msg := sub.read()
		require.Equal(t, byte('*'), msg.typ)
		require.Equal(t, []string{"message", "news", "hello"}, replyStrings(msg))
		requireInt(t, pub.cmd("PUBLISH", "other", "x"), 0)
	})
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		s       string
		want    bool
	}{
		{"star", "*", "anything", true},
		{"prefix", "user:*", "user:42", true},
		{"prefix miss", "user:*", "post:42", false},
		{"question", "a/?/c", "a/b/c", true},
		{"star spans slash", "a*c", "a/b/c", true},
		{"class", "h[ae]llo", "hello", true},
		{"class miss", "h[ae]llo", "hillo", false},
		{"negated class", "h[^x]llo", "hello", true},
		{"range", "[a-c]", "b", true},
		{"range miss", "[a-c]", "d", false},
		{"exact", "foo", "foo", true},
		{"exact miss", "foo", "foobar", false},
		{"escaped star", `a\*c`, "a*c", true},
		{"escaped star miss", `a\*c`, "axc", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, globMatch(tc.pattern, tc.s))
		})
	}
}
