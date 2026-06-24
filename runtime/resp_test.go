package runtime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRespBulk(t *testing.T) {
	if got := respBulk("version"); got != "$7\r\nversion\r\n" {
		t.Fatalf("respBulk: got %q", got)
	}
	if got := respBulk(""); got != "$0\r\n\r\n" {
		t.Fatalf("respBulk empty: got %q", got)
	}
}

// =============================================================================
// In-memory fake engine (satisfies kvEngine; no DynamoDB needed)
// =============================================================================

type fakeEntry struct {
	val     []byte
	version uint64
	expires int64 // unix seconds; 0 = none
	deleted bool
	kvType  string // "" = string; else hash/list/set/zset/stream
}

type fakeKV struct {
	mu   sync.Mutex
	data map[string]*fakeEntry
}

func newFakeKV() *fakeKV { return &fakeKV{data: map[string]*fakeEntry{}} }

func fakeGone(e *fakeEntry) bool {
	return e == nil || e.deleted || (e.expires > 0 && time.Now().Unix() >= e.expires)
}

func (f *fakeKV) Get(_ context.Context, key string) ([]byte, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.data[key]
	if fakeGone(e) {
		return nil, 0, ErrKVNotFound
	}
	if e.kvType != "" {
		return nil, 0, ErrWrongType
	}
	return e.val, e.version, nil
}

func (f *fakeKV) SetMode(_ context.Context, key string, value []byte, ttl int64, mode setMode) (uint64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.data[key]
	exists := !fakeGone(e)
	if (mode == setNX && exists) || (mode == setXX && !exists) {
		return 0, false, nil
	}
	ver := uint64(1)
	if e != nil {
		ver = e.version + 1
	}
	var expires int64
	if ttl > 0 {
		expires = time.Now().Unix() + ttl
	}
	f.data[key] = &fakeEntry{val: append([]byte(nil), value...), version: ver, expires: expires}
	return ver, true, nil
}

func (f *fakeKV) Exists(_ context.Context, key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !fakeGone(f.data[key]), nil
}

func (f *fakeKV) Del(_ context.Context, key string) (bool, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.data[key]
	if fakeGone(e) {
		v := uint64(0)
		if e != nil {
			v = e.version
		}
		return false, v, nil
	}
	e.deleted, e.val, e.version = true, nil, e.version+1
	return true, e.version, nil
}

func (f *fakeKV) TTL(_ context.Context, key string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.data[key]
	if fakeGone(e) {
		return -2, nil
	}
	if e.expires == 0 {
		return -1, nil
	}
	return e.expires - time.Now().Unix(), nil
}

func (f *fakeKV) Expire(_ context.Context, key string, ttl int64) (bool, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.data[key]
	if fakeGone(e) {
		v := uint64(0)
		if e != nil {
			v = e.version
		}
		return false, v, nil
	}
	e.expires = time.Now().Unix() + ttl
	return true, e.version, nil
}

func (f *fakeKV) Incr(_ context.Context, key string, delta int64) (int64, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.data[key]
	var cur int64
	if !fakeGone(e) {
		if e.kvType != "" {
			return 0, 0, ErrWrongType
		}
		n, err := strconv.ParseInt(string(e.val), 10, 64)
		if err != nil {
			return 0, 0, ErrNotInteger
		}
		cur = n
	}
	ver := uint64(1)
	if e != nil {
		ver = e.version + 1
	}
	next := cur + delta
	f.data[key] = &fakeEntry{val: []byte(strconv.FormatInt(next, 10)), version: ver}
	return next, ver, nil
}

func (f *fakeKV) Append(_ context.Context, key string, suffix []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.data[key]
	var cur []byte
	expires := int64(0)
	ver := uint64(1)
	if !fakeGone(e) {
		if e.kvType != "" {
			return 0, ErrWrongType
		}
		cur, expires, ver = e.val, e.expires, e.version+1
	} else if e != nil {
		ver = e.version + 1
	}
	next := append(append([]byte(nil), cur...), suffix...)
	f.data[key] = &fakeEntry{val: next, version: ver, expires: expires}
	return len(next), nil
}

func (f *fakeKV) GetSet(_ context.Context, key string, value []byte) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.data[key]
	var old []byte
	existed := false
	ver := uint64(1)
	if !fakeGone(e) {
		if e.kvType != "" {
			return nil, false, ErrWrongType
		}
		old, existed = e.val, true
	}
	if e != nil {
		ver = e.version + 1
	}
	f.data[key] = &fakeEntry{val: value, version: ver}
	return old, existed, nil
}

func (f *fakeKV) Rename(_ context.Context, src, dst string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.data[src]
	if fakeGone(e) {
		return ErrKVNotFound
	}
	ver := uint64(1)
	if d := f.data[dst]; d != nil {
		ver = d.version + 1
	}
	f.data[dst] = &fakeEntry{val: e.val, version: ver, expires: e.expires, kvType: e.kvType}
	sver := e.version + 1
	f.data[src] = &fakeEntry{version: sver, deleted: true, kvType: e.kvType}
	return nil
}

func (f *fakeKV) Persist(_ context.Context, key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.data[key]
	if fakeGone(e) || e.expires == 0 {
		return false, nil
	}
	e.expires = 0
	return true, nil
}

func (f *fakeKV) ScanKeys(_ context.Context, cursor string, count int) ([]kvKeyInfo, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k, e := range f.data {
		if !fakeGone(e) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys) // stable order so the index cursor is meaningful
	idx := 0
	if cursor != "" && cursor != "0" {
		idx, _ = strconv.Atoi(cursor)
	}
	if count <= 0 {
		count = 10
	}
	end := min(idx+count, len(keys))
	var out []kvKeyInfo
	for _, k := range keys[idx:end] {
		t := f.data[k].kvType
		if t == "" {
			t = "string"
		}
		out = append(out, kvKeyInfo{Key: k, Type: t})
	}
	next := "0"
	if end < len(keys) {
		next = strconv.Itoa(end)
	}
	return out, next, nil
}

func (f *fakeKV) Version(_ context.Context, key string) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e := f.data[key]; e != nil {
		return e.version, nil
	}
	return 0, nil
}

func (f *fakeKV) TypeOf(_ context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.data[key]
	if fakeGone(e) {
		return "none", nil
	}
	if e.kvType == "" {
		return "string", nil
	}
	return e.kvType, nil
}

func (f *fakeKV) ReadTyped(_ context.Context, key, kvType string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.data[key]
	if fakeGone(e) {
		return nil, false, nil
	}
	if e.kvType != kvType {
		return nil, false, ErrWrongType
	}
	return e.val, true, nil
}

func (f *fakeKV) ModifyTyped(_ context.Context, key, kvType string, fn func([]byte) ([]byte, bool, error)) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.data[key]
	var cur []byte
	if !fakeGone(e) {
		if e.kvType != kvType {
			return 0, ErrWrongType
		}
		cur = e.val
	}
	next, del, err := fn(cur)
	if err != nil {
		return 0, err
	}
	ver := uint64(1)
	if e != nil {
		ver = e.version + 1
	}
	if del {
		if fakeGone(e) {
			if e != nil {
				return e.version, nil
			}
			return 0, nil
		}
		f.data[key] = &fakeEntry{version: ver, deleted: true, kvType: kvType}
		return ver, nil
	}
	expires := int64(0)
	if !fakeGone(e) {
		expires = e.expires
	}
	f.data[key] = &fakeEntry{val: next, version: ver, expires: expires, kvType: kvType}
	return ver, nil
}

// =============================================================================
// RESP client + loopback harness
// =============================================================================

type reply struct {
	typ        byte // '+' '-' ':' '$' '*' '%' '_'
	str        string
	null       bool
	version    uint64
	hasVersion bool
	elems      []reply
}

type respClient struct {
	conn net.Conn
	br   *bufio.Reader
}

func (c *respClient) cmd(args ...string) reply {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := c.conn.Write([]byte(b.String())); err != nil {
		panic(err)
	}
	return c.read()
}

func (c *respClient) read() reply {
	line, err := c.br.ReadString('\n')
	if err != nil {
		panic(err)
	}
	line = strings.TrimRight(line, "\r\n")
	switch line[0] {
	case '|': // RESP3 attribute: read pairs, attach version, then read the real reply
		n, _ := strconv.Atoi(line[1:])
		var ver uint64
		var has bool
		for i := 0; i < n; i++ {
			k := c.read()
			v := c.read()
			if k.str == "version" {
				ver, _ = strconv.ParseUint(v.str, 10, 64)
				has = true
			}
		}
		r := c.read()
		r.version, r.hasVersion = ver, has
		return r
	case '+', '-', ':':
		return reply{typ: line[0], str: line[1:]}
	case '_':
		return reply{typ: '_', null: true}
	case '$':
		n, _ := strconv.Atoi(line[1:])
		if n < 0 {
			return reply{typ: '$', null: true}
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(c.br, buf); err != nil {
			panic(err)
		}
		return reply{typ: '$', str: string(buf[:n])}
	case '*', '%':
		n, _ := strconv.Atoi(line[1:])
		if n < 0 {
			return reply{typ: line[0], null: true} // *-1 = null array
		}
		count := n
		if line[0] == '%' {
			count = n * 2
		}
		r := reply{typ: line[0]}
		for i := 0; i < count; i++ {
			r.elems = append(r.elems, c.read())
		}
		return r
	default:
		panic("unknown reply type: " + line)
	}
}

const testRESPToken = "s3cret"

// startRESP runs a real RESPServer over loopback TCP and returns a connected,
// un-authenticated client. authToken is always set (auth is mandatory).
func startRESP(t *testing.T, eng kvEngine, authToken string) *respClient {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &RESPServer{kv: eng, authToken: authToken, cmdTimeout: 2 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(); _ = ln.Close() })
	return &respClient{conn: conn, br: bufio.NewReader(conn)}
}

// startAuthedRESP starts a server and returns a client that has already
// authenticated, for tests that exercise commands rather than the AUTH gate.
func startAuthedRESP(t *testing.T, eng kvEngine) *respClient {
	t.Helper()
	c := startRESP(t, eng, testRESPToken)
	wantStr(t, c.cmd("AUTH", testRESPToken), "OK")
	return c
}

// startRESPShared starts one server and returns a dialer for multiple
// authenticated clients sharing it (needed for pub/sub).
func startRESPShared(t *testing.T, eng kvEngine) func() *respClient {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &RESPServer{kv: eng, authToken: testRESPToken, cmdTimeout: 2 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return func() *respClient {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		c := &respClient{conn: conn, br: bufio.NewReader(conn)}
		wantStr(t, c.cmd("AUTH", testRESPToken), "OK")
		return c
	}
}

func wantStr(t *testing.T, r reply, want string) {
	t.Helper()
	if r.str != want {
		t.Fatalf("reply = %q (type %c), want %q", r.str, r.typ, want)
	}
}

// =============================================================================
// Tests
// =============================================================================

func TestRESP_PingAndUnknown(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	wantStr(t, c.cmd("PING"), "PONG")
	wantStr(t, c.cmd("PING", "hi"), "hi")
	if r := c.cmd("BOGUS"); r.typ != '-' || !strings.Contains(r.str, "unknown command") {
		t.Fatalf("BOGUS: %q", r.str)
	}
}

func TestRESP_AuthGate(t *testing.T) {
	c := startRESP(t, newFakeKV(), "s3cret")
	if r := c.cmd("GET", "k"); r.typ != '-' || !strings.HasPrefix(r.str, "NOAUTH") {
		t.Fatalf("expected NOAUTH before AUTH, got %q", r.str)
	}
	if r := c.cmd("AUTH", "wrong"); r.typ != '-' || !strings.HasPrefix(r.str, "WRONGPASS") {
		t.Fatalf("expected WRONGPASS, got %q", r.str)
	}
	wantStr(t, c.cmd("AUTH", "s3cret"), "OK")
	if r := c.cmd("GET", "k"); !r.null {
		t.Fatalf("after AUTH, GET missing should be null, got %q", r.str)
	}
}

// go-redis authenticates via HELLO's AUTH option, so the server must honor it:
// the connection is usable afterwards without a separate AUTH.
func TestRESP_HelloAuth(t *testing.T) {
	c := startRESP(t, newFakeKV(), "s3cret")
	if r := c.cmd("HELLO", "3", "AUTH", "default", "s3cret"); r.typ != '%' {
		t.Fatalf("HELLO AUTH should return a map, got type %c %q", r.typ, r.str)
	}
	wantStr(t, c.cmd("SET", "k", "v"), "OK")
	wantStr(t, c.cmd("GET", "k"), "v")

	bad := startRESP(t, newFakeKV(), "s3cret")
	if r := bad.cmd("HELLO", "3", "AUTH", "default", "nope"); r.typ != '-' || !strings.HasPrefix(r.str, "WRONGPASS") {
		t.Fatalf("HELLO with wrong pass: want WRONGPASS, got %q", r.str)
	}
	if r := bad.cmd("GET", "k"); r.typ != '-' || !strings.HasPrefix(r.str, "NOAUTH") {
		t.Fatalf("after failed HELLO AUTH, GET should be NOAUTH, got %q", r.str)
	}
}

func TestRESP_SetGetRoundTrip(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	wantStr(t, c.cmd("SET", "k", "v1"), "OK")
	wantStr(t, c.cmd("GET", "k"), "v1")
	wantStr(t, c.cmd("SET", "k", "v2"), "OK")
	wantStr(t, c.cmd("GET", "k"), "v2")
	if r := c.cmd("GET", "missing"); !r.null {
		t.Fatalf("GET missing: want null, got %q", r.str)
	}
}

func TestRESP_NXXX(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	wantStr(t, c.cmd("SET", "k", "a", "NX"), "OK") // absent → set
	if r := c.cmd("SET", "k", "b", "NX"); !r.null {
		t.Fatalf("NX on existing should be null, got %q", r.str)
	}
	wantStr(t, c.cmd("GET", "k"), "a") // unchanged
	wantStr(t, c.cmd("SET", "k", "c", "XX"), "OK")
	wantStr(t, c.cmd("GET", "k"), "c")
	if r := c.cmd("SET", "new", "x", "XX"); !r.null {
		t.Fatalf("XX on absent should be null, got %q", r.str)
	}
	if r := c.cmd("SET", "k", "v", "NX", "XX"); r.typ != '-' || !strings.Contains(r.str, "syntax error") {
		t.Fatalf("NX+XX should be syntax error, got %q", r.str)
	}
}

func TestRESP_SetNxSetEx(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	if r := c.cmd("SETNX", "k", "a"); r.str != "1" {
		t.Fatalf("SETNX new: want 1, got %q", r.str)
	}
	if r := c.cmd("SETNX", "k", "b"); r.str != "0" {
		t.Fatalf("SETNX existing: want 0, got %q", r.str)
	}
	wantStr(t, c.cmd("SETEX", "k2", "100", "v"), "OK")
	if r := c.cmd("TTL", "k2"); r.str == "" || r.str == "-1" || r.str == "-2" {
		t.Fatalf("TTL after SETEX should be positive, got %q", r.str)
	}
}

func TestRESP_DelExistsTTL(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	c.cmd("SET", "k", "v")
	if r := c.cmd("EXISTS", "k", "missing"); r.str != "1" {
		t.Fatalf("EXISTS: want 1, got %q", r.str)
	}
	if r := c.cmd("TTL", "k"); r.str != "-1" {
		t.Fatalf("TTL no-expiry: want -1, got %q", r.str)
	}
	if r := c.cmd("TTL", "missing"); r.str != "-2" {
		t.Fatalf("TTL absent: want -2, got %q", r.str)
	}
	if r := c.cmd("DEL", "k", "missing"); r.str != "1" {
		t.Fatalf("DEL: want 1, got %q", r.str)
	}
	if r := c.cmd("GET", "k"); !r.null {
		t.Fatalf("GET after DEL: want null, got %q", r.str)
	}
}

func TestRESP_Counters(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	if r := c.cmd("INCR", "n"); r.str != "1" {
		t.Fatalf("INCR: want 1, got %q", r.str)
	}
	if r := c.cmd("INCRBY", "n", "5"); r.str != "6" {
		t.Fatalf("INCRBY 5: want 6, got %q", r.str)
	}
	if r := c.cmd("DECR", "n"); r.str != "5" {
		t.Fatalf("DECR: want 5, got %q", r.str)
	}
	if r := c.cmd("DECRBY", "n", "5"); r.str != "0" {
		t.Fatalf("DECRBY 5: want 0, got %q", r.str)
	}
	c.cmd("SET", "s", "notanumber")
	if r := c.cmd("INCR", "s"); r.typ != '-' || !strings.Contains(r.str, "not an integer") {
		t.Fatalf("INCR non-integer: want error, got %q", r.str)
	}
}

func TestRESP_Arity(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	for _, args := range [][]string{{"GET"}, {"SET", "k"}, {"INCRBY", "k"}} {
		if r := c.cmd(args...); r.typ != '-' || !strings.Contains(r.str, "wrong number of arguments") {
			t.Fatalf("%v: want arity error, got %q", args, r.str)
		}
	}
}

// The client-side version high-water-mark was removed in favour of the
// server-side S3 Object-Lock anchor: no reply, on any protocol, carries a
// version attribute. HELLO negotiation still works for standard clients.
func TestRESP_NoVersionAttribute(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())

	if r := c.cmd("SET", "k", "v"); r.hasVersion {
		t.Fatalf("RESP2 reply must not carry a version attribute")
	}

	// HELLO 3 still returns a map; but replies stay bare.
	if h := c.cmd("HELLO", "3"); h.typ != '%' {
		t.Fatalf("HELLO 3 should return a map, got type %c", h.typ)
	}
	if r := c.cmd("SET", "k", "v2"); r.hasVersion {
		t.Fatalf("RESP3 SET must not carry a version attribute")
	}
	if g := c.cmd("GET", "k"); g.str != "v2" || g.hasVersion {
		t.Fatalf("RESP3 GET: val=%q hasVersion=%v, want v2 / no attribute", g.str, g.hasVersion)
	}
}

func TestRESP_HelloNegotiation(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	if h := c.cmd("HELLO", "2"); h.typ != '*' {
		t.Fatalf("HELLO 2 should return an array, got type %c", h.typ)
	}
	if h := c.cmd("HELLO", "9"); h.typ != '-' || !strings.HasPrefix(h.str, "NOPROTO") {
		t.Fatalf("HELLO 9 should be NOPROTO, got %q", h.str)
	}
}

// go-redis sends two CLIENT SETINFO on connect and expects a status reply; an
// array reply desyncs the stream and breaks the next command.
func TestRESP_ClientAndCommand(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	wantStr(t, c.cmd("CLIENT", "SETINFO", "lib-name", "go-redis"), "OK")
	wantStr(t, c.cmd("CLIENT", "SETINFO", "lib-ver", "9.21.0"), "OK")
	if r := c.cmd("COMMAND", "DOCS"); r.typ != '*' {
		t.Fatalf("COMMAND should return an array, got type %c", r.typ)
	}
	// The stream stays in sync: a normal command still works.
	wantStr(t, c.cmd("SET", "k", "v"), "OK")
}

func TestRESP_InfoConfig(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())

	if info := c.cmd("INFO"); info.typ != '$' || !strings.Contains(info.str, "redis_version") {
		t.Fatalf("INFO = type %c %q", info.typ, info.str)
	}
	cfg := c.cmd("CONFIG", "GET", "maxmemory")
	if cfg.typ != '*' || len(cfg.elems) != 2 || cfg.elems[0].str != "maxmemory" || cfg.elems[1].str != "0" {
		t.Fatalf("CONFIG GET maxmemory = %+v", cfg)
	}
	wantStr(t, c.cmd("CONFIG", "SET", "maxmemory", "100"), "OK")
}

func TestRESP_AppendGetSetRenameKeys(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())

	// APPEND creates then extends; returns new length.
	if r := c.cmd("APPEND", "a", "foo"); r.str != "3" {
		t.Fatalf("APPEND new = %q, want 3", r.str)
	}
	if r := c.cmd("APPEND", "a", "bar"); r.str != "6" {
		t.Fatalf("APPEND = %q, want 6", r.str)
	}
	wantStr(t, c.cmd("GET", "a"), "foobar")

	// GETSET returns the old value and stores the new.
	wantStr(t, c.cmd("GETSET", "a", "new"), "foobar")
	wantStr(t, c.cmd("GET", "a"), "new")
	if r := c.cmd("GETSET", "fresh", "v"); !r.null {
		t.Fatalf("GETSET on absent key should be null")
	}

	// RENAME moves the value; source is gone, dest has it.
	wantStr(t, c.cmd("RENAME", "a", "b"), "OK")
	if r := c.cmd("GET", "a"); !r.null {
		t.Fatalf("source should be gone after RENAME")
	}
	wantStr(t, c.cmd("GET", "b"), "new")
	if r := c.cmd("RENAME", "missing", "x"); r.typ != '-' || !strings.Contains(r.str, "no such key") {
		t.Fatalf("RENAME missing = %q, want no such key", r.str)
	}

	// KEYS returns all glob-matched keys.
	c.cmd("MSET", "user:1", "a", "user:2", "b", "post:1", "c")
	got := map[string]bool{}
	for _, e := range c.cmd("KEYS", "user:*").elems {
		got[e.str] = true
	}
	if len(got) != 2 || !got["user:1"] || !got["user:2"] {
		t.Fatalf("KEYS user:* = %v, want user:1,user:2", got)
	}

	// APPEND on a non-string key → WRONGTYPE.
	c.cmd("HSET", "h", "f", "v")
	if r := c.cmd("APPEND", "h", "x"); r.typ != '-' || !strings.HasPrefix(r.str, "WRONGTYPE") {
		t.Fatalf("APPEND on hash = %q, want WRONGTYPE", r.str)
	}
}

func TestRESP_StringOps(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())

	wantStr(t, c.cmd("MSET", "a", "1", "b", "hello", "c", "x"), "OK")

	mg := c.cmd("MGET", "a", "missing", "b")
	if mg.typ != '*' || len(mg.elems) != 3 {
		t.Fatalf("MGET: want 3-element array, got type %c len %d", mg.typ, len(mg.elems))
	}
	if mg.elems[0].str != "1" || !mg.elems[1].null || mg.elems[2].str != "hello" {
		t.Fatalf("MGET elements wrong: %+v", mg.elems)
	}

	if r := c.cmd("STRLEN", "b"); r.str != "5" {
		t.Fatalf("STRLEN b = %q, want 5", r.str)
	}
	if r := c.cmd("STRLEN", "missing"); r.str != "0" {
		t.Fatalf("STRLEN missing = %q, want 0", r.str)
	}
	if r := c.cmd("TYPE", "b"); r.str != "string" {
		t.Fatalf("TYPE b = %q, want string", r.str)
	}
	if r := c.cmd("TYPE", "missing"); r.str != "none" {
		t.Fatalf("TYPE missing = %q, want none", r.str)
	}

	// GETDEL returns the value then removes it.
	if r := c.cmd("GETDEL", "a"); r.str != "1" {
		t.Fatalf("GETDEL a = %q, want 1", r.str)
	}
	if r := c.cmd("GET", "a"); !r.null {
		t.Fatalf("GET after GETDEL should be null")
	}

	// PERSIST clears a TTL; PTTL reflects it in milliseconds.
	wantStr(t, c.cmd("SETEX", "t", "100", "v"), "OK")
	if r := c.cmd("PTTL", "t"); r.str == "-1" || r.str == "-2" {
		t.Fatalf("PTTL on key with TTL should be positive, got %q", r.str)
	}
	if r := c.cmd("PERSIST", "t"); r.str != "1" {
		t.Fatalf("PERSIST t = %q, want 1", r.str)
	}
	if r := c.cmd("PTTL", "t"); r.str != "-1" {
		t.Fatalf("PTTL after PERSIST = %q, want -1", r.str)
	}
	if r := c.cmd("PTTL", "missing"); r.str != "-2" {
		t.Fatalf("PTTL missing = %q, want -2", r.str)
	}
}

func TestRESP_Scan(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	wantStr(t, c.cmd("MSET", "user:1", "a", "user:2", "b", "post:1", "c"), "OK")

	all := c.cmd("SCAN", "0")
	if all.typ != '*' || len(all.elems) != 2 || all.elems[0].str != "0" {
		t.Fatalf("SCAN: want [cursor, keys], got %+v", all)
	}
	if len(all.elems[1].elems) != 3 {
		t.Fatalf("SCAN should return 3 keys, got %d", len(all.elems[1].elems))
	}

	m := c.cmd("SCAN", "0", "MATCH", "user:*")
	keys := map[string]bool{}
	for _, e := range m.elems[1].elems {
		keys[e.str] = true
	}
	if len(keys) != 2 || !keys["user:1"] || !keys["user:2"] {
		t.Fatalf("SCAN MATCH user:* = %v, want user:1,user:2", keys)
	}
}

// scanAll drives SCAN's cursor loop to completion and returns every key.
func scanAll(t *testing.T, c *respClient, args ...string) []string {
	t.Helper()
	var out []string
	cursor := "0"
	for i := 0; ; i++ {
		r := c.cmd(append([]string{"SCAN", cursor}, args...)...)
		if r.typ != '*' || len(r.elems) != 2 {
			t.Fatalf("SCAN reply = %+v", r)
		}
		for _, e := range r.elems[1].elems {
			out = append(out, e.str)
		}
		cursor = r.elems[0].str
		if cursor == "0" {
			return out
		}
		if i > 1000 {
			t.Fatal("SCAN cursor did not terminate")
		}
	}
}

// SCAN paginates via the cursor (COUNT page size) and TYPE filters by data type.
func TestRESP_ScanCursorAndType(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	for i := 0; i < 7; i++ {
		wantStr(t, c.cmd("SET", "s"+strconv.Itoa(i), "v"), "OK")
	}
	c.cmd("HSET", "h1", "f", "v")
	c.cmd("HSET", "h2", "f", "v")

	// COUNT=2 forces multiple pages; all 9 keys come back across the loop.
	all := scanAll(t, c, "COUNT", "2")
	if len(all) != 9 {
		t.Fatalf("SCAN COUNT loop returned %d keys, want 9", len(all))
	}

	// TYPE filters across pages.
	hashes := scanAll(t, c, "COUNT", "2", "TYPE", "hash")
	sort.Strings(hashes)
	if len(hashes) != 2 || hashes[0] != "h1" || hashes[1] != "h2" {
		t.Fatalf("SCAN TYPE hash = %v, want h1,h2", hashes)
	}
	strs := scanAll(t, c, "TYPE", "string")
	if len(strs) != 7 {
		t.Fatalf("SCAN TYPE string = %d keys, want 7", len(strs))
	}
}

func TestRESP_MultiExec(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())

	wantStr(t, c.cmd("MULTI"), "OK")
	wantStr(t, c.cmd("SET", "a", "1"), "QUEUED")
	wantStr(t, c.cmd("INCR", "a"), "QUEUED")
	wantStr(t, c.cmd("GET", "a"), "QUEUED")

	r := c.cmd("EXEC")
	if r.typ != '*' || len(r.elems) != 3 {
		t.Fatalf("EXEC: want 3-element array, got type %c len %d", r.typ, len(r.elems))
	}
	if r.elems[0].str != "OK" || r.elems[1].str != "2" || r.elems[2].str != "2" {
		t.Fatalf("EXEC results = %q,%q,%q; want OK,2,2", r.elems[0].str, r.elems[1].str, r.elems[2].str)
	}
	wantStr(t, c.cmd("GET", "a"), "2") // committed
}

func TestRESP_Discard(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	wantStr(t, c.cmd("MULTI"), "OK")
	wantStr(t, c.cmd("SET", "a", "queued"), "QUEUED")
	wantStr(t, c.cmd("DISCARD"), "OK")
	if r := c.cmd("GET", "a"); !r.null {
		t.Fatalf("after DISCARD, key must not be set, got %q", r.str)
	}
	if r := c.cmd("EXEC"); r.typ != '-' || !strings.Contains(r.str, "without MULTI") {
		t.Fatalf("EXEC after DISCARD should error, got %q", r.str)
	}
}

// WATCH aborts EXEC (null array) when a watched key changes; otherwise it commits.
func TestRESP_WatchAbort(t *testing.T) {
	kv := newFakeKV()
	c := startAuthedRESP(t, kv)
	wantStr(t, c.cmd("SET", "a", "1"), "OK")

	wantStr(t, c.cmd("WATCH", "a"), "OK")
	// Simulate another connection modifying "a" after WATCH.
	if _, _, err := kv.SetMode(context.Background(), "a", []byte("changed"), 0, setAlways); err != nil {
		t.Fatalf("concurrent set: %v", err)
	}
	wantStr(t, c.cmd("MULTI"), "OK")
	wantStr(t, c.cmd("INCR", "a"), "QUEUED")
	if r := c.cmd("EXEC"); !r.null {
		t.Fatalf("EXEC after watched key changed must abort (null), got type %c %q", r.typ, r.str)
	}

	// Unchanged watched key → EXEC commits.
	wantStr(t, c.cmd("WATCH", "a"), "OK")
	wantStr(t, c.cmd("MULTI"), "OK")
	wantStr(t, c.cmd("SET", "a", "final"), "QUEUED")
	if r := c.cmd("EXEC"); r.typ != '*' || len(r.elems) != 1 {
		t.Fatalf("EXEC should commit, got type %c", r.typ)
	}
	wantStr(t, c.cmd("GET", "a"), "final")
}

func TestRESP_Hash(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())

	// HSET returns count of NEW fields.
	if r := c.cmd("HSET", "h", "a", "1", "b", "2"); r.str != "2" {
		t.Fatalf("HSET = %q, want 2", r.str)
	}
	if r := c.cmd("HSET", "h", "a", "9", "c", "3"); r.str != "1" {
		t.Fatalf("HSET (1 new) = %q, want 1", r.str)
	}
	wantStr(t, c.cmd("HGET", "h", "a"), "9")
	if r := c.cmd("HGET", "h", "missing"); !r.null {
		t.Fatalf("HGET missing should be null")
	}
	if r := c.cmd("HLEN", "h"); r.str != "3" {
		t.Fatalf("HLEN = %q, want 3", r.str)
	}
	if r := c.cmd("HEXISTS", "h", "b"); r.str != "1" {
		t.Fatalf("HEXISTS b = %q, want 1", r.str)
	}
	if r := c.cmd("HEXISTS", "h", "z"); r.str != "0" {
		t.Fatalf("HEXISTS z = %q, want 0", r.str)
	}
	wantStr(t, c.cmd("TYPE", "h"), "hash")

	// HSETNX only sets when absent.
	if r := c.cmd("HSETNX", "h", "a", "x"); r.str != "0" {
		t.Fatalf("HSETNX existing = %q, want 0", r.str)
	}
	if r := c.cmd("HSETNX", "h", "d", "4"); r.str != "1" {
		t.Fatalf("HSETNX new = %q, want 1", r.str)
	}

	// HMGET preserves order, nil for missing.
	mg := c.cmd("HMGET", "h", "a", "missing", "b")
	if len(mg.elems) != 3 || mg.elems[0].str != "9" || !mg.elems[1].null || mg.elems[2].str != "2" {
		t.Fatalf("HMGET = %+v", mg.elems)
	}

	// HINCRBY.
	if r := c.cmd("HINCRBY", "h", "b", "5"); r.str != "7" {
		t.Fatalf("HINCRBY = %q, want 7", r.str)
	}

	// HGETALL has all fields.
	all := c.cmd("HGETALL", "h")
	pairs := map[string]string{}
	for i := 0; i+1 < len(all.elems); i += 2 {
		pairs[all.elems[i].str] = all.elems[i+1].str
	}
	if pairs["a"] != "9" || pairs["b"] != "7" || pairs["c"] != "3" || pairs["d"] != "4" {
		t.Fatalf("HGETALL = %v", pairs)
	}

	// HDEL; deleting all fields removes the key.
	if r := c.cmd("HDEL", "h", "a", "b", "missing"); r.str != "2" {
		t.Fatalf("HDEL = %q, want 2", r.str)
	}
	if r := c.cmd("HDEL", "h", "c", "d"); r.str != "2" {
		t.Fatalf("HDEL rest = %q, want 2", r.str)
	}
	wantStr(t, c.cmd("TYPE", "h"), "none") // key gone after last field
}

// A hash command against a string key (and vice versa) returns WRONGTYPE.
func TestRESP_WrongType(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	wantStr(t, c.cmd("SET", "s", "v"), "OK")
	if r := c.cmd("HGET", "s", "f"); r.typ != '-' || !strings.HasPrefix(r.str, "WRONGTYPE") {
		t.Fatalf("HGET on string = %q, want WRONGTYPE", r.str)
	}
	if r := c.cmd("HSET", "s", "f", "v"); r.typ != '-' || !strings.HasPrefix(r.str, "WRONGTYPE") {
		t.Fatalf("HSET on string = %q, want WRONGTYPE", r.str)
	}

	wantStr(t, c.cmd("HSET", "h", "f", "v"), "1")
	if r := c.cmd("GET", "h"); r.typ != '-' || !strings.HasPrefix(r.str, "WRONGTYPE") {
		t.Fatalf("GET on hash = %q, want WRONGTYPE", r.str)
	}
}

func TestRESP_List(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())

	// RPUSH appends; LPUSH prepends each in turn.
	if r := c.cmd("RPUSH", "l", "b", "c", "d"); r.str != "3" {
		t.Fatalf("RPUSH = %q, want 3", r.str)
	}
	if r := c.cmd("LPUSH", "l", "a"); r.str != "4" {
		t.Fatalf("LPUSH = %q, want 4", r.str)
	}
	wantStr(t, c.cmd("TYPE", "l"), "list")
	if r := c.cmd("LLEN", "l"); r.str != "4" {
		t.Fatalf("LLEN = %q, want 4", r.str)
	}

	// LRANGE full + negative indices → a,b,c,d.
	rng := c.cmd("LRANGE", "l", "0", "-1")
	got := []string{}
	for _, e := range rng.elems {
		got = append(got, e.str)
	}
	if strings.Join(got, ",") != "a,b,c,d" {
		t.Fatalf("LRANGE = %v, want a,b,c,d", got)
	}

	wantStr(t, c.cmd("LINDEX", "l", "0"), "a")
	wantStr(t, c.cmd("LINDEX", "l", "-1"), "d")
	if r := c.cmd("LINDEX", "l", "99"); !r.null {
		t.Fatalf("LINDEX oob should be null")
	}

	wantStr(t, c.cmd("LSET", "l", "1", "B"), "OK")
	wantStr(t, c.cmd("LINDEX", "l", "1"), "B")
	if r := c.cmd("LSET", "l", "99", "x"); r.typ != '-' || !strings.Contains(r.str, "out of range") {
		t.Fatalf("LSET oob = %q", r.str)
	}

	// LPOP/RPOP.
	wantStr(t, c.cmd("LPOP", "l"), "a")
	wantStr(t, c.cmd("RPOP", "l"), "d")
	// list is now [B, c]; LPOP count.
	pop := c.cmd("LPOP", "l", "5")
	if len(pop.elems) != 2 || pop.elems[0].str != "B" || pop.elems[1].str != "c" {
		t.Fatalf("LPOP count = %+v", pop.elems)
	}
	wantStr(t, c.cmd("TYPE", "l"), "none") // emptied → key gone
}

func TestRESP_ListRemTrim(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	c.cmd("RPUSH", "l", "a", "b", "a", "c", "a")
	// LREM 2 from head removes first two "a".
	if r := c.cmd("LREM", "l", "2", "a"); r.str != "2" {
		t.Fatalf("LREM = %q, want 2", r.str)
	}
	rng := c.cmd("LRANGE", "l", "0", "-1")
	got := []string{}
	for _, e := range rng.elems {
		got = append(got, e.str)
	}
	if strings.Join(got, ",") != "b,c,a" {
		t.Fatalf("after LREM = %v, want b,c,a", got)
	}
	// LTRIM to middle.
	wantStr(t, c.cmd("LTRIM", "l", "0", "1"), "OK")
	if r := c.cmd("LLEN", "l"); r.str != "2" {
		t.Fatalf("LLEN after LTRIM = %q, want 2", r.str)
	}
}

func TestRESP_Set(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	if r := c.cmd("SADD", "s", "a", "b", "c", "a"); r.str != "3" {
		t.Fatalf("SADD = %q, want 3 (dedup)", r.str)
	}
	wantStr(t, c.cmd("TYPE", "s"), "set")
	if r := c.cmd("SCARD", "s"); r.str != "3" {
		t.Fatalf("SCARD = %q, want 3", r.str)
	}
	if r := c.cmd("SISMEMBER", "s", "b"); r.str != "1" {
		t.Fatalf("SISMEMBER b = %q, want 1", r.str)
	}
	if r := c.cmd("SISMEMBER", "s", "z"); r.str != "0" {
		t.Fatalf("SISMEMBER z = %q, want 0", r.str)
	}
	mem := c.cmd("SMEMBERS", "s")
	set := map[string]bool{}
	for _, e := range mem.elems {
		set[e.str] = true
	}
	if len(set) != 3 || !set["a"] || !set["b"] || !set["c"] {
		t.Fatalf("SMEMBERS = %v", set)
	}
	if r := c.cmd("SREM", "s", "a", "z"); r.str != "1" {
		t.Fatalf("SREM = %q, want 1", r.str)
	}

	// set ops
	c.cmd("SADD", "s1", "a", "b", "c")
	c.cmd("SADD", "s2", "b", "c", "d")
	collect := func(r reply) map[string]bool {
		m := map[string]bool{}
		for _, e := range r.elems {
			m[e.str] = true
		}
		return m
	}
	u := collect(c.cmd("SUNION", "s1", "s2"))
	if len(u) != 4 {
		t.Fatalf("SUNION = %v, want 4", u)
	}
	in := collect(c.cmd("SINTER", "s1", "s2"))
	if len(in) != 2 || !in["b"] || !in["c"] {
		t.Fatalf("SINTER = %v, want b,c", in)
	}
	d := collect(c.cmd("SDIFF", "s1", "s2"))
	if len(d) != 1 || !d["a"] {
		t.Fatalf("SDIFF = %v, want a", d)
	}
}

func TestRESP_ZSet(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())
	if r := c.cmd("ZADD", "z", "1", "a", "3", "c", "2", "b"); r.str != "3" {
		t.Fatalf("ZADD = %q, want 3", r.str)
	}
	wantStr(t, c.cmd("TYPE", "z"), "zset")
	if r := c.cmd("ZCARD", "z"); r.str != "3" {
		t.Fatalf("ZCARD = %q, want 3", r.str)
	}
	wantStr(t, c.cmd("ZSCORE", "z", "b"), "2")
	if r := c.cmd("ZSCORE", "z", "missing"); !r.null {
		t.Fatalf("ZSCORE missing should be null")
	}
	// ordered by score: a(1) b(2) c(3) → ranks 0,1,2.
	wantStr(t, c.cmd("ZRANK", "z", "a"), "0")
	wantStr(t, c.cmd("ZRANK", "z", "c"), "2")

	names := func(r reply) string {
		out := []string{}
		for _, e := range r.elems {
			out = append(out, e.str)
		}
		return strings.Join(out, ",")
	}
	if g := names(c.cmd("ZRANGE", "z", "0", "-1")); g != "a,b,c" {
		t.Fatalf("ZRANGE = %q, want a,b,c", g)
	}
	if g := names(c.cmd("ZRANGE", "z", "0", "0", "WITHSCORES")); g != "a,1" {
		t.Fatalf("ZRANGE WITHSCORES = %q, want a,1", g)
	}
	if g := names(c.cmd("ZRANGEBYSCORE", "z", "2", "+inf")); g != "b,c" {
		t.Fatalf("ZRANGEBYSCORE [2,+inf] = %q, want b,c", g)
	}
	if g := names(c.cmd("ZRANGEBYSCORE", "z", "(1", "3")); g != "b,c" {
		t.Fatalf("ZRANGEBYSCORE (1,3] = %q, want b,c", g)
	}

	wantStr(t, c.cmd("ZINCRBY", "z", "5", "a"), "6") // a: 1→6
	wantStr(t, c.cmd("ZRANK", "z", "a"), "2")        // now highest
	if r := c.cmd("ZREM", "z", "a", "missing"); r.str != "1" {
		t.Fatalf("ZREM = %q, want 1", r.str)
	}
}

func TestRESP_Stream(t *testing.T) {
	c := startAuthedRESP(t, newFakeKV())

	// Explicit IDs keep ordering deterministic for the test.
	wantStr(t, c.cmd("XADD", "st", "1-1", "f", "a"), "1-1")
	wantStr(t, c.cmd("XADD", "st", "2-1", "f", "b"), "2-1")
	wantStr(t, c.cmd("XADD", "st", "3-1", "g", "c"), "3-1")
	wantStr(t, c.cmd("TYPE", "st"), "stream")
	if r := c.cmd("XLEN", "st"); r.str != "3" {
		t.Fatalf("XLEN = %q, want 3", r.str)
	}

	// A smaller-or-equal ID is rejected.
	if r := c.cmd("XADD", "st", "2-1", "f", "x"); r.typ != '-' || !strings.Contains(r.str, "equal or smaller") {
		t.Fatalf("XADD too-small = %q", r.str)
	}

	// XRANGE full: 3 entries, each [id, [f,v]].
	rng := c.cmd("XRANGE", "st", "-", "+")
	if len(rng.elems) != 3 || rng.elems[0].elems[0].str != "1-1" {
		t.Fatalf("XRANGE = %+v", rng)
	}
	first := rng.elems[0]
	if first.elems[1].elems[0].str != "f" || first.elems[1].elems[1].str != "a" {
		t.Fatalf("XRANGE entry fields = %+v", first.elems[1].elems)
	}

	// XRANGE bounded.
	mid := c.cmd("XRANGE", "st", "2", "2")
	if len(mid.elems) != 1 || mid.elems[0].elems[0].str != "2-1" {
		t.Fatalf("XRANGE 2..2 = %+v", mid)
	}

	// XREAD after 1-1 → entries 2-1 and 3-1.
	rd := c.cmd("XREAD", "STREAMS", "st", "1-1")
	if rd.null || len(rd.elems) != 1 || rd.elems[0].elems[0].str != "st" {
		t.Fatalf("XREAD = %+v", rd)
	}
	if len(rd.elems[0].elems[1].elems) != 2 {
		t.Fatalf("XREAD should return 2 entries, got %d", len(rd.elems[0].elems[1].elems))
	}
	// XREAD with $ → nothing new → null.
	if r := c.cmd("XREAD", "STREAMS", "st", "$"); !r.null {
		t.Fatalf("XREAD $ should be null, got %+v", r)
	}

	// Auto-ID generation yields a monotonically increasing ID.
	auto := c.cmd("XADD", "st", "*", "f", "z")
	if auto.typ != '$' || !strings.Contains(auto.str, "-") {
		t.Fatalf("XADD * = %q, want ms-seq", auto.str)
	}
}

func TestRESP_PubSub(t *testing.T) {
	dial := startRESPShared(t, newFakeKV())
	sub := dial()
	pub := dial()

	// SUBSCRIBE confirmation: [subscribe, channel, count].
	r := sub.cmd("SUBSCRIBE", "news")
	if r.typ != '*' || len(r.elems) != 3 || r.elems[0].str != "subscribe" || r.elems[1].str != "news" {
		t.Fatalf("SUBSCRIBE reply = %+v", r)
	}

	// PUBLISH returns the number of receivers (1).
	if p := pub.cmd("PUBLISH", "news", "hello"); p.str != "1" {
		t.Fatalf("PUBLISH = %q, want 1", p.str)
	}

	// The subscriber receives an unsolicited [message, channel, payload].
	msg := sub.read()
	if msg.typ != '*' || len(msg.elems) != 3 || msg.elems[0].str != "message" ||
		msg.elems[1].str != "news" || msg.elems[2].str != "hello" {
		t.Fatalf("delivered message = %+v", msg)
	}

	// No subscribers on another channel → 0 receivers.
	if p := pub.cmd("PUBLISH", "other", "x"); p.str != "0" {
		t.Fatalf("PUBLISH no subs = %q, want 0", p.str)
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "anything", true},
		{"user:*", "user:42", true},
		{"user:*", "post:42", false},
		{"a/?/c", "a/b/c", true}, // * and ? span '/'
		{"a*c", "a/b/c", true},   // unlike path.Match
		{"h[ae]llo", "hello", true},
		{"h[ae]llo", "hillo", false},
		{"h[^x]llo", "hello", true},
		{"[a-c]", "b", true},
		{"[a-c]", "d", false},
		{"foo", "foo", true},
		{"foo", "foobar", false},
		{`a\*c`, "a*c", true}, // escaped literal *
		{`a\*c`, "axc", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}
