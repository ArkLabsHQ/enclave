package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// The AEAD AAD must bind {key, version, chunkIndex, chunkCount}: a value sealed
// at version N must not open under a different version (rollback), a different
// chunk position (reorder), or a different key (relabel). This is the crypto
// floor of the store's rollback/integrity guarantee.
func TestKVAAD_VersionAndPositionBinding(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand: %v", err)
	}
	plaintext := []byte("the answer is 42")

	blob, err := sealStorage(dek, plaintext, getAAD("k", 5, 0, 0))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Correct AAD opens.
	got, err := openStorage(dek, blob, getAAD("k", 5, 0, 0))
	if err != nil {
		t.Fatalf("open with correct AAD failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}

	// Each of these is an attack the AAD must defeat: rolled-back version,
	// shifted chunk index, changed chunk count, relabeled key.
	for name, aad := range map[string][]byte{
		"older version": getAAD("k", 4, 0, 0),
		"newer version": getAAD("k", 6, 0, 0),
		"wrong index":   getAAD("k", 5, 1, 0),
		"wrong count":   getAAD("k", 5, 0, 2),
		"relabeled key": getAAD("other", 5, 0, 0),
		"wrong app":     []byte("prod/evil/kv/k/v5/c0/0"),
	} {
		if _, err := openStorage(dek, blob, aad); err == nil {
			t.Errorf("%s: open MUST fail but succeeded", name)
		}
	}
}

func TestSplitChunks(t *testing.T) {
	cases := []struct {
		n, size, want int
	}{
		{0, 100, 0},
		{1, 100, 1},
		{100, 100, 1},
		{101, 100, 2},
		{250, 100, 3},
	}
	for _, c := range cases {
		data := make([]byte, c.n)
		chunks := splitChunks(data, c.size)
		if len(chunks) != c.want {
			t.Errorf("splitChunks(%d,%d): got %d chunks, want %d", c.n, c.size, len(chunks), c.want)
		}
		// Reassembly must equal the input.
		var out []byte
		for _, ch := range chunks {
			out = append(out, ch...)
		}
		if len(out) != c.n {
			t.Errorf("splitChunks(%d,%d): reassembled %d bytes", c.n, c.size, len(out))
		}
	}
}

// =============================================================================
// fakeDDB — an in-memory DynamoDB that honors the ConditionExpression /
// UpdateExpression subset the KV engine emits (versionCAS, SET/REMOVE), so the
// real engine's atomicity can be tested without AWS.
// =============================================================================

type fakeDDB struct {
	mu    sync.Mutex
	items map[string]map[string]ddbtypes.AttributeValue
}

func newFakeDDB() *fakeDDB { return &fakeDDB{items: map[string]map[string]ddbtypes.AttributeValue{}} }

func ddbS(av ddbtypes.AttributeValue) string {
	if s, ok := av.(*ddbtypes.AttributeValueMemberS); ok {
		return s.Value
	}
	return ""
}

func compositeKey(m map[string]ddbtypes.AttributeValue) string {
	return ddbS(m[attrPartitionKey]) + "\x00" + ddbS(m[attrSortKey])
}

func cloneItem(m map[string]ddbtypes.AttributeValue) map[string]ddbtypes.AttributeValue {
	if m == nil {
		return nil
	}
	out := make(map[string]ddbtypes.AttributeValue, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func avEqual(a, b ddbtypes.AttributeValue) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	switch x := a.(type) {
	case *ddbtypes.AttributeValueMemberN:
		y, ok := b.(*ddbtypes.AttributeValueMemberN)
		return ok && x.Value == y.Value
	case *ddbtypes.AttributeValueMemberS:
		y, ok := b.(*ddbtypes.AttributeValueMemberS)
		return ok && x.Value == y.Value
	case *ddbtypes.AttributeValueMemberBOOL:
		y, ok := b.(*ddbtypes.AttributeValueMemberBOOL)
		return ok && x.Value == y.Value
	case *ddbtypes.AttributeValueMemberB:
		y, ok := b.(*ddbtypes.AttributeValueMemberB)
		return ok && bytes.Equal(x.Value, y.Value)
	}
	return false
}

// ddbTokens normalizes an expression to whitespace-delimited tokens, dropping
// parens and commas so the term/clause parsers stay simple.
func ddbTokens(s string) []string {
	return strings.Fields(strings.NewReplacer("\n", " ", ",", " ", "(", " ", ")", " ").Replace(s))
}

func evalCond(expr string, names map[string]string, vals map[string]ddbtypes.AttributeValue, item map[string]ddbtypes.AttributeValue) bool {
	if strings.TrimSpace(expr) == "" {
		return true
	}
	toks := ddbTokens(expr)
	result, op, first := false, "OR", true
	for i := 0; i < len(toks); {
		var term bool
		switch toks[i] {
		case "attribute_not_exists":
			term = item[names[toks[i+1]]] == nil
			i += 2
		case "attribute_exists":
			term = item[names[toks[i+1]]] != nil
			i += 2
		default: // #name = :val
			term = avEqual(item[names[toks[i]]], vals[toks[i+2]])
			i += 3
		}
		if first {
			result, first = term, false
		} else if op == "OR" {
			result = result || term
		} else {
			result = result && term
		}
		if i < len(toks) {
			op = toks[i]
			i++
		}
	}
	return result
}

func applyUpdate(item map[string]ddbtypes.AttributeValue, expr string, names map[string]string, vals map[string]ddbtypes.AttributeValue) {
	toks := ddbTokens(expr)
	sec := ""
	for i := 0; i < len(toks); {
		switch toks[i] {
		case "SET", "REMOVE", "ADD", "DELETE":
			sec = toks[i]
			i++
		default:
			switch sec {
			case "SET": // #name = :val
				item[names[toks[i]]] = vals[toks[i+2]]
				i += 3
			case "REMOVE":
				delete(item, names[toks[i]])
				i++
			default:
				i++
			}
		}
	}
}

func (f *fakeDDB) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &dynamodb.GetItemOutput{Item: cloneItem(f.items[compositeKey(in.Key)])}, nil
}

func (f *fakeDDB) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ck := compositeKey(in.Key)
	cond := ""
	if in.ConditionExpression != nil {
		cond = *in.ConditionExpression
	}
	if !evalCond(cond, in.ExpressionAttributeNames, in.ExpressionAttributeValues, f.items[ck]) {
		return nil, &ddbtypes.ConditionalCheckFailedException{Message: aws.String("conditional check failed")}
	}
	item := cloneItem(f.items[ck])
	if item == nil {
		item = cloneItem(in.Key) // upsert: seed with the key attributes
	}
	applyUpdate(item, *in.UpdateExpression, in.ExpressionAttributeNames, in.ExpressionAttributeValues)
	f.items[ck] = item
	return &dynamodb.UpdateItemOutput{}, nil
}

func (f *fakeDDB) TransactWriteItems(_ context.Context, in *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Pass 1: all conditions must hold against the pre-transaction state.
	for _, ti := range in.TransactItems {
		if ti.Update != nil && ti.Update.ConditionExpression != nil {
			if !evalCond(*ti.Update.ConditionExpression, ti.Update.ExpressionAttributeNames, ti.Update.ExpressionAttributeValues, f.items[compositeKey(ti.Update.Key)]) {
				return nil, &ddbtypes.TransactionCanceledException{Message: aws.String("ConditionalCheckFailed")}
			}
		}
	}
	// Pass 2: apply atomically.
	for _, ti := range in.TransactItems {
		switch {
		case ti.Put != nil:
			f.items[compositeKey(ti.Put.Item)] = cloneItem(ti.Put.Item)
		case ti.Update != nil:
			ck := compositeKey(ti.Update.Key)
			item := cloneItem(f.items[ck])
			if item == nil {
				item = cloneItem(ti.Update.Key)
			}
			applyUpdate(item, *ti.Update.UpdateExpression, ti.Update.ExpressionAttributeNames, ti.Update.ExpressionAttributeValues)
			f.items[ck] = item
		}
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func (f *fakeDDB) BatchWriteItem(_ context.Context, in *dynamodb.BatchWriteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, reqs := range in.RequestItems {
		for _, r := range reqs {
			switch {
			case r.PutRequest != nil:
				f.items[compositeKey(r.PutRequest.Item)] = cloneItem(r.PutRequest.Item)
			case r.DeleteRequest != nil:
				delete(f.items, compositeKey(r.DeleteRequest.Key))
			}
		}
	}
	return &dynamodb.BatchWriteItemOutput{}, nil
}

func (f *fakeDDB) BatchGetItem(_ context.Context, in *dynamodb.BatchGetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	resp := map[string][]map[string]ddbtypes.AttributeValue{}
	for table, ka := range in.RequestItems {
		for _, key := range ka.Keys {
			if item := f.items[compositeKey(key)]; item != nil {
				resp[table] = append(resp[table], cloneItem(item))
			}
		}
	}
	return &dynamodb.BatchGetItemOutput{Responses: resp}, nil
}

func (f *fakeDDB) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[compositeKey(in.Item)] = cloneItem(in.Item)
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDDB) DeleteItem(_ context.Context, in *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.items, compositeKey(in.Key))
	return &dynamodb.DeleteItemOutput{}, nil
}

func (f *fakeDDB) Query(_ context.Context, _ *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	return &dynamodb.QueryOutput{}, nil
}

// Scan returns every head item in one page. The only caller (VersionVector)
// filters on sk = HEAD, which we apply directly rather than parsing the filter.
func (f *fakeDDB) Scan(_ context.Context, _ *dynamodb.ScanInput, _ ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var items []map[string]ddbtypes.AttributeValue
	for _, it := range f.items {
		if ddbS(it[attrSortKey]) == kvHeadSK {
			items = append(items, cloneItem(it))
		}
	}
	return &dynamodb.ScanOutput{Items: items}, nil
}

// =============================================================================
// Engine tests (real KVStore against fakeDDB)
// =============================================================================

func newEngineKV(ddb DynamoDBAPI) *KVStore {
	return &KVStore{ddb: ddb, dek: make([]byte, 32), tableName: "t", maxValue: kvDefaultMaxValue}
}

// Exercises the real engine + fakeDDB so the type tag round-trips through the
// DynamoDB marshaling and version-CAS write, not just the in-memory fakeKV.
func TestKVEngine_AppendGetSetRename(t *testing.T) {
	kv := newEngineKV(newFakeDDB())
	ctx := context.Background()

	if n, err := kv.Append(ctx, "a", []byte("foo")); err != nil || n != 3 {
		t.Fatalf("Append new = %d, %v; want 3", n, err)
	}
	if n, err := kv.Append(ctx, "a", []byte("bar")); err != nil || n != 6 {
		t.Fatalf("Append = %d, %v; want 6", n, err)
	}
	if v, _, _ := kv.Get(ctx, "a"); string(v) != "foobar" {
		t.Fatalf("after Append = %q, want foobar", v)
	}

	old, existed, err := kv.GetSet(ctx, "a", []byte("new"))
	if err != nil || !existed || string(old) != "foobar" {
		t.Fatalf("GetSet = %q, %v, %v; want foobar/true", old, existed, err)
	}
	if _, existed, _ := kv.GetSet(ctx, "fresh", []byte("v")); existed {
		t.Fatalf("GetSet on absent key: existed should be false")
	}

	if err := kv.Rename(ctx, "a", "b"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, _, err := kv.Get(ctx, "a"); err != ErrKVNotFound {
		t.Fatalf("source after Rename = %v, want ErrKVNotFound", err)
	}
	if v, _, _ := kv.Get(ctx, "b"); string(v) != "new" {
		t.Fatalf("dest after Rename = %q, want new", v)
	}
	if err := kv.Rename(ctx, "missing", "x"); err != ErrKVNotFound {
		t.Fatalf("Rename missing = %v, want ErrKVNotFound", err)
	}
}

func TestKVEngine_TypedRoundTrip(t *testing.T) {
	kv := newEngineKV(newFakeDDB())
	ctx := context.Background()

	if _, err := kv.ModifyTyped(ctx, "h", typeHash, func(cur []byte) ([]byte, bool, error) {
		if cur != nil {
			t.Fatalf("first write: cur should be nil, got %q", cur)
		}
		return []byte("blob-v1"), false, nil
	}); err != nil {
		t.Fatalf("ModifyTyped: %v", err)
	}

	if typ, err := kv.TypeOf(ctx, "h"); err != nil || typ != typeHash {
		t.Fatalf("TypeOf = %q, %v; want hash", typ, err)
	}
	if b, ok, err := kv.ReadTyped(ctx, "h", typeHash); err != nil || !ok || string(b) != "blob-v1" {
		t.Fatalf("ReadTyped = %q, %v, %v", b, ok, err)
	}
	if _, _, err := kv.ReadTyped(ctx, "h", typeList); err != ErrWrongType {
		t.Fatalf("ReadTyped wrong type = %v, want ErrWrongType", err)
	}
	if _, _, err := kv.Get(ctx, "h"); err != ErrWrongType {
		t.Fatalf("GET on hash = %v, want ErrWrongType", err)
	}

	// del=true tombstones the key.
	if _, err := kv.ModifyTyped(ctx, "h", typeHash, func(cur []byte) ([]byte, bool, error) {
		return nil, true, nil
	}); err != nil {
		t.Fatalf("ModifyTyped delete: %v", err)
	}
	if typ, err := kv.TypeOf(ctx, "h"); err != nil || typ != "none" {
		t.Fatalf("TypeOf after delete = %q, %v; want none", typ, err)
	}
}

func TestKVEngine_SetGetVersions(t *testing.T) {
	kv := newEngineKV(newFakeDDB())
	ctx := context.Background()

	v1, ok, err := kv.SetMode(ctx, "k", []byte("v1"), 0, setAlways)
	if err != nil || !ok || v1 != 1 {
		t.Fatalf("set v1: ver=%d ok=%v err=%v", v1, ok, err)
	}
	got, ver, err := kv.Get(ctx, "k")
	if err != nil || string(got) != "v1" || ver != 1 {
		t.Fatalf("get: %q ver=%d err=%v", got, ver, err)
	}
	v2, _, _ := kv.SetMode(ctx, "k", []byte("v2"), 0, setAlways)
	if v2 <= v1 {
		t.Fatalf("version not monotonic: %d then %d", v1, v2)
	}
	got, _, _ = kv.Get(ctx, "k")
	if string(got) != "v2" {
		t.Fatalf("get after overwrite: %q", got)
	}
	if _, _, err := kv.Get(ctx, "missing"); !errors.Is(err, ErrKVNotFound) {
		t.Fatalf("get missing: %v", err)
	}
}

func TestKVEngine_NXXX(t *testing.T) {
	kv := newEngineKV(newFakeDDB())
	ctx := context.Background()

	if _, ok, _ := kv.SetMode(ctx, "k", []byte("a"), 0, setNX); !ok {
		t.Fatal("NX on absent should set")
	}
	if _, ok, _ := kv.SetMode(ctx, "k", []byte("b"), 0, setNX); ok {
		t.Fatal("NX on present should not set")
	}
	if g, _, _ := kv.Get(ctx, "k"); string(g) != "a" {
		t.Fatalf("value changed under failed NX: %q", g)
	}
	if _, ok, _ := kv.SetMode(ctx, "k", []byte("c"), 0, setXX); !ok {
		t.Fatal("XX on present should set")
	}
	if _, ok, _ := kv.SetMode(ctx, "new", []byte("x"), 0, setXX); ok {
		t.Fatal("XX on absent should not set")
	}
}

// The TOCTOU regression: many goroutines race SET NX on one absent key; exactly
// one must win. With the old check-then-write this could elect multiple winners.
func TestKVEngine_ConcurrentNXOneWinner(t *testing.T) {
	kv := newEngineKV(newFakeDDB())
	const n = 32
	var wins int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, ok, err := kv.SetMode(context.Background(), "lock", []byte(strconv.Itoa(i)), 0, setNX)
			if err != nil {
				t.Errorf("goroutine %d: %v", i, err)
				return
			}
			if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("SET NX winners = %d, want exactly 1", wins)
	}
}

// A delete must not reset the version: SET after DEL continues climbing, so a
// client's high-water mark can't be rewound by delete-then-recreate.
func TestKVEngine_DeleteTombstoneMonotonic(t *testing.T) {
	kv := newEngineKV(newFakeDDB())
	ctx := context.Background()

	v1, _, _ := kv.SetMode(ctx, "k", []byte("v"), 0, setAlways)
	existed, vdel, err := kv.Del(ctx, "k")
	if err != nil || !existed || vdel <= v1 {
		t.Fatalf("del: existed=%v ver=%d (prev %d) err=%v", existed, vdel, v1, err)
	}
	if _, _, err := kv.Get(ctx, "k"); !errors.Is(err, ErrKVNotFound) {
		t.Fatalf("get after del: %v", err)
	}
	v3, _, _ := kv.SetMode(ctx, "k", []byte("again"), 0, setAlways)
	if v3 <= vdel {
		t.Fatalf("version reset after delete/recreate: del=%d, recreate=%d", vdel, v3)
	}
}

func TestKVEngine_Incr(t *testing.T) {
	kv := newEngineKV(newFakeDDB())
	ctx := context.Background()

	for _, step := range []struct {
		delta int64
		want  int64
	}{{1, 1}, {5, 6}, {-2, 4}} {
		got, _, err := kv.Incr(ctx, "n", step.delta)
		if err != nil || got != step.want {
			t.Fatalf("incr %d: got %d err=%v, want %d", step.delta, got, err, step.want)
		}
	}
	kv.SetMode(ctx, "s", []byte("notanumber"), 0, setAlways)
	if _, _, err := kv.Incr(ctx, "s", 1); !errors.Is(err, ErrNotInteger) {
		t.Fatalf("incr non-integer: %v", err)
	}
}

// A value larger than one DynamoDB item must round-trip via the chunk path.
func TestKVEngine_ChunkingRoundTrip(t *testing.T) {
	kv := newEngineKV(newFakeDDB())
	ctx := context.Background()

	big := make([]byte, kvChunkSize*2+1234) // forces 3 chunks
	if _, err := rand.Read(big); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, ok, err := kv.SetMode(ctx, "blob", big, 0, setAlways); err != nil || !ok {
		t.Fatalf("set big: ok=%v err=%v", ok, err)
	}
	got, _, err := kv.Get(ctx, "blob")
	if err != nil {
		t.Fatalf("get big: %v", err)
	}
	if !bytes.Equal(got, big) {
		t.Fatalf("chunked round-trip mismatch: got %d bytes, want %d", len(got), len(big))
	}
}

// Concurrent unconditional SETs never corrupt: at least one wins and the final
// value is some writer's. Under heavy single-key contention a writer may exhaust
// the bounded retries (errConcurrentModification) — that's acceptable, not a
// failure; what must not happen is corruption or a non-CAS error.
func TestKVEngine_ConcurrentSetNoCorruption(t *testing.T) {
	kv := newEngineKV(newFakeDDB())
	const n = 16
	var won int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := kv.SetMode(context.Background(), "k", []byte(strconv.Itoa(i)), 0, setAlways)
			switch {
			case err == nil:
				mu.Lock()
				won++
				mu.Unlock()
			case errors.Is(err, errConcurrentModification): // bounded retries exhausted — fine
			default:
				t.Errorf("goroutine %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if won == 0 {
		t.Fatal("no concurrent SET succeeded")
	}
	got, _, err := kv.Get(context.Background(), "k")
	if err != nil {
		t.Fatalf("final get: %v", err)
	}
	if v, perr := strconv.Atoi(string(got)); perr != nil || v < 0 || v >= n {
		t.Fatalf("final value %q not one of the writers (corruption)", got)
	}
}
