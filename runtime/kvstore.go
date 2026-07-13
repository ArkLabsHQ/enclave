package runtime

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// DynamoDB KV: sealed values, version-CAS writes, S3 freshness anchors.

// ErrKVNotFound reports an absent or expired key.
var ErrKVNotFound = errors.New("kv: key not found")

// ErrKVDisabled indicates KV storage is unavailable.
var ErrKVDisabled = errors.New("kv: store not initialized (no table provisioned)")

// ErrValueTooLarge is returned when a value exceeds the configured maximum.
var ErrValueTooLarge = errors.New("kv: value exceeds maximum size")

// ErrNotInteger reports a non-base-10 integer value.
var ErrNotInteger = errors.New("value is not an integer or out of range")

// ErrWrongType reports Redis WRONGTYPE.
var ErrWrongType = errors.New("WRONGTYPE Operation against a key holding the wrong kind of value")

// errConcurrentModification: a write lost the version CAS; callers re-read and retry.
var errConcurrentModification = errors.New("concurrent modification")

type setMode int

const (
	setAlways setMode = iota // Redis SET
	setNX                    // only if absent
	setXX                    // only if present
)

const kvMaxWriteRetries = 5

// DynamoDB attribute names; the dynamodbav struct tags must be kept in sync.
const (
	attrPartitionKey = "pk"
	attrSortKey      = "sk"
	attrVersion      = "ver"
	attrType         = "t"
	attrChunks       = "chunks"
	attrBlob         = "blob"
	attrNBytes       = "nbytes"
	attrExpires      = "expires"
	attrDeleted      = "del"
)

// Value types stored in the head's `t` attribute; "" means string.
const (
	typeHash   = "hash"
	typeList   = "list"
	typeSet    = "set"
	typeZSet   = "zset"
	typeStream = "stream"
)

const (
	kvHeadSK = "HEAD"

	// kvChunkSize is the plaintext bytes per chunk, sized under DynamoDB's 400 KB item limit.
	kvChunkSize = 300 * 1024

	// kvTransactItemMax/kvTransactByteMax bound one TransactWriteItems commit; above either, fall back to write-then-flip.
	kvTransactItemMax = 100
	kvTransactByteMax = 3_500_000

	// kvDefaultMaxValue caps a single value; overridable via ENCLAVE_KV_MAX_VALUE_BYTES.
	kvDefaultMaxValue = 64 * 1024 * 1024
)

// kvHeadItem is the head row: per-key metadata and (for small values) inline ciphertext.
type kvHeadItem struct {
	PartitionKey string `dynamodbav:"pk"`
	SortKey      string `dynamodbav:"sk"`
	Version      uint64 `dynamodbav:"ver"`
	Type         string `dynamodbav:"t,omitempty"` // "" = string; else hash/list/set/zset/stream
	Chunks       int    `dynamodbav:"chunks"`
	Blob         []byte `dynamodbav:"blob,omitempty"` // inline envelope when Chunks == 0
	NBytes       int64  `dynamodbav:"nbytes"`
	Expires      int64  `dynamodbav:"expires,omitempty"` // epoch seconds; 0/absent = no expiry
	Deleted      bool   `dynamodbav:"del,omitempty"`     // tombstone: key removed but version preserved
}

// kvChunkItem is one chunk row of a large value.
type kvChunkItem struct {
	PartitionKey string `dynamodbav:"pk"`
	SortKey      string `dynamodbav:"sk"`
	Blob         []byte `dynamodbav:"blob"`
}

// kvKey is a DynamoDB primary key.
type kvKey struct {
	PartitionKey string `dynamodbav:"pk"`
	SortKey      string `dynamodbav:"sk"`
}

// kvHead is the decoded head with an existence flag.
type kvHead struct {
	kvHeadItem
	exists bool
}

func (h kvHead) expired() bool {
	return h.Expires > 0 && time.Now().Unix() >= h.Expires
}

// gone reports no live value (absent, tombstoned, or expired); version is still carried forward.
func (h kvHead) gone() bool {
	return !h.exists || h.Deleted || h.expired()
}

// kvStore owns the DEK and DynamoDB engine.
type kvStore struct {
	ddb       DynamoDBAPI
	dek       DEK
	anchor    FreshnessAnchor
	tableName string
	maxValue  int
}

// KVKeyInfo is one live key and its Redis type.
type KVKeyInfo struct {
	Key  string
	Type string // "string"/"hash"/...
}

type KVStore interface {
	ScanKeys(ctx context.Context, cursor string, count int) ([]KVKeyInfo, string, error)
	SetMode(
		ctx context.Context,
		key string,
		value []byte,
		ttlSeconds int64,
		mode setMode,
	) (uint64, bool, error)
	Get(ctx context.Context, key string) ([]byte, uint64, error)
	Exists(ctx context.Context, key string) (bool, error)
	Del(ctx context.Context, key string) (bool, uint64, error)
	TTL(ctx context.Context, key string) (int64, error)
	Expire(ctx context.Context, key string, ttlSeconds int64) (bool, uint64, error)
	Persist(ctx context.Context, key string) (bool, error)
	Version(ctx context.Context, key string) (uint64, error)
	Incr(ctx context.Context, key string, delta int64) (int64, uint64, error)
	Append(ctx context.Context, key string, suffix []byte) (int, error)
	GetSet(ctx context.Context, key string, value []byte) (old []byte, existed bool, err error)
	Rename(ctx context.Context, src, dst string) error
	TypeOf(ctx context.Context, key string) (string, error)
	ReadTyped(ctx context.Context, key, kvType string) (value []byte, exists bool, err error)
	ModifyTyped(
		ctx context.Context,
		key, kvType string,
		fn func(cur []byte) (next []byte, del bool, err error),
	) (uint64, error)
}

func NewKVStore(
	ctx context.Context,
	ddb DynamoDBAPI,
	ssm SSM,
	dek DEK,
	anchor FreshnessAnchor,
) (KVStore, error) {
	tableName, err := ssm.MustGet(ctx, kvTableNameParam())
	if err != nil {
		return nil, fmt.Errorf("read KV table name: %w", err)
	}

	expr, err := expression.NewBuilder().
		WithFilter(expression.Name(attrSortKey).Equal(expression.Value(kvHeadSK))).
		Build()
	if err != nil {
		return nil, err
	}

	prefix := fmt.Sprintf("%s/%s/", getDeployment(), getAppName())

	live := map[string]uint64{}
	var startKey map[string]ddbtypes.AttributeValue
	for {
		res, err := ddb.Scan(ctx, &dynamodb.ScanInput{
			TableName:                 &tableName,
			FilterExpression:          expr.Filter(),
			ExpressionAttributeNames:  expr.Names(),
			ExpressionAttributeValues: expr.Values(),
			ExclusiveStartKey:         startKey,
		})
		if err != nil {
			return nil, fmt.Errorf("kv version vector scan: %w", err)
		}
		for _, raw := range res.Items {
			var item kvHeadItem
			if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
				return nil, fmt.Errorf("kv version vector decode: %w", err)
			}
			live[strings.TrimPrefix(item.PartitionKey, prefix)] = item.Version
		}
		if len(res.LastEvaluatedKey) == 0 {
			break
		}
		startKey = res.LastEvaluatedKey
	}

	if err := anchor.Establish(ctx, live); err != nil {
		return nil, fmt.Errorf("kv version vector decode: %w", err)
	}

	return &kvStore{
		ddb:       ddb,
		dek:       dek,
		anchor:    anchor,
		tableName: tableName,
		maxValue:  kvMaxValue(),
	}, nil
}

// ScanKeys returns one page of live keys after cursor plus the next cursor ("0" when complete); backs SCAN.
func (kv *kvStore) ScanKeys(
	ctx context.Context,
	cursor string,
	count int,
) ([]KVKeyInfo, string, error) {
	start, err := decodeScanCursor(cursor)
	if err != nil {
		return nil, "0", err
	}
	expr, err := expression.NewBuilder().
		WithFilter(expression.Name(attrSortKey).Equal(expression.Value(kvHeadSK))).
		Build()
	if err != nil {
		return nil, "0", err
	}
	if count <= 0 {
		count = 10
	}
	res, err := kv.ddb.Scan(ctx, &dynamodb.ScanInput{
		TableName:                 &kv.tableName,
		FilterExpression:          expr.Filter(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		ExclusiveStartKey:         start,
		Limit:                     aws.Int32(int32(count)),
	})
	if err != nil {
		return nil, "0", fmt.Errorf("kv scan: %w", err)
	}
	prefix := fmt.Sprintf("%s/%s/", getDeployment(), getAppName())
	var keys []KVKeyInfo
	for _, raw := range res.Items {
		var item kvHeadItem
		if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
			return nil, "0", fmt.Errorf("kv scan decode: %w", err)
		}
		if (kvHead{kvHeadItem: item, exists: true}).gone() {
			continue
		}
		t := item.Type
		if t == "" {
			t = "string"
		}
		keys = append(keys, KVKeyInfo{Key: strings.TrimPrefix(item.PartitionKey, prefix), Type: t})
	}
	next, err := encodeScanCursor(res.LastEvaluatedKey)
	if err != nil {
		return nil, "0", err
	}
	return keys, next, nil
}

// SetMode enforces NX/XX atomically with the version-CAS write.
func (kv *kvStore) SetMode(
	ctx context.Context,
	key string,
	value []byte,
	ttlSeconds int64,
	mode setMode,
) (uint64, bool, error) {
	if len(value) > kv.maxValue {
		return 0, false, ErrValueTooLarge
	}
	var expires int64
	if ttlSeconds > 0 {
		expires = time.Now().Unix() + ttlSeconds
	}
	for attempt := 0; attempt <= kvMaxWriteRetries; attempt++ {
		h, err := kv.readHead(ctx, key)
		if err != nil {
			return 0, false, err
		}
		switch {
		case mode == setNX && !h.gone():
			return 0, false, nil
		case mode == setXX && h.gone():
			return 0, false, nil
		}
		v, err := kv.write(ctx, key, value, "", h, expires)
		if err == nil {
			return v, true, nil
		}
		if errors.Is(err, errConcurrentModification) {
			continue
		}
		return 0, false, err
	}
	return 0, false, errConcurrentModification
}

// Get returns the value and its version, or ErrKVNotFound if absent/deleted/expired.
func (kv *kvStore) Get(ctx context.Context, key string) ([]byte, uint64, error) {
	h, err := kv.readHead(ctx, key)
	if err != nil {
		return nil, 0, err
	}
	if h.gone() {
		return nil, 0, ErrKVNotFound
	}
	if h.Type != "" {
		return nil, 0, ErrWrongType
	}
	val, err := kv.readValue(ctx, key, h)
	if err != nil {
		return nil, 0, err
	}
	return val, h.Version, nil
}

// Exists reports whether key is present (not absent/deleted/expired).
func (kv *kvStore) Exists(ctx context.Context, key string) (bool, error) {
	h, err := kv.readHead(ctx, key)
	if err != nil {
		return false, err
	}
	return !h.gone(), nil
}

// Del tombstones key (bumps version, marks deleted, reclaims chunks) so the version stays monotonic across delete/recreate.
func (kv *kvStore) Del(ctx context.Context, key string) (bool, uint64, error) {
	for attempt := 0; attempt <= kvMaxWriteRetries; attempt++ {
		h, err := kv.readHead(ctx, key)
		if err != nil {
			return false, 0, err
		}
		if h.gone() {
			return false, h.Version, nil
		}
		next, err := kv.writeTombstone(ctx, key, h)
		if err == nil {
			return true, next, nil
		}
		if errors.Is(err, errConcurrentModification) {
			continue
		}
		return false, 0, err
	}
	return false, 0, errConcurrentModification
}

// TTL returns remaining seconds (>=0), -1 if no expiry, -2 if absent (Redis TTL semantics).
func (kv *kvStore) TTL(ctx context.Context, key string) (int64, error) {
	h, err := kv.readHead(ctx, key)
	if err != nil {
		return -2, err
	}
	if h.gone() {
		return -2, nil
	}
	if h.Expires == 0 {
		return -1, nil
	}
	return h.Expires - time.Now().Unix(), nil
}

// Expire sets a TTL on an existing key without rewriting its value, returning whether it existed and the unchanged version.
func (kv *kvStore) Expire(ctx context.Context, key string, ttlSeconds int64) (bool, uint64, error) {
	for attempt := 0; attempt <= kvMaxWriteRetries; attempt++ {
		h, err := kv.readHead(ctx, key)
		if err != nil {
			return false, 0, err
		}
		if h.gone() {
			return false, h.Version, nil
		}
		upd := expression.Set(
			expression.Name(attrExpires),
			expression.Value(time.Now().Unix()+ttlSeconds),
		)
		cond := expression.Name(attrVersion).Equal(expression.Value(h.Version))
		expr, err := expression.NewBuilder().WithUpdate(upd).WithCondition(cond).Build()
		if err != nil {
			return false, 0, err
		}
		k, err := marshalKey(getPartitionKey(key), kvHeadSK)
		if err != nil {
			return false, 0, err
		}
		_, err = kv.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:                 &kv.tableName,
			Key:                       k,
			UpdateExpression:          expr.Update(),
			ConditionExpression:       expr.Condition(),
			ExpressionAttributeNames:  expr.Names(),
			ExpressionAttributeValues: expr.Values(),
		})
		if err == nil {
			return true, h.Version, nil
		}
		if isConditionalCheckFailed(err) {
			continue
		}
		return false, 0, fmt.Errorf("kv expire %q: %w", key, err)
	}
	return false, 0, errConcurrentModification
}

// Persist removes the TTL from key; true if one was removed, false if none or gone (Redis PERSIST).
func (kv *kvStore) Persist(ctx context.Context, key string) (bool, error) {
	for attempt := 0; attempt <= kvMaxWriteRetries; attempt++ {
		h, err := kv.readHead(ctx, key)
		if err != nil {
			return false, err
		}
		if h.gone() || h.Expires == 0 {
			return false, nil
		}
		upd := expression.Remove(expression.Name(attrExpires))
		cond := expression.Name(attrVersion).Equal(expression.Value(h.Version))
		expr, err := expression.NewBuilder().WithUpdate(upd).WithCondition(cond).Build()
		if err != nil {
			return false, err
		}
		k, err := marshalKey(getPartitionKey(key), kvHeadSK)
		if err != nil {
			return false, err
		}
		_, err = kv.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:                 &kv.tableName,
			Key:                       k,
			UpdateExpression:          expr.Update(),
			ConditionExpression:       expr.Condition(),
			ExpressionAttributeNames:  expr.Names(),
			ExpressionAttributeValues: expr.Values(),
		})
		if err == nil {
			return true, nil
		}
		if isConditionalCheckFailed(err) {
			continue
		}
		return false, fmt.Errorf("kv persist %q: %w", key, err)
	}
	return false, errConcurrentModification
}

// Version returns the current head version of key (0 if no head); WATCH compares this to detect modification.
func (kv *kvStore) Version(ctx context.Context, key string) (uint64, error) {
	h, err := kv.readHead(ctx, key)
	if err != nil {
		return 0, err
	}
	if !h.exists {
		return 0, nil
	}
	return h.Version, nil
}

// Incr adds delta; missing/expired starts at 0; live TTL stays.
func (kv *kvStore) Incr(ctx context.Context, key string, delta int64) (int64, uint64, error) {
	for attempt := 0; attempt <= kvMaxWriteRetries; attempt++ {
		h, err := kv.readHead(ctx, key)
		if err != nil {
			return 0, 0, err
		}
		var cur int64
		if !h.gone() {
			if h.Type != "" {
				return 0, 0, ErrWrongType
			}
			val, err := kv.readValue(ctx, key, h)
			if err != nil {
				return 0, 0, err
			}
			cur, err = strconv.ParseInt(string(val), 10, 64)
			if err != nil {
				return 0, 0, ErrNotInteger
			}
		}
		next := cur + delta
		expires := h.Expires
		if h.gone() {
			expires = 0
		}
		version, err := kv.write(ctx, key, []byte(strconv.FormatInt(next, 10)), "", h, expires)
		if err == nil {
			return next, version, nil
		}
		if errors.Is(err, errConcurrentModification) {
			continue
		}
		return 0, 0, err
	}
	return 0, 0, errConcurrentModification
}

// Append concatenates suffix to the string at key (creating it if absent), preserving any TTL.
func (kv *kvStore) Append(ctx context.Context, key string, suffix []byte) (int, error) {
	for attempt := 0; attempt <= kvMaxWriteRetries; attempt++ {
		h, err := kv.readHead(ctx, key)
		if err != nil {
			return 0, err
		}
		var cur []byte
		expires := int64(0)
		if !h.gone() {
			if h.Type != "" {
				return 0, ErrWrongType
			}
			if cur, err = kv.readValue(ctx, key, h); err != nil {
				return 0, err
			}
			expires = h.Expires
		}
		next := append(append([]byte(nil), cur...), suffix...)
		if _, err := kv.write(ctx, key, next, "", h, expires); err == nil {
			return len(next), nil
		} else if errors.Is(err, errConcurrentModification) {
			continue
		} else {
			return 0, err
		}
	}
	return 0, errConcurrentModification
}

// GetSet sets key to value (clearing any TTL, like SET) and returns the old string value.
func (kv *kvStore) GetSet(
	ctx context.Context,
	key string,
	value []byte,
) (old []byte, existed bool, err error) {
	for attempt := 0; attempt <= kvMaxWriteRetries; attempt++ {
		h, err := kv.readHead(ctx, key)
		if err != nil {
			return nil, false, err
		}
		old, existed = nil, false
		if !h.gone() {
			if h.Type != "" {
				return nil, false, ErrWrongType
			}
			if old, err = kv.readValue(ctx, key, h); err != nil {
				return nil, false, err
			}
			existed = true
		}
		if _, err := kv.write(ctx, key, value, "", h, 0); err == nil {
			return old, existed, nil
		} else if errors.Is(err, errConcurrentModification) {
			continue
		} else {
			return nil, false, err
		}
	}
	return nil, false, errConcurrentModification
}

// Rename moves the value (any type, preserving TTL) from src to dst and tombstones src; not atomic across the two keys.
func (kv *kvStore) Rename(ctx context.Context, src, dst string) error {
	h, err := kv.readHead(ctx, src)
	if err != nil {
		return err
	}
	if h.gone() {
		return ErrKVNotFound
	}
	val, err := kv.readValue(ctx, src, h)
	if err != nil {
		return err
	}
	dstHead, err := kv.readHead(ctx, dst)
	if err != nil {
		return err
	}
	if _, err := kv.write(ctx, dst, val, h.Type, dstHead, h.Expires); err != nil {
		return err
	}
	_, err = kv.writeTombstone(ctx, src, h)
	return err
}

// Typed values are one sealed, type-tagged blob per key.

// TypeOf returns the Redis type name of key: "none", "string", or the collection type.
func (kv *kvStore) TypeOf(ctx context.Context, key string) (string, error) {
	h, err := kv.readHead(ctx, key)
	if err != nil {
		return "", err
	}
	if h.gone() {
		return "none", nil
	}
	if h.Type == "" {
		return "string", nil
	}
	return h.Type, nil
}

// ReadTyped returns the decrypted value bytes for key, requiring type kvType (ErrWrongType otherwise).
func (kv *kvStore) ReadTyped(
	ctx context.Context,
	key, kvType string,
) (value []byte, exists bool, err error) {
	h, err := kv.readHead(ctx, key)
	if err != nil {
		return nil, false, err
	}
	if h.gone() {
		return nil, false, nil
	}
	if h.Type != kvType {
		return nil, false, ErrWrongType
	}
	val, err := kv.readValue(ctx, key, h)
	if err != nil {
		return nil, false, err
	}
	return val, true, nil
}

// ModifyTyped runs a version-CAS read-modify-write on a typed value; a lost CAS re-runs fn, so fn must be idempotent.
func (kv *kvStore) ModifyTyped(
	ctx context.Context,
	key, kvType string,
	fn func(cur []byte) (next []byte, del bool, err error),
) (uint64, error) {
	for attempt := 0; attempt <= kvMaxWriteRetries; attempt++ {
		h, err := kv.readHead(ctx, key)
		if err != nil {
			return 0, err
		}
		var cur []byte
		if !h.gone() {
			if h.Type != kvType {
				return 0, ErrWrongType
			}
			if cur, err = kv.readValue(ctx, key, h); err != nil {
				return 0, err
			}
		}
		next, del, err := fn(cur)
		if err != nil {
			return 0, err
		}
		if del {
			if h.gone() {
				return h.Version, nil
			}
			v, err := kv.writeTombstone(ctx, key, h)
			if err == nil {
				return v, nil
			}
			if errors.Is(err, errConcurrentModification) {
				continue
			}
			return 0, err
		}
		expires := h.Expires
		if h.gone() {
			expires = 0
		}
		v, err := kv.write(ctx, key, next, kvType, h, expires)
		if err == nil {
			return v, nil
		}
		if errors.Is(err, errConcurrentModification) {
			continue
		}
		return 0, err
	}
	return 0, errConcurrentModification
}

// readHead fetches a key's head item with a strongly-consistent read.
func (kv *kvStore) readHead(ctx context.Context, key string) (kvHead, error) {
	k, err := marshalKey(getPartitionKey(key), kvHeadSK)
	if err != nil {
		return kvHead{}, err
	}
	out, err := kv.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      &kv.tableName,
		Key:            k,
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return kvHead{}, fmt.Errorf("dynamodb get head %q: %w", key, err)
	}
	if out.Item == nil {
		return kvHead{}, nil
	}
	var item kvHeadItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return kvHead{}, fmt.Errorf("decode head %q: %w", key, err)
	}
	if err := kv.anchor.CheckFresh(key, item.Version); err != nil {
		return kvHead{}, err
	}
	return kvHead{kvHeadItem: item, exists: true}, nil
}

func (kv *kvStore) write(
	ctx context.Context,
	key string,
	value []byte,
	kvType string,
	cur kvHead,
	expires int64,
) (uint64, error) {
	next := cur.Version + 1
	var version uint64
	var err error
	if len(value) <= kvChunkSize {
		version, err = kv.writeSmall(ctx, key, value, kvType, cur, next, expires)
	} else {
		version, err = kv.writeChunked(ctx, key, value, kvType, cur, next, expires)
	}
	if err != nil {
		return 0, err
	}
	// Anchor after the DynamoDB commit so anchored ≤ live; a failure here leaves the write committed but unanchored.
	if err := kv.anchor.Record(ctx, key, version); err != nil {
		return 0, fmt.Errorf("kv set %q: anchor: %w", key, err)
	}
	return version, nil
}

func (kv *kvStore) writeSmall(
	ctx context.Context,
	key string,
	value []byte,
	kvType string,
	cur kvHead,
	next uint64,
	expires int64,
) (uint64, error) {
	blob, err := kv.dek.Seal(value, getAAD(key, next, 0, 0))
	if err != nil {
		return 0, err
	}
	upd := expression.
		Set(expression.Name(attrVersion), expression.Value(next)).
		Set(expression.Name(attrBlob), expression.Value(blob)).
		Set(expression.Name(attrChunks), expression.Value(0)).
		Set(expression.Name(attrNBytes), expression.Value(len(value))).
		Remove(expression.Name(attrDeleted)) // clear tombstone
	upd = setType(upd, kvType)
	upd = setExpires(upd, expires)
	expr, err := expression.NewBuilder().
		WithUpdate(upd).
		WithCondition(versionCAS(cur.Version)).
		Build()
	if err != nil {
		return 0, err
	}
	k, err := marshalKey(getPartitionKey(key), kvHeadSK)
	if err != nil {
		return 0, err
	}
	if _, err := kv.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &kv.tableName,
		Key:                       k,
		UpdateExpression:          expr.Update(),
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}); err != nil {
		if isConditionalCheckFailed(err) {
			return 0, fmt.Errorf("kv set %q: %w", key, errConcurrentModification)
		}
		return 0, fmt.Errorf("kv set %q: %w", key, err)
	}
	// A previous chunked version's chunk items are now orphaned — reclaim them.
	if cur.Chunks > 0 {
		kv.gcChunks(ctx, key, cur.Version, cur.Chunks)
	}
	return next, nil
}

func (kv *kvStore) writeChunked(
	ctx context.Context,
	key string,
	value []byte,
	kvType string,
	cur kvHead,
	next uint64,
	expires int64,
) (uint64, error) {
	chunks := splitChunks(value, kvChunkSize)
	chunkItems := make([]map[string]ddbtypes.AttributeValue, len(chunks))
	total := 0
	for i, c := range chunks {
		b, err := kv.dek.Seal(c, getAAD(key, next, i, len(chunks)))
		if err != nil {
			return 0, err
		}
		item, err := attributevalue.MarshalMap(
			kvChunkItem{
				PartitionKey: getPartitionKey(key),
				SortKey:      getChunkSortKey(next, i),
				Blob:         b,
			},
		)
		if err != nil {
			return 0, err
		}
		chunkItems[i] = item
		total += len(b)
	}

	upd := expression.
		Set(expression.Name(attrVersion), expression.Value(next)).
		Set(expression.Name(attrChunks), expression.Value(len(chunks))).
		Set(expression.Name(attrNBytes), expression.Value(len(value))).
		Remove(expression.Name(attrBlob)).
		Remove(expression.Name(attrDeleted)) // clear tombstone
	upd = setType(upd, kvType)
	upd = setExpires(upd, expires)
	expr, err := expression.NewBuilder().
		WithUpdate(upd).
		WithCondition(versionCAS(cur.Version)).
		Build()
	if err != nil {
		return 0, err
	}
	headKey, err := marshalKey(getPartitionKey(key), kvHeadSK)
	if err != nil {
		return 0, err
	}
	headUpdate := &ddbtypes.Update{
		TableName:                 &kv.tableName,
		Key:                       headKey,
		UpdateExpression:          expr.Update(),
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}

	if len(chunkItems)+1 <= kvTransactItemMax && total <= kvTransactByteMax {
		// One atomic transaction: chunks + head flip commit together.
		items := make([]ddbtypes.TransactWriteItem, 0, len(chunkItems)+1)
		for _, item := range chunkItems {
			items = append(
				items,
				ddbtypes.TransactWriteItem{
					Put: &ddbtypes.Put{TableName: &kv.tableName, Item: item},
				},
			)
		}
		items = append(items, ddbtypes.TransactWriteItem{Update: headUpdate})
		if _, err := kv.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
			if isTransactionCanceled(err) || isConditionalCheckFailed(err) {
				return 0, fmt.Errorf("kv set %q: %w", key, errConcurrentModification)
			}
			return 0, fmt.Errorf("kv set %q (transact): %w", key, err)
		}
	} else {
		// Too big for one transaction: write chunks first, then the conditional head flip is the commit point.
		if err := kv.putChunks(ctx, chunkItems); err != nil {
			return 0, fmt.Errorf("kv set %q (chunks): %w", key, err)
		}
		if _, err := kv.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:                 headUpdate.TableName,
			Key:                       headUpdate.Key,
			UpdateExpression:          headUpdate.UpdateExpression,
			ConditionExpression:       headUpdate.ConditionExpression,
			ExpressionAttributeNames:  headUpdate.ExpressionAttributeNames,
			ExpressionAttributeValues: headUpdate.ExpressionAttributeValues,
		}); err != nil {
			if isConditionalCheckFailed(err) {
				return 0, fmt.Errorf("kv set %q: %w", key, errConcurrentModification)
			}
			return 0, fmt.Errorf("kv set %q (commit): %w", key, err)
		}
	}

	if cur.Chunks > 0 {
		kv.gcChunks(ctx, key, cur.Version, cur.Chunks)
	}
	return next, nil
}

// readValue decrypts the value for a head, reassembling chunks when needed.
func (kv *kvStore) readValue(ctx context.Context, key string, h kvHead) ([]byte, error) {
	if h.Chunks == 0 {
		pt, err := kv.dek.Open(h.Blob, getAAD(key, h.Version, 0, 0))
		if err != nil {
			return nil, fmt.Errorf("kv get %q: %w", key, err)
		}
		return pt, nil
	}
	chunks, err := kv.getChunks(ctx, key, h.Version, h.Chunks)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, h.NBytes)
	for i, blob := range chunks {
		pt, err := kv.dek.Open(blob, getAAD(key, h.Version, i, h.Chunks))
		if err != nil {
			return nil, fmt.Errorf("kv get %q chunk %d: %w", key, i, err)
		}
		out = append(out, pt...)
	}
	if int64(len(out)) != h.NBytes {
		return nil, fmt.Errorf(
			"kv get %q: reassembled size %d != recorded %d",
			key,
			len(out),
			h.NBytes,
		)
	}
	return out, nil
}

func (kv *kvStore) putChunks(
	ctx context.Context,
	items []map[string]ddbtypes.AttributeValue,
) error {
	const batch = 25 // DynamoDB BatchWriteItem limit
	for start := 0; start < len(items); start += batch {
		end := min(start+batch, len(items))
		reqs := make([]ddbtypes.WriteRequest, 0, end-start)
		for _, item := range items[start:end] {
			reqs = append(reqs, ddbtypes.WriteRequest{PutRequest: &ddbtypes.PutRequest{Item: item}})
		}
		if err := kv.batchWrite(ctx, reqs); err != nil {
			return err
		}
	}
	return nil
}

// batchWrite issues a BatchWriteItem and retries any UnprocessedItems.
func (kv *kvStore) batchWrite(ctx context.Context, reqs []ddbtypes.WriteRequest) error {
	pending := map[string][]ddbtypes.WriteRequest{kv.tableName: reqs}
	for attempt := 0; attempt < 5 && len(pending) > 0; attempt++ {
		out, err := kv.ddb.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{RequestItems: pending})
		if err != nil {
			return err
		}
		pending = out.UnprocessedItems
		if len(pending) > 0 {
			time.Sleep(time.Duration(1<<attempt) * 50 * time.Millisecond)
		}
	}
	if len(pending) > 0 {
		return fmt.Errorf("dynamodb batch write: unprocessed items remain")
	}
	return nil
}

func (kv *kvStore) getChunks(
	ctx context.Context,
	key string,
	version uint64,
	count int,
) ([][]byte, error) {
	out := make([][]byte, count)
	const batch = 100 // BatchGetItem limit
	for start := 0; start < count; start += batch {
		end := min(start+batch, count)
		keys := make([]map[string]ddbtypes.AttributeValue, 0, end-start)
		for i := start; i < end; i++ {
			k, err := marshalKey(getPartitionKey(key), getChunkSortKey(version, i))
			if err != nil {
				return nil, err
			}
			keys = append(keys, k)
		}
		got, err := kv.batchGet(ctx, keys)
		if err != nil {
			return nil, err
		}
		for _, raw := range got {
			var ci kvChunkItem
			if err := attributevalue.UnmarshalMap(raw, &ci); err != nil {
				return nil, fmt.Errorf("kv get %q: decode chunk: %w", key, err)
			}
			idx, err := strconv.Atoi(strings.TrimPrefix(ci.SortKey, fmt.Sprintf("v%d#c", version)))
			if err != nil || idx < 0 || idx >= count {
				return nil, fmt.Errorf("kv get %q: bad chunk sk %q", key, ci.SortKey)
			}
			out[idx] = ci.Blob
		}
	}
	for i, b := range out {
		if b == nil {
			return nil, fmt.Errorf("kv get %q: missing chunk %d/%d", key, i, count)
		}
	}
	return out, nil
}

// batchGet issues a BatchGetItem (consistent) and retries UnprocessedKeys.
func (kv *kvStore) batchGet(
	ctx context.Context,
	keys []map[string]ddbtypes.AttributeValue,
) ([]map[string]ddbtypes.AttributeValue, error) {
	var items []map[string]ddbtypes.AttributeValue
	pending := map[string]ddbtypes.KeysAndAttributes{
		kv.tableName: {Keys: keys, ConsistentRead: aws.Bool(true)},
	}
	for attempt := 0; attempt < 5 && len(pending) > 0; attempt++ {
		out, err := kv.ddb.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{RequestItems: pending})
		if err != nil {
			return nil, err
		}
		items = append(items, out.Responses[kv.tableName]...)
		pending = out.UnprocessedKeys
		if len(pending) > 0 {
			time.Sleep(time.Duration(1<<attempt) * 50 * time.Millisecond)
		}
	}
	if len(pending) > 0 {
		return nil, fmt.Errorf("dynamodb batch get: unprocessed keys remain")
	}
	return items, nil
}

// writeTombstone marks key deleted at the next version; the head stays so the version counter is monotonic across delete/recreate.
func (kv *kvStore) writeTombstone(ctx context.Context, key string, cur kvHead) (uint64, error) {
	next := cur.Version + 1
	upd := expression.
		Set(expression.Name(attrVersion), expression.Value(next)).
		Set(expression.Name(attrDeleted), expression.Value(true)).
		Set(expression.Name(attrChunks), expression.Value(0)).
		Remove(expression.Name(attrBlob)).
		Remove(expression.Name(attrNBytes)).
		Remove(expression.Name(attrExpires))
	expr, err := expression.NewBuilder().
		WithUpdate(upd).
		WithCondition(versionCAS(cur.Version)).
		Build()
	if err != nil {
		return 0, err
	}
	k, err := marshalKey(getPartitionKey(key), kvHeadSK)
	if err != nil {
		return 0, err
	}
	if _, err := kv.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &kv.tableName,
		Key:                       k,
		UpdateExpression:          expr.Update(),
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}); err != nil {
		if isConditionalCheckFailed(err) {
			return 0, fmt.Errorf("kv del %q: %w", key, errConcurrentModification)
		}
		return 0, fmt.Errorf("kv del %q: %w", key, err)
	}
	if cur.Chunks > 0 {
		kv.gcChunks(ctx, key, cur.Version, cur.Chunks)
	}
	if err := kv.anchor.Record(ctx, key, next); err != nil {
		return 0, fmt.Errorf("kv del %q: anchor: %w", key, err)
	}
	return next, nil
}

// gcChunks best-effort deletes a stale version's chunk items.
func (kv *kvStore) gcChunks(ctx context.Context, key string, version uint64, count int) {
	const batch = 25
	for start := 0; start < count; start += batch {
		end := min(start+batch, count)
		reqs := make([]ddbtypes.WriteRequest, 0, end-start)
		for i := start; i < end; i++ {
			k, err := marshalKey(getPartitionKey(key), getChunkSortKey(version, i))
			if err != nil {
				continue
			}
			reqs = append(
				reqs,
				ddbtypes.WriteRequest{DeleteRequest: &ddbtypes.DeleteRequest{Key: k}},
			)
		}
		_ = kv.batchWrite(ctx, reqs) // best-effort; ignore cleanup failure
	}
}

// encodeScanCursor packs a LastEvaluatedKey into an opaque cursor ("0" when exhausted).
func encodeScanCursor(lek map[string]ddbtypes.AttributeValue) (string, error) {
	if len(lek) == 0 {
		return "0", nil
	}
	var k kvKey
	if err := attributevalue.UnmarshalMap(lek, &k); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString([]byte(k.PartitionKey + "\x00" + k.SortKey)), nil
}

func decodeScanCursor(cursor string) (map[string]ddbtypes.AttributeValue, error) {
	if cursor == "" || cursor == "0" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor")
	}
	partitionKey, sortKey, ok := strings.Cut(string(raw), "\x00")
	if !ok {
		return nil, fmt.Errorf("invalid cursor")
	}
	return marshalKey(partitionKey, sortKey)
}

func kvMaxValue() int {
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("ENCLAVE_KV_MAX_VALUE_BYTES"))); err == nil &&
		n > 0 {
		return n
	}
	return kvDefaultMaxValue
}

// kvTableNameParam returns the SSM table-name parameter.
func kvTableNameParam() string {
	return fmt.Sprintf("/%s/%s/KVTableName", getDeployment(), getAppName())
}

// getAAD binds chunks to deployment/app/key/version/index/count.
func getAAD(key string, version uint64, chunkIndex, chunkCount int) []byte {
	return fmt.Appendf(nil, "%s/%s/kv/%s/v%d/c%d/%d",
		getDeployment(), getAppName(), key, version, chunkIndex, chunkCount)
}

func getPartitionKey(key string) string {
	return fmt.Sprintf("%s/%s/%s", getDeployment(), getAppName(), key)
}

func getChunkSortKey(version uint64, i int) string {
	return fmt.Sprintf("v%d#c%d", version, i)
}

func marshalKey(partitionKey, sortKey string) (map[string]ddbtypes.AttributeValue, error) {
	return attributevalue.MarshalMap(kvKey{PartitionKey: partitionKey, SortKey: sortKey})
}

// versionCAS guards a write: head absent or its version equals cur; this serializes honest writers.
func versionCAS(cur uint64) expression.ConditionBuilder {
	return expression.AttributeNotExists(expression.Name(attrVersion)).
		Or(expression.Name(attrVersion).Equal(expression.Value(cur)))
}

// setExpires sets the expires attribute when expires>0, otherwise removes it (SET clears any prior TTL).
func setExpires(u expression.UpdateBuilder, expires int64) expression.UpdateBuilder {
	if expires > 0 {
		return u.Set(expression.Name(attrExpires), expression.Value(expires))
	}
	return u.Remove(expression.Name(attrExpires))
}

// setType tags the head with a collection type, or removes the tag for a string.
func setType(u expression.UpdateBuilder, kvType string) expression.UpdateBuilder {
	if kvType == "" {
		return u.Remove(expression.Name(attrType))
	}
	return u.Set(expression.Name(attrType), expression.Value(kvType))
}

func splitChunks(value []byte, size int) [][]byte {
	chunks := make([][]byte, 0, (len(value)+size-1)/size)
	for start := 0; start < len(value); start += size {
		chunks = append(chunks, value[start:min(start+size, len(value))])
	}
	return chunks
}

func isConditionalCheckFailed(err error) bool {
	var ce *ddbtypes.ConditionalCheckFailedException
	return errors.As(err, &ce)
}

func isTransactionCanceled(err error) bool {
	var tc *ddbtypes.TransactionCanceledException
	return errors.As(err, &tc)
}
