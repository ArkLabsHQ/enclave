package runtime

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

type fakeSSM struct {
	params map[string]string
	err    error
	calls  []string

	// For GetParametersByPath pagination tests: pages[i] is the i-th page of
	// (Name, Value) pairs. nextTokens[i] is the NextToken returned on page i
	// (empty string = no more). lastDecryption captures the last call's
	// WithDecryption value so tests can assert SecureString handling.
	pages          [][]ssmtypes.Parameter
	nextTokens     []string
	lastDecryption bool
	pathCalls      int
}

func (f *fakeSSM) PutParameter(
	_ context.Context,
	in *ssm.PutParameterInput,
	_ ...func(*ssm.Options),
) (*ssm.PutParameterOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.params == nil {
		f.params = map[string]string{}
	}
	f.params[aws.ToString(in.Name)] = aws.ToString(in.Value)
	return &ssm.PutParameterOutput{}, nil
}

func (f *fakeSSM) GetParameter(
	_ context.Context,
	in *ssm.GetParameterInput,
	_ ...func(*ssm.Options),
) (*ssm.GetParameterOutput, error) {
	name := aws.ToString(in.Name)
	f.calls = append(f.calls, name)
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.params[name]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	return &ssm.GetParameterOutput{
		Parameter: &ssmtypes.Parameter{Name: aws.String(name), Value: aws.String(v)},
	}, nil
}

func (f *fakeSSM) GetParametersByPath(
	_ context.Context,
	in *ssm.GetParametersByPathInput,
	_ ...func(*ssm.Options),
) (*ssm.GetParametersByPathOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if in.WithDecryption != nil {
		f.lastDecryption = *in.WithDecryption
	}

	if f.pages != nil {
		i := f.pathCalls
		if i == 0 && in.NextToken != nil {
			return nil, fmt.Errorf("unexpected next token %q", aws.ToString(in.NextToken))
		}
		if i > 0 {
			want := ""
			if i-1 < len(f.nextTokens) {
				want = f.nextTokens[i-1]
			}
			if aws.ToString(in.NextToken) != want {
				return nil, fmt.Errorf(
					"unexpected next token %q, want %q",
					aws.ToString(in.NextToken),
					want,
				)
			}
		}
		f.pathCalls++
		if i >= len(f.pages) {
			return &ssm.GetParametersByPathOutput{}, nil
		}
		out := &ssm.GetParametersByPathOutput{Parameters: f.pages[i]}
		if i < len(f.nextTokens) && f.nextTokens[i] != "" {
			out.NextToken = aws.String(f.nextTokens[i])
		}
		return out, nil
	}

	prefix := aws.ToString(in.Path)
	var out []ssmtypes.Parameter
	for name, val := range f.params {
		if strings.HasPrefix(name, prefix) {
			n, v := name, val
			out = append(out, ssmtypes.Parameter{Name: &n, Value: &v})
		}
	}
	return &ssm.GetParametersByPathOutput{Parameters: out}, nil
}

func (f *fakeSSM) Set(_ context.Context, key, val string, _ ...SSMSetOption) error {
	if f.err != nil {
		return f.err
	}
	if f.params == nil {
		f.params = map[string]string{}
	}
	f.params[key] = val
	return nil
}

func (f *fakeSSM) MustGet(_ context.Context, key string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	val := strings.TrimSpace(f.params[key])
	if val == "" || val == "UNSET" {
		return "", fmt.Errorf("parameter %s is unset", key)
	}
	return val, nil
}

func (f *fakeSSM) MayGet(_ context.Context, key string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	val := strings.TrimSpace(f.params[key])
	if val == "UNSET" {
		return "", nil
	}
	return val, nil
}

func (f *fakeSSM) ListParams(_ context.Context, prefix string) ([]Param, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []Param
	for key, val := range f.params {
		if strings.HasPrefix(key, prefix) {
			out = append(out, Param{Name: key, Value: val})
		}
	}
	return out, nil
}

type fakeSTS struct {
	arn string
	err error
}

func (f *fakeSTS) GetCallerIdentity(
	_ context.Context,
	_ *sts.GetCallerIdentityInput,
	_ ...func(*sts.Options),
) (*sts.GetCallerIdentityOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	arn := f.arn
	if arn == "" {
		arn = "arn:aws:iam::123456789012:role/enclave"
	}
	return &sts.GetCallerIdentityOutput{Arn: aws.String(arn)}, nil
}

type fakeKMS struct {
	mu    sync.Mutex
	seq   int
	keys  map[string]string
	blobs map[string][]byte
}

func newFakeKMS() *fakeKMS { return &fakeKMS{keys: map[string]string{}, blobs: map[string][]byte{}} }

func (f *fakeKMS) putKey(keyID, policy string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	f.keys[keyID] = policy
}

func (f *fakeKMS) keyPolicy(keyID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys[keyID]
}

func (f *fakeKMS) init() {
	if f.keys == nil {
		f.keys = map[string]string{}
	}
	if f.blobs == nil {
		f.blobs = map[string][]byte{}
	}
}

func (f *fakeKMS) Encrypt(
	_ context.Context,
	in *kms.EncryptInput,
	_ ...func(*kms.Options),
) (*kms.EncryptOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	f.seq++
	blob := []byte(fmt.Sprintf("fake-kms-blob-%d", f.seq))
	f.blobs[string(blob)] = append([]byte(nil), in.Plaintext...)
	return &kms.EncryptOutput{KeyId: in.KeyId, CiphertextBlob: blob}, nil
}

func (f *fakeKMS) Decrypt(
	_ context.Context,
	in *kms.DecryptInput,
	_ ...func(*kms.Options),
) (*kms.DecryptOutput, error) {
	f.mu.Lock()
	f.init()
	plaintext, ok := f.blobs[string(in.CiphertextBlob)]
	plaintext = append([]byte(nil), plaintext...)
	f.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("fake kms ciphertext not found")
	}
	if in.Recipient == nil {
		return &kms.DecryptOutput{KeyId: in.KeyId, Plaintext: plaintext}, nil
	}
	enveloped, err := fakeKMSEnvelopeForRecipient(plaintext, in.Recipient.AttestationDocument)
	if err != nil {
		return nil, err
	}
	return &kms.DecryptOutput{KeyId: in.KeyId, CiphertextForRecipient: enveloped}, nil
}

func (f *fakeKMS) GenerateDataKey(
	_ context.Context,
	in *kms.GenerateDataKeyInput,
	_ ...func(*kms.Options),
) (*kms.GenerateDataKeyOutput, error) {
	n := int(aws.ToInt32(in.NumberOfBytes))
	if n == 0 {
		n = 32
	}
	plaintext := make([]byte, n)
	for i := range plaintext {
		plaintext[i] = byte(i + 1)
	}

	f.mu.Lock()
	f.init()
	f.seq++
	blob := []byte(fmt.Sprintf("fake-kms-data-key-%d", f.seq))
	f.blobs[string(blob)] = append([]byte(nil), plaintext...)
	f.mu.Unlock()

	out := &kms.GenerateDataKeyOutput{KeyId: in.KeyId, CiphertextBlob: blob}
	if in.Recipient == nil {
		out.Plaintext = plaintext
		return out, nil
	}
	enveloped, err := fakeKMSEnvelopeForRecipient(plaintext, in.Recipient.AttestationDocument)
	if err != nil {
		return nil, err
	}
	out.CiphertextForRecipient = enveloped
	return out, nil
}

func (f *fakeKMS) GetKeyPolicy(
	_ context.Context,
	in *kms.GetKeyPolicyInput,
	_ ...func(*kms.Options),
) (*kms.GetKeyPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	policy, ok := f.keys[aws.ToString(in.KeyId)]
	if !ok {
		return nil, fmt.Errorf("fake kms key not found")
	}
	return &kms.GetKeyPolicyOutput{Policy: aws.String(policy)}, nil
}

func (f *fakeKMS) CreateKey(
	_ context.Context,
	in *kms.CreateKeyInput,
	_ ...func(*kms.Options),
) (*kms.CreateKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	f.seq++
	keyID := fmt.Sprintf("fake-kms-key-%d", f.seq)
	f.keys[keyID] = aws.ToString(in.Policy)
	return &kms.CreateKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String(keyID)}}, nil
}

var (
	fakeKMSOIDData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	fakeKMSOIDEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	fakeKMSOIDRSAESOAEP     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	fakeKMSOIDAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type fakeKMSContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     fakeKMSEnvelopedData `asn1:"explicit,tag:0"`
}

type fakeKMSEnvelopedData struct {
	Version              int
	RecipientInfos       []fakeKMSKeyTransRecipientInfo `asn1:"set"`
	EncryptedContentInfo fakeKMSEncryptedContentInfo
}

type fakeKMSKeyTransRecipientInfo struct {
	Version                int
	RecipientIdentifier    []byte `asn1:"tag:0"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type fakeKMSEncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0"`
}

func fakeKMSEnvelopeForRecipient(plaintext, attestationDoc []byte) ([]byte, error) {
	pubKey, err := fakeKMSRSAPublicKey(attestationDoc)
	if err != nil {
		return nil, err
	}
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append(
		append([]byte(nil), plaintext...),
		bytes.Repeat([]byte{byte(padLen)}, padLen)...)
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	encryptedCEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, cek, nil)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(fakeKMSContentInfo{
		ContentType: fakeKMSOIDEnvelopedData,
		Content: fakeKMSEnvelopedData{
			Version: 2,
			RecipientInfos: []fakeKMSKeyTransRecipientInfo{{
				Version:             2,
				RecipientIdentifier: []byte{},
				KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: fakeKMSOIDRSAESOAEP,
				},
				EncryptedKey: encryptedCEK,
			}},
			EncryptedContentInfo: fakeKMSEncryptedContentInfo{
				ContentType: fakeKMSOIDData,
				ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: fakeKMSOIDAES256CBC,
					Parameters: asn1.RawValue{
						Tag:   asn1.TagOctetString,
						Class: asn1.ClassUniversal,
						Bytes: iv,
					},
				},
				EncryptedContent: asn1.RawValue{
					Tag:   0,
					Class: asn1.ClassContextSpecific,
					Bytes: ciphertext,
				},
			},
		},
	})
}

func fakeKMSRSAPublicKey(attestationDoc []byte) (*rsa.PublicKey, error) {
	var coseSign1 []cbor.RawMessage
	if err := cbor.Unmarshal(attestationDoc, &coseSign1); err != nil {
		return nil, err
	}
	if len(coseSign1) < 3 {
		return nil, fmt.Errorf("invalid attestation document")
	}
	var payload []byte
	if err := cbor.Unmarshal(coseSign1[2], &payload); err != nil {
		return nil, err
	}
	var doc struct {
		PublicKey []byte `cbor:"public_key"`
	}
	if err := cbor.Unmarshal(payload, &doc); err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(doc.PublicKey)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("attestation public key is not RSA")
	}
	return rsaPub, nil
}

type fakeS3Object struct {
	id       string
	body     []byte
	lockMode s3types.ObjectLockMode
}

type fakeS3 struct {
	mu      sync.Mutex
	seq     int
	objects map[string][]fakeS3Object
}

func newFakeS3() *fakeS3 { return &fakeS3{objects: map[string][]fakeS3Object{}} }

type fakeCloudWatchLogs struct {
	mu                 sync.Mutex
	createLogGroupErr  error
	createLogStreamErr error
	putLogEventsErr    error
	groups             []string
	streams            []string
	retentionDays      []int32
	puts               []*cloudwatchlogs.PutLogEventsInput
	putCh              chan *cloudwatchlogs.PutLogEventsInput
}

func newFakeCloudWatchLogs() *fakeCloudWatchLogs {
	return &fakeCloudWatchLogs{putCh: make(chan *cloudwatchlogs.PutLogEventsInput, 10)}
}

func (f *fakeCloudWatchLogs) CreateLogGroup(
	_ context.Context,
	in *cloudwatchlogs.CreateLogGroupInput,
	_ ...func(*cloudwatchlogs.Options),
) (*cloudwatchlogs.CreateLogGroupOutput, error) {
	if f.createLogGroupErr != nil {
		return nil, f.createLogGroupErr
	}
	f.mu.Lock()
	f.groups = append(f.groups, aws.ToString(in.LogGroupName))
	f.mu.Unlock()
	return &cloudwatchlogs.CreateLogGroupOutput{}, nil
}

func (f *fakeCloudWatchLogs) CreateLogStream(
	_ context.Context,
	in *cloudwatchlogs.CreateLogStreamInput,
	_ ...func(*cloudwatchlogs.Options),
) (*cloudwatchlogs.CreateLogStreamOutput, error) {
	if f.createLogStreamErr != nil {
		return nil, f.createLogStreamErr
	}
	f.mu.Lock()
	f.streams = append(f.streams, aws.ToString(in.LogStreamName))
	f.mu.Unlock()
	return &cloudwatchlogs.CreateLogStreamOutput{}, nil
}

func (f *fakeCloudWatchLogs) PutRetentionPolicy(
	_ context.Context,
	in *cloudwatchlogs.PutRetentionPolicyInput,
	_ ...func(*cloudwatchlogs.Options),
) (*cloudwatchlogs.PutRetentionPolicyOutput, error) {
	f.mu.Lock()
	f.retentionDays = append(f.retentionDays, aws.ToInt32(in.RetentionInDays))
	f.mu.Unlock()
	return &cloudwatchlogs.PutRetentionPolicyOutput{}, nil
}

func (f *fakeCloudWatchLogs) PutLogEvents(
	_ context.Context,
	in *cloudwatchlogs.PutLogEventsInput,
	_ ...func(*cloudwatchlogs.Options),
) (*cloudwatchlogs.PutLogEventsOutput, error) {
	if f.putLogEventsErr != nil {
		return nil, f.putLogEventsErr
	}
	f.mu.Lock()
	copyIn := *in
	copyIn.LogEvents = append([]cwltypes.InputLogEvent(nil), in.LogEvents...)
	f.puts = append(f.puts, &copyIn)
	f.mu.Unlock()
	if f.putCh != nil {
		select {
		case f.putCh <- &copyIn:
		default:
		}
	}
	return &cloudwatchlogs.PutLogEventsOutput{}, nil
}

func requireCloudWatchPut(t *testing.T, cw *fakeCloudWatchLogs) *cloudwatchlogs.PutLogEventsInput {
	t.Helper()
	select {
	case put := <-cw.putCh:
		return put
	case <-time.After(time.Second):
		require.FailNow(t, "timed out waiting for PutLogEvents")
		return nil
	}
}

func stringValue(value string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}
}

func (f *fakeS3) PutObject(
	_ context.Context,
	in *s3.PutObjectInput,
	_ ...func(*s3.Options),
) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(in.Body)
	f.seq++
	id := strconv.Itoa(f.seq)
	key := aws.ToString(in.Key)
	f.objects[key] = append(
		f.objects[key],
		fakeS3Object{id: id, body: body, lockMode: in.ObjectLockMode},
	)
	return &s3.PutObjectOutput{VersionId: aws.String(id)}, nil
}

func (f *fakeS3) GetObject(
	_ context.Context,
	in *s3.GetObjectInput,
	_ ...func(*s3.Options),
) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	objects := f.objects[aws.ToString(in.Key)]
	for i := len(objects) - 1; i >= 0; i-- {
		if in.VersionId == nil || objects[i].id == aws.ToString(in.VersionId) {
			return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(objects[i].body))}, nil
		}
	}
	return nil, &s3types.NoSuchKey{}
}

func (f *fakeS3) ListObjectVersions(
	_ context.Context,
	in *s3.ListObjectVersionsInput,
	_ ...func(*s3.Options),
) (*s3.ListObjectVersionsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := aws.ToString(in.Prefix)
	var out []s3types.ObjectVersion
	for key, objects := range f.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		for _, obj := range objects {
			out = append(
				out,
				s3types.ObjectVersion{Key: aws.String(key), VersionId: aws.String(obj.id)},
			)
		}
	}
	return &s3.ListObjectVersionsOutput{Versions: out, IsTruncated: aws.Bool(false)}, nil
}

func (f *fakeS3) ListObjectsV2(
	_ context.Context,
	_ *s3.ListObjectsV2Input,
	_ ...func(*s3.Options),
) (*s3.ListObjectsV2Output, error) {
	return &s3.ListObjectsV2Output{}, nil
}

func (f *fakeS3) DeleteObject(
	_ context.Context,
	in *s3.DeleteObjectInput,
	_ ...func(*s3.Options),
) (*s3.DeleteObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := aws.ToString(in.Key)
	objects := f.objects[key]
	if len(objects) == 0 {
		return &s3.DeleteObjectOutput{}, nil
	}

	target := len(objects) - 1
	if in.VersionId != nil {
		target = -1
		want := aws.ToString(in.VersionId)
		for i, obj := range objects {
			if obj.id == want {
				target = i
				break
			}
		}
		if target == -1 {
			return &s3.DeleteObjectOutput{}, nil
		}
	}
	if objects[target].lockMode == s3types.ObjectLockModeCompliance {
		return &s3.DeleteObjectOutput{}, nil
	}
	if in.VersionId == nil {
		delete(f.objects, key)
		return &s3.DeleteObjectOutput{}, nil
	}

	objects = append(objects[:target], objects[target+1:]...)
	if len(objects) == 0 {
		delete(f.objects, key)
	} else {
		f.objects[key] = objects
	}
	return &s3.DeleteObjectOutput{}, nil
}

// putRawObject injects object bytes as if written outside runtime code.
func (f *fakeS3) putRawObject(key string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	f.objects[key] = append(f.objects[key], fakeS3Object{id: strconv.Itoa(f.seq), body: body})
}

func (f *fakeS3) latestBody(key string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	objects := f.objects[key]
	if len(objects) == 0 {
		return nil
	}
	return objects[len(objects)-1].body
}

func TestFakeS3DeleteObjectRespectsCompliance(t *testing.T) {
	ctx := context.Background()
	s3f := newFakeS3()

	_, err := s3f.PutObject(
		ctx,
		&s3.PutObjectInput{Key: aws.String("unlocked"), Body: bytes.NewReader([]byte("x"))},
	)
	require.NoError(t, err)

	_, err = s3f.DeleteObject(ctx, &s3.DeleteObjectInput{Key: aws.String("unlocked")})
	require.NoError(t, err)

	_, err = s3f.GetObject(ctx, &s3.GetObjectInput{Key: aws.String("unlocked")})
	require.Error(t, err)
	require.True(t, isNoSuchKey(err))

	_, err = s3f.PutObject(ctx, &s3.PutObjectInput{
		Key:            aws.String("locked"),
		Body:           bytes.NewReader([]byte("x")),
		ObjectLockMode: s3types.ObjectLockModeCompliance,
	})
	require.NoError(t, err)

	_, err = s3f.DeleteObject(ctx, &s3.DeleteObjectInput{Key: aws.String("locked")})
	require.NoError(t, err)

	obj, err := s3f.GetObject(ctx, &s3.GetObjectInput{Key: aws.String("locked")})
	require.NoError(t, err)

	got, err := io.ReadAll(obj.Body)
	require.NoError(t, err)

	require.Equal(t, "x", string(got))
}

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

func ddbTokens(s string) []string {
	return strings.Fields(strings.NewReplacer("\n", " ", ",", " ", "(", " ", ")", " ").Replace(s))
}

func evalCond(
	expr string,
	names map[string]string,
	vals map[string]ddbtypes.AttributeValue,
	item map[string]ddbtypes.AttributeValue,
) bool {
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
		default:
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

func applyUpdate(
	item map[string]ddbtypes.AttributeValue,
	expr string,
	names map[string]string,
	vals map[string]ddbtypes.AttributeValue,
) {
	toks := ddbTokens(expr)
	section := ""
	for i := 0; i < len(toks); {
		switch toks[i] {
		case "SET", "REMOVE", "ADD", "DELETE":
			section = toks[i]
			i++
		default:
			switch section {
			case "SET":
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

func (f *fakeDDB) copyHead(key string) map[string]ddbtypes.AttributeValue {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cloneItem(f.items[getHeadCompositeKey(key)])
}

func (f *fakeDDB) replaceHead(key string, item map[string]ddbtypes.AttributeValue) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[getHeadCompositeKey(key)] = cloneItem(item)
}

func getHeadCompositeKey(key string) string {
	k, err := marshalKey(getPartitionKey(key), kvHeadSK)
	if err != nil {
		panic(err)
	}
	return compositeKey(k)
}

func (f *fakeDDB) GetItem(
	_ context.Context,
	in *dynamodb.GetItemInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &dynamodb.GetItemOutput{Item: cloneItem(f.items[compositeKey(in.Key)])}, nil
}

func (f *fakeDDB) UpdateItem(
	_ context.Context,
	in *dynamodb.UpdateItemInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.UpdateItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ck := compositeKey(in.Key)
	cond := ""
	if in.ConditionExpression != nil {
		cond = *in.ConditionExpression
	}
	if !evalCond(cond, in.ExpressionAttributeNames, in.ExpressionAttributeValues, f.items[ck]) {
		return nil, &ddbtypes.ConditionalCheckFailedException{
			Message: aws.String("conditional check failed"),
		}
	}
	item := cloneItem(f.items[ck])
	if item == nil {
		item = cloneItem(in.Key)
	}
	applyUpdate(
		item,
		*in.UpdateExpression,
		in.ExpressionAttributeNames,
		in.ExpressionAttributeValues,
	)
	f.items[ck] = item
	return &dynamodb.UpdateItemOutput{}, nil
}

func (f *fakeDDB) TransactWriteItems(
	_ context.Context,
	in *dynamodb.TransactWriteItemsInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.TransactWriteItemsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, item := range in.TransactItems {
		if item.Update != nil && item.Update.ConditionExpression != nil {
			if !evalCond(
				*item.Update.ConditionExpression,
				item.Update.ExpressionAttributeNames,
				item.Update.ExpressionAttributeValues,
				f.items[compositeKey(item.Update.Key)],
			) {
				return nil, &ddbtypes.TransactionCanceledException{
					Message: aws.String("ConditionalCheckFailed"),
				}
			}
		}
	}
	for _, item := range in.TransactItems {
		switch {
		case item.Put != nil:
			f.items[compositeKey(item.Put.Item)] = cloneItem(item.Put.Item)
		case item.Update != nil:
			ck := compositeKey(item.Update.Key)
			cur := cloneItem(f.items[ck])
			if cur == nil {
				cur = cloneItem(item.Update.Key)
			}
			applyUpdate(
				cur,
				*item.Update.UpdateExpression,
				item.Update.ExpressionAttributeNames,
				item.Update.ExpressionAttributeValues,
			)
			f.items[ck] = cur
		}
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func (f *fakeDDB) BatchWriteItem(
	_ context.Context,
	in *dynamodb.BatchWriteItemInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.BatchWriteItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, reqs := range in.RequestItems {
		for _, req := range reqs {
			switch {
			case req.PutRequest != nil:
				f.items[compositeKey(req.PutRequest.Item)] = cloneItem(req.PutRequest.Item)
			case req.DeleteRequest != nil:
				delete(f.items, compositeKey(req.DeleteRequest.Key))
			}
		}
	}
	return &dynamodb.BatchWriteItemOutput{}, nil
}

func (f *fakeDDB) BatchGetItem(
	_ context.Context,
	in *dynamodb.BatchGetItemInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.BatchGetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	resp := map[string][]map[string]ddbtypes.AttributeValue{}
	for table, attrs := range in.RequestItems {
		for _, key := range attrs.Keys {
			if item := f.items[compositeKey(key)]; item != nil {
				resp[table] = append(resp[table], cloneItem(item))
			}
		}
	}
	return &dynamodb.BatchGetItemOutput{Responses: resp}, nil
}

func (f *fakeDDB) PutItem(
	_ context.Context,
	in *dynamodb.PutItemInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[compositeKey(in.Item)] = cloneItem(in.Item)
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDDB) DeleteItem(
	_ context.Context,
	in *dynamodb.DeleteItemInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.DeleteItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.items, compositeKey(in.Key))
	return &dynamodb.DeleteItemOutput{}, nil
}

func (f *fakeDDB) Query(
	_ context.Context,
	_ *dynamodb.QueryInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.QueryOutput, error) {
	return &dynamodb.QueryOutput{}, nil
}

func (f *fakeDDB) Scan(
	_ context.Context,
	in *dynamodb.ScanInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.ScanOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var keys []string
	for key, item := range f.items {
		if ddbS(item[attrSortKey]) == kvHeadSK {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	start := 0
	if in != nil && len(in.ExclusiveStartKey) > 0 {
		after := compositeKey(in.ExclusiveStartKey)
		for i, key := range keys {
			if key == after {
				start = i + 1
				break
			}
		}
	}
	start = min(start, len(keys))

	end := len(keys)
	if in != nil && in.Limit != nil {
		end = min(end, start+int(aws.ToInt32(in.Limit)))
	}

	var items []map[string]ddbtypes.AttributeValue
	for _, key := range keys[start:end] {
		items = append(items, cloneItem(f.items[key]))
	}

	var last map[string]ddbtypes.AttributeValue
	if end < len(keys) && end > start {
		last = cloneItem(f.items[keys[end-1]])
	}
	return &dynamodb.ScanOutput{Items: items, LastEvaluatedKey: last}, nil
}

func isNoSuchKey(err error) bool {
	var noSuchKey *s3types.NoSuchKey
	return errors.As(err, &noSuchKey)
}
