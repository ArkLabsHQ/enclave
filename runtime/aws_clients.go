package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// KMSAPI is the subset of *kms.Client used by the runtime.
type KMSAPI interface {
	Encrypt(
		ctx context.Context,
		params *kms.EncryptInput,
		optFns ...func(*kms.Options),
	) (*kms.EncryptOutput, error)
	Decrypt(
		ctx context.Context,
		params *kms.DecryptInput,
		optFns ...func(*kms.Options),
	) (*kms.DecryptOutput, error)
	GenerateDataKey(
		ctx context.Context,
		params *kms.GenerateDataKeyInput,
		optFns ...func(*kms.Options),
	) (*kms.GenerateDataKeyOutput, error)
	GetKeyPolicy(
		ctx context.Context,
		params *kms.GetKeyPolicyInput,
		optFns ...func(*kms.Options),
	) (*kms.GetKeyPolicyOutput, error)
	DescribeKey(
		ctx context.Context,
		params *kms.DescribeKeyInput,
		optFns ...func(*kms.Options),
	) (*kms.DescribeKeyOutput, error)
	CreateKey(
		ctx context.Context,
		params *kms.CreateKeyInput,
		optFns ...func(*kms.Options),
	) (*kms.CreateKeyOutput, error)
}

// SSMAPI is the subset of *ssm.Client used by the runtime.
type SSMAPI interface {
	GetParameter(
		ctx context.Context,
		params *ssm.GetParameterInput,
		optFns ...func(*ssm.Options),
	) (*ssm.GetParameterOutput, error)
	GetParametersByPath(
		ctx context.Context,
		params *ssm.GetParametersByPathInput,
		optFns ...func(*ssm.Options),
	) (*ssm.GetParametersByPathOutput, error)
	PutParameter(
		ctx context.Context,
		params *ssm.PutParameterInput,
		optFns ...func(*ssm.Options),
	) (*ssm.PutParameterOutput, error)
}

// S3API is the subset of *s3.Client used by the runtime.
type S3API interface {
	GetObject(
		ctx context.Context,
		params *s3.GetObjectInput,
		optFns ...func(*s3.Options),
	) (*s3.GetObjectOutput, error)
	HeadObject(
		ctx context.Context,
		params *s3.HeadObjectInput,
		optFns ...func(*s3.Options),
	) (*s3.HeadObjectOutput, error)
	PutObject(
		ctx context.Context,
		params *s3.PutObjectInput,
		optFns ...func(*s3.Options),
	) (*s3.PutObjectOutput, error)
	DeleteObject(
		ctx context.Context,
		params *s3.DeleteObjectInput,
		optFns ...func(*s3.Options),
	) (*s3.DeleteObjectOutput, error)
	ListObjectsV2(
		ctx context.Context,
		params *s3.ListObjectsV2Input,
		optFns ...func(*s3.Options),
	) (*s3.ListObjectsV2Output, error)
	ListObjectVersions(
		ctx context.Context,
		params *s3.ListObjectVersionsInput,
		optFns ...func(*s3.Options),
	) (*s3.ListObjectVersionsOutput, error)
}

// Route53API is the subset of *route53.Client used by DNS-01 issuance.
type Route53API interface {
	ChangeResourceRecordSets(
		ctx context.Context,
		params *route53.ChangeResourceRecordSetsInput,
		optFns ...func(*route53.Options),
	) (*route53.ChangeResourceRecordSetsOutput, error)
	GetChange(
		ctx context.Context,
		params *route53.GetChangeInput,
		optFns ...func(*route53.Options),
	) (*route53.GetChangeOutput, error)
}

// STSAPI is the subset of *sts.Client used by the runtime.
type STSAPI interface {
	GetCallerIdentity(
		ctx context.Context,
		params *sts.GetCallerIdentityInput,
		optFns ...func(*sts.Options),
	) (*sts.GetCallerIdentityOutput, error)
}

// CloudWatchLogsAPI is the subset of *cloudwatchlogs.Client used by the runtime.
type CloudWatchLogsAPI interface {
	CreateLogGroup(
		ctx context.Context,
		params *cloudwatchlogs.CreateLogGroupInput,
		optFns ...func(*cloudwatchlogs.Options),
	) (*cloudwatchlogs.CreateLogGroupOutput, error)
	CreateLogStream(
		ctx context.Context,
		params *cloudwatchlogs.CreateLogStreamInput,
		optFns ...func(*cloudwatchlogs.Options),
	) (*cloudwatchlogs.CreateLogStreamOutput, error)
	PutRetentionPolicy(
		ctx context.Context,
		params *cloudwatchlogs.PutRetentionPolicyInput,
		optFns ...func(*cloudwatchlogs.Options),
	) (*cloudwatchlogs.PutRetentionPolicyOutput, error)
}

// AWSClient bundles runtime AWS clients from one shared config.
type AWSClient struct {
	KMS     KMSAPI
	SSM     SSMAPI
	S3      S3API
	STS     STSAPI
	CWL     CloudWatchLogsAPI
	Route53 Route53API

	// OTLP signs for the AWS OTLP endpoints, which no SDK client speaks.
	OTLP *OTLPEndpoints

	InstanceID string
}

// NewAWSClient constructs all SDK clients from a single shared aws.Config.
// Returns an error if the IMDS-bridged config can't be loaded or IMDS does not
// name the instance: that ID names every CloudWatch log stream, so a boot
// without it has nowhere to ship telemetry.
func NewAWSClient(ctx context.Context, cfg Config) (*AWSClient, error) {
	opts := []func(*awscfg.LoadOptions) error{
		awscfg.WithRegion(cfg.AWSRegion),
		awscfg.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
		awscfg.WithEC2IMDSEndpoint(cfg.EC2MetadataEndpoint),
	}

	awsCfg, err := awscfg.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	instanceID, err := resolveInstanceID(ctx, imds.NewFromConfig(awsCfg))
	if err != nil {
		return nil, fmt.Errorf("resolve instance ID: %w", err)
	}

	return &AWSClient{
		KMS:     newKMSClient(cfg, awsCfg),
		SSM:     newSSMClient(cfg, awsCfg),
		S3:      newS3Client(cfg, awsCfg),
		STS:     newSTSClient(cfg, awsCfg),
		CWL:     newCloudWatchLogsClient(cfg, awsCfg),
		Route53: newRoute53Client(cfg, awsCfg),
		OTLP:    newOTLPEndpoints(cfg, awsCfg),

		InstanceID: instanceID,
	}, nil
}

func newRoute53Client(cfg Config, awsCfg aws.Config) *route53.Client {
	return route53.NewFromConfig(awsCfg, func(o *route53.Options) {
		if cfg.Route53Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Route53Endpoint)
		}
	})
}

func newKMSClient(cfg Config, awsCfg aws.Config) *kms.Client {
	return kms.NewFromConfig(awsCfg, func(o *kms.Options) {
		if cfg.KMSEndpoint != "" {
			o.BaseEndpoint = aws.String(cfg.KMSEndpoint)
		}
	})
}

func newSSMClient(cfg Config, awsCfg aws.Config) *ssm.Client {
	return ssm.NewFromConfig(awsCfg, func(o *ssm.Options) {
		if cfg.SSMEndpoint != "" {
			o.BaseEndpoint = aws.String(cfg.SSMEndpoint)
		}
	})
}

func newSTSClient(cfg Config, awsCfg aws.Config) *sts.Client {
	return sts.NewFromConfig(awsCfg, func(o *sts.Options) {
		if cfg.STSEndpoint != "" {
			o.BaseEndpoint = aws.String(cfg.STSEndpoint)
		}
	})
}

func newS3Client(cfg Config, awsCfg aws.Config) *s3.Client {
	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.S3Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.S3Endpoint)
			o.UsePathStyle = true // localstack requires path-style addressing
		}
	})
}

func newCloudWatchLogsClient(cfg Config, awsCfg aws.Config) *cloudwatchlogs.Client {
	return cloudwatchlogs.NewFromConfig(awsCfg, func(o *cloudwatchlogs.Options) {
		if cfg.CloudWatchEndpoint != "" {
			o.BaseEndpoint = aws.String(cfg.CloudWatchEndpoint)
		}
	})
}

// imdsMetadataAPI is the subset of *imds.Client used to name the instance.
type imdsMetadataAPI interface {
	GetMetadata(
		ctx context.Context,
		params *imds.GetMetadataInput,
		optFns ...func(*imds.Options),
	) (*imds.GetMetadataOutput, error)
}

func resolveInstanceID(ctx context.Context, client imdsMetadataAPI) (string, error) {
	out, err := client.GetMetadata(ctx, &imds.GetMetadataInput{Path: "instance-id"})
	if err != nil {
		return "", fmt.Errorf("IMDS instance-id lookup: %w", err)
	}
	defer func() { _ = out.Content.Close() }()

	raw, err := io.ReadAll(out.Content)
	if err != nil {
		return "", fmt.Errorf("read IMDS instance-id response: %w", err)
	}
	id := strings.TrimSpace(string(raw))
	if id == "" {
		return "", fmt.Errorf("IMDS returned an empty instance-id")
	}
	return id, nil
}

type otlpClient struct {
	base   string
	client *http.Client
}

// OTLPEndpoints contains a signing client for each AWS OTLP service.
type OTLPEndpoints struct {
	Logs    otlpClient
	Traces  otlpClient
	Metrics otlpClient
}

func newOTLPEndpoints(cfg Config, awsCfg aws.Config) *OTLPEndpoints {
	signer := v4.NewSigner()
	return &OTLPEndpoints{
		Logs:    newOTLPClient(awsCfg, signer, "logs", cfg.CloudWatchEndpoint),
		Traces:  newOTLPClient(awsCfg, signer, "xray", cfg.XRayEndpoint),
		Metrics: newOTLPClient(awsCfg, signer, "monitoring", cfg.MonitoringEndpoint),
	}
}

func newOTLPClient(cfg aws.Config, signer *v4.Signer, service, override string) otlpClient {
	base := fmt.Sprintf("https://%s.%s.amazonaws.com", service, cfg.Region)
	if override != "" {
		base = strings.TrimRight(override, "/")
	}

	// AWS OTLP endpoints require HTTP/1.1.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}

	return otlpClient{
		base: base,
		client: &http.Client{
			Timeout: otlpHTTPTimeout,
			Transport: &sigv4Transport{
				creds:   cfg.Credentials,
				region:  cfg.Region,
				service: service,
				signer:  signer,
				next:    transport,
			},
		},
	}
}

// sigv4Transport signs requests without modifying the caller's request.
type sigv4Transport struct {
	creds   aws.CredentialsProvider
	region  string
	service string
	signer  *v4.Signer
	next    http.RoundTripper
}

func (t *sigv4Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("sigv4: read body: %w", err)
		}
	}
	creds, err := t.creds.Retrieve(req.Context())
	if err != nil {
		return nil, fmt.Errorf("sigv4: credentials: %w", err)
	}

	signed := req.Clone(req.Context())
	signed.Body = io.NopCloser(bytes.NewReader(body))
	signed.ContentLength = int64(len(body))
	signed.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	sum := sha256.Sum256(body)
	if err := t.signer.SignHTTP(
		req.Context(), creds, signed, hex.EncodeToString(sum[:]),
		t.service, t.region, time.Now(),
	); err != nil {
		return nil, fmt.Errorf("sigv4: sign %s request: %w", t.service, err)
	}
	return t.next.RoundTrip(signed)
}
