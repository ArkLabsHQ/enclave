package runtime

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/kms"
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
	PutLogEvents(
		ctx context.Context,
		params *cloudwatchlogs.PutLogEventsInput,
		optFns ...func(*cloudwatchlogs.Options),
	) (*cloudwatchlogs.PutLogEventsOutput, error)
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
	KMS KMSAPI
	SSM SSMAPI
	S3  S3API
	STS STSAPI
	CWL CloudWatchLogsAPI
}

// NewAWSClient constructs all SDK clients from a single shared aws.Config.
// Returns an error if the IMDS-bridged config can't be loaded.
func NewAWSClient(ctx context.Context) (*AWSClient, error) {
	cfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &AWSClient{
		KMS: newKMSClient(cfg),
		SSM: newSSMClient(cfg),
		S3:  newS3Client(cfg),
		STS: newSTSClient(cfg),
		CWL: newCloudWatchLogsClient(cfg),
	}, nil
}

// newKMSClient creates a KMS client, respecting AWS_ENDPOINT_URL_KMS for localstack.
func newKMSClient(cfg aws.Config) *kms.Client {
	return kms.NewFromConfig(cfg, func(o *kms.Options) {
		if ep := os.Getenv("AWS_ENDPOINT_URL_KMS"); ep != "" {
			o.BaseEndpoint = aws.String(ep)
		}
	})
}

// newSSMClient creates an SSM client, respecting AWS_ENDPOINT_URL_SSM for localstack.
func newSSMClient(cfg aws.Config) *ssm.Client {
	return ssm.NewFromConfig(cfg, func(o *ssm.Options) {
		if ep := os.Getenv("AWS_ENDPOINT_URL_SSM"); ep != "" {
			o.BaseEndpoint = aws.String(ep)
		}
	})
}

// newSTSClient creates an STS client, respecting AWS_ENDPOINT_URL_STS for localstack.
func newSTSClient(cfg aws.Config) *sts.Client {
	return sts.NewFromConfig(cfg, func(o *sts.Options) {
		if ep := os.Getenv("AWS_ENDPOINT_URL_STS"); ep != "" {
			o.BaseEndpoint = aws.String(ep)
		}
	})
}

// newS3Client creates an S3 client, respecting AWS_ENDPOINT_URL_S3 for localstack.
func newS3Client(cfg aws.Config) *s3.Client {
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		if ep := os.Getenv("AWS_ENDPOINT_URL_S3"); ep != "" {
			o.BaseEndpoint = aws.String(ep)
			o.UsePathStyle = true // localstack requires path-style addressing
		}
	})
}

// newCloudWatchLogsClient creates a CloudWatch Logs client, respecting
// AWS_ENDPOINT_URL_LOGS for localstack.
func newCloudWatchLogsClient(cfg aws.Config) *cloudwatchlogs.Client {
	if ep := os.Getenv("AWS_ENDPOINT_URL_LOGS"); ep != "" {
		return cloudwatchlogs.NewFromConfig(cfg, func(o *cloudwatchlogs.Options) {
			o.BaseEndpoint = aws.String(ep)
		})
	}
	return cloudwatchlogs.NewFromConfig(cfg)
}

// loadAWSConfigWithIMDS loads AWS config using SDK defaults.
// startViproxy points IMDS at the local forwarder before clients are built.
func loadAWSConfigWithIMDS(ctx context.Context) (aws.Config, error) {
	region := os.Getenv("ENCLAVE_AWS_REGION")

	if region == "" {
		region = "us-east-1"
	}

	opts := []func(*awscfg.LoadOptions) error{
		awscfg.WithRegion(region),
		awscfg.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
	}

	// If IMDS endpoint is set via the standard env var, the SDK picks it up
	// automatically. For the legacy IMDS_ENDPOINT env var, explicitly configure it.
	if endpoint := os.Getenv("IMDS_ENDPOINT"); endpoint != "" &&
		os.Getenv("AWS_EC2_METADATA_SERVICE_ENDPOINT") == "" {
		opts = append(opts, awscfg.WithEC2IMDSEndpoint("http://"+endpoint))
	}

	cfg, err := awscfg.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}

	return cfg, nil
}
