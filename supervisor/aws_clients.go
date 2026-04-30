package supervisor

import (
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AWSClient bundles every AWS SDK client the supervisor needs, built once
// from a shared aws.Config and shared across subsystems.
type AWSClient struct {
	KMS *kms.Client
	SSM *ssm.Client
	S3  *s3.Client
	STS *sts.Client
	CWL *cloudwatchlogs.Client
}

// NewAWSClient honours AWS_ENDPOINT_URL_* overrides for localstack and the
// integration test harness.
func NewAWSClient(cfg aws.Config) *AWSClient {
	return &AWSClient{
		KMS: newKMSClient(cfg),
		SSM: newSSMClient(cfg),
		S3:  newS3Client(cfg),
		STS: newSTSClient(cfg),
		CWL: newCloudWatchLogsClient(cfg),
	}
}

func newKMSClient(cfg aws.Config) *kms.Client {
	return kms.NewFromConfig(cfg, func(o *kms.Options) {
		if ep := os.Getenv("AWS_ENDPOINT_URL_KMS"); ep != "" {
			o.BaseEndpoint = aws.String(ep)
		}
	})
}

func newSSMClient(cfg aws.Config) *ssm.Client {
	return ssm.NewFromConfig(cfg, func(o *ssm.Options) {
		if ep := os.Getenv("AWS_ENDPOINT_URL_SSM"); ep != "" {
			o.BaseEndpoint = aws.String(ep)
		}
	})
}

func newSTSClient(cfg aws.Config) *sts.Client {
	return sts.NewFromConfig(cfg, func(o *sts.Options) {
		if ep := os.Getenv("AWS_ENDPOINT_URL_STS"); ep != "" {
			o.BaseEndpoint = aws.String(ep)
		}
	})
}

func newS3Client(cfg aws.Config) *s3.Client {
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		if ep := os.Getenv("AWS_ENDPOINT_URL_S3"); ep != "" {
			o.BaseEndpoint = aws.String(ep)
			o.UsePathStyle = true
		}
	})
}

func newCloudWatchLogsClient(cfg aws.Config) *cloudwatchlogs.Client {
	if ep := os.Getenv("AWS_ENDPOINT_URL_LOGS"); ep != "" {
		return cloudwatchlogs.NewFromConfig(cfg, func(o *cloudwatchlogs.Options) {
			o.BaseEndpoint = aws.String(ep)
		})
	}
	return cloudwatchlogs.NewFromConfig(cfg)
}
