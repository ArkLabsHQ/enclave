package runtime

import (
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

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
