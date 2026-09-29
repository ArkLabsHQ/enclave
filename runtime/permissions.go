package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Each grant is simulated separately because IAM evaluates every action-resource pair.
type requiredGrant struct {
	sid      string
	resource string
	actions  []string
	context  []iamtypes.ContextEntry
	region   string
}

const (
	preflightAttempts = 5
	preflightBackoff  = 5 * time.Second
)

// Permissions checks the host role's boot and migration grants.
type Permissions struct {
	cfg     *Config
	ssm     SSM
	iam     IAMAPI
	pcr0    string
	backoff time.Duration // grows linearly between attempts
}

// Preflight checks role grants before durable writes can strand state.
// It does not check resource policies or bucket configuration.
func (p *Permissions) Preflight(ctx context.Context, stsc STSAPI) error {
	for attempt := 1; ; attempt++ {
		err := p.check(ctx, stsc)
		if err == nil || !isTransient(err) || attempt == preflightAttempts {
			return err
		}
		slog.Warn("permission preflight could not complete; retrying",
			"attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(time.Duration(attempt) * p.backoff):
		}
	}
}

func (p *Permissions) check(ctx context.Context, stsc STSAPI) error {
	identity, err := stsc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("permission preflight: resolve caller identity: %w", err)
	}
	roleARN, err := assumedRoleARNToRoleARN(aws.ToString(identity.Arn))
	if err != nil {
		return fmt.Errorf("permission preflight: %w", err)
	}

	grants, err := p.requiredGrants(
		ctx, strings.SplitN(roleARN, ":", 3)[1], aws.ToString(identity.Account),
	)
	if err != nil {
		return fmt.Errorf("permission preflight: %w", err)
	}

	var missing []string
	for _, g := range grants {
		region := g.region
		if region == "" {
			region = p.cfg.AWSRegion
		}
		entries := []iamtypes.ContextEntry{
			permissionContext("aws:RequestedRegion", region),
			permissionContext("aws:PrincipalArn", roleARN),
		}
		denied, err := p.simulateGrant(ctx, roleARN, g, append(entries, g.context...))
		if err != nil {
			return fmt.Errorf("permission preflight: %w", err)
		}
		missing = append(missing, denied...)
	}
	if len(missing) > 0 {
		return fmt.Errorf(
			"permission preflight: role %s is missing %s", roleARN, strings.Join(missing, "; "),
		)
	}
	return nil
}

func (p *Permissions) simulateGrant(
	ctx context.Context, roleARN string, g requiredGrant,
	entries []iamtypes.ContextEntry,
) ([]string, error) {
	in := iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(roleARN),
		ActionNames:     g.actions,
		ResourceArns:    []string{g.resource},
		ContextEntries:  entries,
	}
	seenActions := make(map[string]bool)
	seenMarkers := make(map[string]bool)
	var missing []string
	for {
		page := in
		out, err := p.iam.SimulatePrincipalPolicy(ctx, &page)
		if err != nil {
			return nil, fmt.Errorf("iam:SimulatePrincipalPolicy on %s: %w", roleARN, err)
		}
		if out == nil {
			return nil, fmt.Errorf("IAM returned no simulation for %s on %s", g.sid, g.resource)
		}
		for _, r := range out.EvaluationResults {
			action := aws.ToString(r.EvalActionName)
			seenActions[strings.ToLower(action)] = true
			if r.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
				continue
			}
			detail := string(r.EvalDecision)
			contextKeys := slices.Clone(r.MissingContextValues)
			for _, resource := range r.ResourceSpecificResults {
				contextKeys = append(contextKeys, resource.MissingContextValues...)
			}
			if len(contextKeys) > 0 {
				slices.Sort(contextKeys)
				detail += "; missing simulation context: " + strings.Join(
					slices.Compact(contextKeys),
					", ",
				)
			}
			missing = append(
				missing,
				fmt.Sprintf("%s %s on %s (%s)", g.sid, action, g.resource, detail),
			)
		}
		if !out.IsTruncated {
			break
		}
		marker := aws.ToString(out.Marker)
		if marker == "" || seenMarkers[marker] {
			return nil, fmt.Errorf(
				"IAM returned incomplete pagination for %s on %s",
				g.sid,
				g.resource,
			)
		}
		seenMarkers[marker] = true
		in.Marker = out.Marker
	}
	for _, action := range g.actions {
		if !seenActions[strings.ToLower(action)] {
			return nil, fmt.Errorf("IAM omitted %s on %s from its simulation", action, g.resource)
		}
	}
	return missing, nil
}

func (p *Permissions) requiredGrants(
	ctx context.Context, partition, account string,
) ([]requiredGrant, error) {
	intentBucket := migrationIntentBucketName(p.cfg, account)
	leaseBucket, err := p.ssm.MustGet(ctx, p.cfg.leaseBucketParam())
	if err != nil {
		return nil, err
	}
	certBucket, err := p.ssm.MustGet(ctx, p.cfg.certBucketParam())
	if err != nil {
		return nil, err
	}

	s3ARN := func(resource string) string { return fmt.Sprintf("arn:%s:s3:::%s", partition, resource) }
	objectRW := []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}

	grants := []requiredGrant{
		{
			sid: "SSMParams",
			resource: fmt.Sprintf("arn:%s:ssm:%s:%s:parameter/%s/%s/*",
				partition, p.cfg.AWSRegion, account, p.cfg.Deployment, p.cfg.AppName),
			actions: []string{"ssm:GetParameter", "ssm:GetParametersByPath", "ssm:PutParameter"},
		},
		// Without ListBucket, S3 answers a missing key with 403 rather than 404.
		{
			sid:      "S3CertAndLeaseReadWrite",
			resource: s3ARN(leaseBucket),
			actions:  []string{"s3:ListBucket"},
		},
		{
			sid:      "S3CertAndLeaseReadWrite",
			resource: s3ARN(certBucket),
			actions:  []string{"s3:ListBucket"},
		},
		{
			sid:      "S3MigrationIntentObjectLock",
			resource: s3ARN(intentBucket + "/*"),
			// GetObjectRetention exposes the lock needed to validate intents.
			actions: []string{
				"s3:PutObject", "s3:GetObject", "s3:GetObjectVersion",
				"s3:PutObjectRetention", "s3:GetObjectRetention",
			},
		},
		{
			sid:      "S3MigrationIntentObjectLock",
			resource: s3ARN(intentBucket),
			actions:  []string{"s3:ListBucketVersions"},
		},
	}

	for _, name := range []string{genesisLeaseName, certLeaseName, "migration-" + p.pcr0} {
		grants = append(grants, requiredGrant{
			sid:      "S3CertAndLeaseReadWrite",
			resource: s3ARN(leaseBucket + "/" + leaseObjectKey(p.cfg, name)), actions: objectRW,
		})
	}
	certPrefix := selfSignedStoragePrefix
	if p.cfg.UseACME {
		certPrefix = acmeStoragePrefix
		grants = append(grants, requiredGrant{
			sid: "S3CertAndLeaseReadWrite",
			resource: s3ARN(
				certBucket + "/" + objectKeyFor(p.cfg, acmeStoragePrefix, "account.key"),
			),
			actions: []string{"s3:GetObject", "s3:PutObject"},
		})
	}
	grants = append(
		grants,
		requiredGrant{
			sid:      "S3CertAndLeaseReadWrite",
			resource: s3ARN(certBucket + "/" + objectKeyFor(p.cfg, certPrefix, p.cfg.FQDN+"/cert")),
			actions:  []string{"s3:GetObject", "s3:PutObject"},
		},
		requiredGrant{
			sid:      "S3MigrationIntentObjectLock",
			resource: s3ARN(intentBucket + "/" + deploymentGenesisKey),
			actions: []string{
				"s3:PutObject", "s3:GetObject", "s3:GetObjectVersion",
				"s3:PutObjectRetention", "s3:GetObjectRetention",
			},
		},
	)
	for _, param := range []string{
		p.cfg.kmsKeyIDParam(p.pcr0), p.cfg.migrationChallengeParam(p.pcr0),
		p.cfg.migrationPreviousPCR0Param(p.pcr0), p.cfg.migrationPreviousKMSKeyIDParam(p.pcr0),
		p.cfg.migrationPreviousPCR0AttestationParam(p.pcr0),
	} {
		grants = append(grants, requiredGrant{
			sid: "SSMParams",
			resource: fmt.Sprintf(
				"arn:%s:ssm:%s:%s:parameter%s",
				partition,
				p.cfg.AWSRegion,
				account,
				param,
			),
			actions: []string{"ssm:GetParameter", "ssm:PutParameter"},
		})
	}

	for _, migration := range []bool{false, true} {
		var entries []iamtypes.ContextEntry
		var tagKeys []string
		for _, tag := range kmsKeyTags(p.cfg, migration) {
			key := aws.ToString(tag.TagKey)
			tagKeys = append(tagKeys, key)
			entries = append(
				entries,
				permissionContext("aws:RequestTag/"+key, aws.ToString(tag.TagValue)),
			)
		}
		entries = append(entries, permissionListContext("aws:TagKeys", tagKeys...))
		grants = append(
			grants,
			requiredGrant{
				sid:      "KMSAccess",
				resource: "*",
				actions:  []string{"kms:CreateKey"},
				context:  entries,
			},
			requiredGrant{
				sid: "KMSAccess",
				resource: fmt.Sprintf(
					"arn:%s:kms:%s:%s:key/*",
					partition,
					p.cfg.AWSRegion,
					account,
				),
				actions: []string{"kms:TagResource"},
				context: entries,
			},
		)
	}

	for sig := signal(0); sig < signalCount; sig++ {
		group := fmt.Sprintf("arn:%s:logs:%s:%s:log-group:%s",
			partition, p.cfg.AWSRegion, account, p.cfg.logGroup(sig))
		grants = append(
			grants,
			requiredGrant{
				sid: "CloudWatchLogsAccess", resource: group + ":*",
				actions: []string{"logs:CreateLogGroup"},
			},
			requiredGrant{
				sid: "CloudWatchLogsAccess", resource: group + ":log-stream:" + p.cfg.InstanceID,
				actions: []string{"logs:CreateLogStream", "logs:PutLogEvents"},
			},
		)
	}

	if p.cfg.UseACME {
		zoneID, err := p.ssm.MustGet(ctx, p.cfg.route53ZoneIDParam())
		if err != nil {
			return nil, err
		}
		region := "us-east-1"
		if partition == "aws-cn" {
			region = "cn-northwest-1"
		}
		for _, action := range []string{"UPSERT", "DELETE"} {
			grants = append(grants, requiredGrant{
				sid: "Route53AcmeChallenge",
				resource: fmt.Sprintf("arn:%s:route53:::hostedzone/%s",
					partition, strings.TrimPrefix(zoneID, "/hostedzone/")),
				actions: []string{"route53:ChangeResourceRecordSets"}, region: region,
				context: []iamtypes.ContextEntry{
					permissionListContext("route53:ChangeResourceRecordSetsNormalizedRecordNames",
						strings.ToLower(strings.TrimSuffix(acmeChallengeName(p.cfg.FQDN), "."))),
					permissionListContext("route53:ChangeResourceRecordSetsRecordTypes", "TXT"),
					permissionListContext("route53:ChangeResourceRecordSetsActions", action),
				},
			})
		}
		grants = append(grants, requiredGrant{
			sid:      "Route53AcmeChallenge",
			resource: fmt.Sprintf("arn:%s:route53:::change/*", partition),
			actions:  []string{"route53:GetChange"},
			region:   region,
		})
	}
	return grants, nil
}

func permissionContext(name, value string) iamtypes.ContextEntry {
	return iamtypes.ContextEntry{
		ContextKeyName: aws.String(name), ContextKeyValues: []string{value},
		ContextKeyType: iamtypes.ContextKeyTypeEnumString,
	}
}

func permissionListContext(name string, values ...string) iamtypes.ContextEntry {
	return iamtypes.ContextEntry{
		ContextKeyName: aws.String(name), ContextKeyValues: values,
		ContextKeyType: iamtypes.ContextKeyTypeEnumStringList,
	}
}

func isTransient(err error) bool {
	var exhausted *retry.MaxAttemptsError
	return errors.As(err, &exhausted)
}
