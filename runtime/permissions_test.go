package runtime

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/require"
)

var permissionTestPCR0 = strings.Repeat("ab", 48)

// fakeIAM allows actions unless a test supplies a denial or response.
type fakeIAM struct {
	denied   map[string]bool
	err      error
	calls    []*iam.SimulatePrincipalPolicyInput
	respond  func(*iam.SimulatePrincipalPolicyInput) (*iam.SimulatePrincipalPolicyOutput, error)
	evaluate func(string, string, []iamtypes.ContextEntry) iamtypes.PolicyEvaluationDecisionType
}

func (f *fakeIAM) SimulatePrincipalPolicy(
	_ context.Context,
	in *iam.SimulatePrincipalPolicyInput,
	_ ...func(*iam.Options),
) (*iam.SimulatePrincipalPolicyOutput, error) {
	f.calls = append(f.calls, in)
	if f.err != nil {
		return nil, f.err
	}
	if f.respond != nil {
		return f.respond(in)
	}
	out := &iam.SimulatePrincipalPolicyOutput{}
	for _, action := range in.ActionNames {
		decision := iamtypes.PolicyEvaluationDecisionTypeAllowed
		if f.denied[action] {
			decision = iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
		}
		if f.evaluate != nil {
			decision = f.evaluate(action, in.ResourceArns[0], in.ContextEntries)
		}
		out.EvaluationResults = append(out.EvaluationResults, iamtypes.EvaluationResult{
			EvalActionName:   aws.String(action),
			EvalResourceName: aws.String(in.ResourceArns[0]),
			EvalDecision:     decision,
		})
	}
	return out, nil
}

// simulated reports whether any call asked about action on resource.
func (f *fakeIAM) simulated(action, resource string) bool {
	return slices.ContainsFunc(f.calls, func(in *iam.SimulatePrincipalPolicyInput) bool {
		return slices.Contains(in.ActionNames, action) && slices.Contains(in.ResourceArns, resource)
	})
}

func TestPermissionsPreflight(t *testing.T) {
	sts := &fakeSTS{
		arn: "arn:aws:sts::" + fakeSTSAccountID + ":assumed-role/enclave/i-0e2ce2ce2ce2ce2ce",
	}
	intentBucket := migrationIntentBucketName(testCfg, fakeSTSAccountID)
	acme := *testCfg
	acme.UseACME = true

	tests := []struct {
		name    string
		cfg     *Config
		iam     *fakeIAM
		wantErr []string
	}{
		{name: "role holds every grant", cfg: testCfg, iam: &fakeIAM{}},
		{
			name: "missing GetObjectRetention",
			cfg:  testCfg,
			iam:  &fakeIAM{denied: map[string]bool{"s3:GetObjectRetention": true}},
			wantErr: []string{
				"S3MigrationIntentObjectLock s3:GetObjectRetention on arn:aws:s3:::" + intentBucket + "/*",
			},
		},
		{
			name: "missing PutLogEvents",
			cfg:  testCfg,
			iam:  &fakeIAM{denied: map[string]bool{"logs:PutLogEvents": true}},
			wantErr: []string{
				"CloudWatchLogsAccess logs:PutLogEvents on arn:aws:logs:",
				":123456789012:log-group:/prod/enclave/logs/app:log-stream:i-0e2ce2ce2ce2ce2ce",
			},
		},
		{
			name: "reports every missing grant at once",
			cfg:  testCfg,
			iam: &fakeIAM{denied: map[string]bool{
				"ssm:PutParameter": true, "kms:CreateKey": true,
			}},
			wantErr: []string{
				"SSMParams ssm:PutParameter",
				"KMSAccess kms:CreateKey on * (implicitDeny)",
			},
		},
		{
			name: "ACME needs Route53",
			cfg:  &acme,
			iam:  &fakeIAM{denied: map[string]bool{"route53:ChangeResourceRecordSets": true}},
			wantErr: []string{
				"Route53AcmeChallenge route53:ChangeResourceRecordSets on arn:aws:route53:::hostedzone/Z123",
			},
		},
		{
			name: "simulation itself denied",
			cfg:  testCfg,
			iam:  &fakeIAM{err: errors.New("AccessDenied")},
			wantErr: []string{
				"iam:SimulatePrincipalPolicy on arn:aws:iam::123456789012:role/enclave",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ssm := NewSSM(&fakeSSM{params: map[string]string{
				tc.cfg.leaseBucketParam():   "lease-bucket",
				tc.cfg.certBucketParam():    "cert-bucket",
				tc.cfg.route53ZoneIDParam(): "/hostedzone/Z123",
			}})

			p := &permissions{
				cfg:  tc.cfg,
				ssm:  ssm,
				iam:  tc.iam,
				sts:  sts,
				pcr0: permissionTestPCR0,
			}
			err := p.preflight(context.Background())
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			for _, want := range tc.wantErr {
				require.ErrorContains(t, err, want)
			}
		})
	}

	t.Run("simulates the role, not the session", func(t *testing.T) {
		fake := &fakeIAM{}
		cfg := *testCfg
		cfg.AWSRegion = "eu-west-1"
		ssm := NewSSM(&fakeSSM{params: map[string]string{
			cfg.leaseBucketParam(): "lease-bucket",
			cfg.certBucketParam():  "cert-bucket",
		}})
		p := &permissions{cfg: &cfg, ssm: ssm, iam: fake, sts: sts, pcr0: permissionTestPCR0}
		require.NoError(t, p.preflight(context.Background()))

		for _, call := range fake.calls {
			require.Equal(
				t,
				"arn:aws:iam::123456789012:role/enclave",
				aws.ToString(call.PolicySourceArn),
			)
			require.Len(t, call.ResourceArns, 1)
		}
		require.True(
			t,
			fake.simulated("s3:PutObject", "arn:aws:s3:::lease-bucket/prod/app/lock/genesis"),
		)
		require.True(t, fake.simulated("s3:ListBucketVersions", "arn:aws:s3:::"+intentBucket))
		require.True(t, fake.simulated(
			"ssm:PutParameter", "arn:aws:ssm:eu-west-1:123456789012:parameter/prod/app/*",
		))
		require.True(t, fake.simulated("kms:CreateKey", "*"),
			"CreateKey has no resource type, so IAM evaluates it against *")
		require.True(t, fake.simulated(
			"logs:CreateLogGroup",
			"arn:aws:logs:eu-west-1:123456789012:log-group:/prod/enclave/traces/app:*",
		))
		require.False(t, fake.simulated("route53:GetChange", "arn:aws:route53:::change/*"),
			"Route53 is only needed with ACME")
	})

	t.Run("missing bucket parameter", func(t *testing.T) {
		p := &permissions{
			cfg:  testCfg,
			ssm:  NewSSM(&fakeSSM{}),
			iam:  &fakeIAM{},
			sts:  sts,
			pcr0: permissionTestPCR0,
		}
		err := p.preflight(context.Background())
		require.ErrorContains(t, err, testCfg.leaseBucketParam())
	})
}

func permissionFixture(acme bool) *permissions {
	cfg := *testCfg
	cfg.UseACME = acme
	cfg.AWSRegion = "eu-west-1"
	cfg.FQDN = "Enclave.Example.com"
	return &permissions{
		cfg: &cfg, pcr0: permissionTestPCR0,
		ssm: NewSSM(&fakeSSM{params: map[string]string{
			cfg.leaseBucketParam():   "lease-bucket",
			cfg.certBucketParam():    "cert-bucket",
			cfg.route53ZoneIDParam(): "/hostedzone/Z123",
		}}),
		sts: &fakeSTS{arn: "arn:aws:sts::123456789012:assumed-role/enclave/session"},
	}
}

func permissionContextValues(entries []iamtypes.ContextEntry) map[string][]string {
	values := make(map[string][]string)
	for _, entry := range entries {
		values[aws.ToString(entry.ContextKeyName)] = entry.ContextKeyValues
	}
	return values
}

func TestPermissionsConditionalPolicies(t *testing.T) {
	p := permissionFixture(true)
	seen := make(map[string]bool)
	fake := &fakeIAM{
		evaluate: func(action, resource string, entries []iamtypes.ContextEntry) iamtypes.PolicyEvaluationDecisionType {
			values := permissionContextValues(entries)
			region := "eu-west-1"
			if strings.HasPrefix(action, "route53:") {
				region = "us-east-1"
			}
			if !slices.Equal(values["aws:RequestedRegion"], []string{region}) ||
				!slices.Equal(
					values["aws:PrincipalArn"],
					[]string{"arn:aws:iam::123456789012:role/enclave"},
				) {
				return iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
			}
			switch action {
			case "kms:CreateKey", "kms:TagResource":
				if !slices.Equal(values["aws:RequestTag/ManagedBy"], []string{"enclave"}) ||
					!slices.Equal(values["aws:RequestTag/Deployment"], []string{"prod"}) ||
					!slices.Equal(values["aws:RequestTag/AppName"], []string{"app"}) {
					return iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
				}
				keys := []string{"AppName", "Deployment", "ManagedBy"}
				scenario := "genesis"
				if purpose, ok := values["aws:RequestTag/Purpose"]; ok {
					require.Equal(t, []string{"migration"}, purpose)
					keys = append(keys, "Purpose")
					scenario = "migration"
				}
				require.ElementsMatch(t, keys, values["aws:TagKeys"])
				seen[action+":"+scenario] = true
			case "route53:ChangeResourceRecordSets":
				if !slices.Equal(
					values["route53:ChangeResourceRecordSetsNormalizedRecordNames"],
					[]string{"_acme-challenge.enclave.example.com"},
				) ||
					!slices.Equal(
						values["route53:ChangeResourceRecordSetsRecordTypes"],
						[]string{"TXT"},
					) {
					return iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
				}
				actions := values["route53:ChangeResourceRecordSetsActions"]
				require.Len(t, actions, 1)
				require.Contains(t, []string{"UPSERT", "DELETE"}, actions[0])
				seen[actions[0]] = true
			case "logs:CreateLogGroup":
				if !strings.HasSuffix(resource, ":*") {
					return iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
				}
				seen["logs"] = true
			default:
				require.NotContains(t, values, "aws:RequestTag/ManagedBy")
				require.NotContains(t, values, "route53:ChangeResourceRecordSetsActions")
			}
			return iamtypes.PolicyEvaluationDecisionTypeAllowed
		},
	}
	p.iam = fake
	require.NoError(t, p.preflight(context.Background()))
	require.Len(t, seen, 7)

	fake.evaluate = func(action, _ string, entries []iamtypes.ContextEntry) iamtypes.PolicyEvaluationDecisionType {
		if action == "kms:CreateKey" &&
			slices.Contains(
				permissionContextValues(entries)["aws:RequestTag/Purpose"],
				"migration",
			) {
			return iamtypes.PolicyEvaluationDecisionTypeExplicitDeny
		}
		return iamtypes.PolicyEvaluationDecisionTypeAllowed
	}
	require.ErrorContains(
		t,
		p.preflight(context.Background()),
		"kms:CreateKey on * (explicitDeny)",
	)
}

func TestPermissionsConcreteResourceDenials(t *testing.T) {
	p := permissionFixture(true)
	intentBucket := migrationIntentBucketName(p.cfg, fakeSTSAccountID)
	tests := []struct{ name, resource, action string }{
		{"genesis record", "arn:aws:s3:::" + intentBucket + "/deployment-genesis", "s3:PutObject"},
		{"genesis lease", "arn:aws:s3:::lease-bucket/prod/app/lock/genesis", "s3:PutObject"},
		{
			"certificate lease",
			"arn:aws:s3:::lease-bucket/prod/app/lock/acme-renewal",
			"s3:DeleteObject",
		},
		{
			"migration lease",
			"arn:aws:s3:::lease-bucket/prod/app/lock/migration-" + permissionTestPCR0,
			"s3:PutObject",
		},
		{
			"certificate",
			"arn:aws:s3:::cert-bucket/prod/app/data/acme/Enclave.Example.com/cert",
			"s3:PutObject",
		},
		{"ACME account", "arn:aws:s3:::cert-bucket/prod/app/data/acme/account.key", "s3:GetObject"},
		{
			"commit pointer",
			"arn:aws:ssm:eu-west-1:123456789012:parameter/prod/app/locked/KMSKeyID/" + permissionTestPCR0,
			"ssm:PutParameter",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeIAM{
				evaluate: func(action, resource string, _ []iamtypes.ContextEntry) iamtypes.PolicyEvaluationDecisionType {
					if action == tc.action && resource == tc.resource {
						return iamtypes.PolicyEvaluationDecisionTypeExplicitDeny
					}
					return iamtypes.PolicyEvaluationDecisionTypeAllowed
				},
			}
			p.iam = fake
			err := p.preflight(context.Background())
			require.ErrorContains(t, err, tc.action+" on "+tc.resource+" (explicitDeny)")
		})
	}
	p = permissionFixture(false)
	fake := &fakeIAM{}
	p.iam = fake
	require.NoError(t, p.preflight(context.Background()))
	require.True(
		t,
		fake.simulated(
			"s3:PutObject",
			"arn:aws:s3:::cert-bucket/prod/app/data/self-signed/Enclave.Example.com/cert",
		),
	)
	require.False(
		t,
		fake.simulated("s3:PutObject", "arn:aws:s3:::cert-bucket/prod/app/data/acme/account.key"),
	)
}

func TestPermissionsPagination(t *testing.T) {
	p := permissionFixture(false)
	for _, denied := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "allowed second page", true: "denied second page"}[denied],
			func(t *testing.T) {
				fake := &fakeIAM{}
				fake.respond = func(in *iam.SimulatePrincipalPolicyInput) (*iam.SimulatePrincipalPolicyOutput, error) {
					out, err := (&fakeIAM{denied: map[string]bool{"ssm:PutParameter": denied}}).SimulatePrincipalPolicy(
						context.Background(),
						in,
					)
					if len(in.ActionNames) == 3 && in.ActionNames[0] == "ssm:GetParameter" {
						if in.Marker == nil {
							out.EvaluationResults = out.EvaluationResults[:1]
							out.IsTruncated, out.Marker = true, aws.String("next")
						} else {
							require.Equal(t, "next", *in.Marker)
							out.EvaluationResults = out.EvaluationResults[1:]
						}
					}
					return out, err
				}
				p.iam = fake
				err := p.preflight(context.Background())
				if denied {
					require.ErrorContains(t, err, "ssm:PutParameter")
				} else {
					require.NoError(t, err)
				}
				require.GreaterOrEqual(t, len(fake.calls), 2)
				first, second := *fake.calls[0], *fake.calls[1]
				require.Nil(t, first.Marker)
				require.Equal(t, "next", aws.ToString(second.Marker))
				second.Marker = nil
				require.Equal(t, first, second, "pagination must preserve the simulation inputs")
			},
		)
	}
}

func TestPermissionsIncompleteSimulation(t *testing.T) {
	p := permissionFixture(false)
	for _, tc := range []struct {
		name string
		out  *iam.SimulatePrincipalPolicyOutput
		want string
	}{
		{"no response", nil, "no simulation"},
		{"no results", &iam.SimulatePrincipalPolicyOutput{}, "IAM omitted ssm:GetParameter"},
		{"missing marker", &iam.SimulatePrincipalPolicyOutput{IsTruncated: true}, "incomplete pagination"},
		{"repeated marker", &iam.SimulatePrincipalPolicyOutput{IsTruncated: true, Marker: aws.String("same")}, "incomplete pagination"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeIAM{
				respond: func(*iam.SimulatePrincipalPolicyInput) (*iam.SimulatePrincipalPolicyOutput, error) {
					return tc.out, nil
				},
			}
			p.iam = fake
			require.ErrorContains(
				t,
				p.preflight(context.Background()),
				tc.want,
			)
			require.LessOrEqual(t, len(fake.calls), 2)
		})
	}
}

func TestPermissionsMissingContextDiagnostic(t *testing.T) {
	p := permissionFixture(false)
	fake := &fakeIAM{
		respond: func(in *iam.SimulatePrincipalPolicyInput) (*iam.SimulatePrincipalPolicyOutput, error) {
			out, err := (&fakeIAM{}).SimulatePrincipalPolicy(context.Background(), in)
			out.EvaluationResults[0].EvalDecision = iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
			out.EvaluationResults[0].MissingContextValues = []string{"aws:SourceIp"}
			out.EvaluationResults[0].ResourceSpecificResults = []iamtypes.ResourceSpecificResult{
				{MissingContextValues: []string{"aws:SourceVpce", "aws:SourceIp"}},
			}
			return out, err
		},
	}
	p.iam = fake
	require.ErrorContains(
		t,
		p.preflight(context.Background()),
		"missing simulation context: aws:SourceIp, aws:SourceVpce",
	)
}

func TestPermissionsPreflightRetries(t *testing.T) {
	throttled := &retry.MaxAttemptsError{Attempt: 3, Err: errors.New("Throttling: Rate exceeded")}

	t.Run("retries a simulation AWS left unanswered", func(t *testing.T) {
		p := permissionFixture(false)
		fake := &fakeIAM{}
		fake.respond = func(*iam.SimulatePrincipalPolicyInput) (*iam.SimulatePrincipalPolicyOutput, error) {
			fake.respond = nil
			return nil, throttled
		}
		p.iam = fake
		require.NoError(t, p.preflight(context.Background()))
	})

	t.Run("stops after bounded attempts", func(t *testing.T) {
		p := permissionFixture(false)
		fake := &fakeIAM{err: throttled}
		p.iam = fake
		err := p.preflight(context.Background())
		require.ErrorContains(t, err, "Rate exceeded")
		require.Len(t, fake.calls, preflightAttempts)
	})

	t.Run("does not retry a denial", func(t *testing.T) {
		p := permissionFixture(false)
		allowed := &fakeIAM{}
		p.iam = allowed
		require.NoError(t, p.preflight(context.Background()))

		denied := &fakeIAM{denied: map[string]bool{"s3:GetObjectRetention": true}}
		p.iam = denied
		require.ErrorContains(t, p.preflight(context.Background()), "is missing")
		require.Len(t, denied.calls, len(allowed.calls), "a denial is one pass, not a retry")
	})

	t.Run("does not retry an answered error", func(t *testing.T) {
		p := permissionFixture(false)
		fake := &fakeIAM{err: errors.New("AccessDenied: not authorized to SimulatePrincipalPolicy")}
		p.iam = fake
		require.ErrorContains(t, p.preflight(context.Background()), "AccessDenied")
		require.Len(t, fake.calls, 1)
	})

	t.Run("stops waiting when the context ends", func(t *testing.T) {
		p := permissionFixture(false)
		p.iam = &fakeIAM{err: throttled}
		p.backoff = time.Hour
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		require.ErrorContains(t, p.preflight(ctx), "Rate exceeded")
	})
}
