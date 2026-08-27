package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type ssmW struct {
	ssm SSMAPI
}

type Param struct {
	Name  string
	Value string
}

type SSM interface {
	Set(ctx context.Context, key, val string, opts ...SSMSetOption) error
	SetIfAbsent(ctx context.Context, key, val string, opts ...SSMSetOption) (bool, error)
	MustGet(ctx context.Context, key string) (string, error)
	MayGet(ctx context.Context, key string) (string, error)
	ListParams(ctx context.Context, prefix string) ([]Param, error)
}

type SSMSetOptions struct {
	tier ssmtypes.ParameterTier
}

type SSMSetOption func(*SSMSetOptions)

func WithAdvancedTier() SSMSetOption {
	return func(so *SSMSetOptions) {
		so.tier = ssmtypes.ParameterTierAdvanced
	}
}

func NewSSM(ssm SSMAPI) SSM {
	return &ssmW{ssm: ssm}
}

func (s *ssmW) Set(ctx context.Context, key, val string, opts ...SSMSetOption) error {
	_, err := s.put(ctx, key, val, true, opts...)
	return err
}

// SetIfAbsent creates a parameter without overwriting an existing value. SSM
// applies Overwrite=false atomically, so it can be used as a cross-process
// write-once commit point.
func (s *ssmW) SetIfAbsent(
	ctx context.Context,
	key, val string,
	opts ...SSMSetOption,
) (bool, error) {
	return s.put(ctx, key, val, false, opts...)
}

func (s *ssmW) put(
	ctx context.Context,
	key, val string,
	overwrite bool,
	opts ...SSMSetOption,
) (bool, error) {
	so := &SSMSetOptions{tier: ssmtypes.ParameterTierStandard}

	for _, opt := range opts {
		opt(so)
	}

	if _, err := s.ssm.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(key),
		Value:     aws.String(val),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(overwrite),
		Tier:      so.tier,
	}); err != nil {
		var exists *ssmtypes.ParameterAlreadyExists
		if !overwrite && errors.As(err, &exists) {
			return false, nil
		}
		return false, fmt.Errorf("ssm put-parameter %s: %w", key, err)
	}
	return true, nil
}

func (s *ssmW) MustGet(ctx context.Context, key string) (string, error) {
	out, err := s.ssm.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(key),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		return "", fmt.Errorf("ssm get-parameter %s: %w", key, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", fmt.Errorf("parameter %s has no value", key)
	}
	value := strings.TrimSpace(*out.Parameter.Value)
	if value == "" || value == "UNSET" {
		return "", fmt.Errorf("parameter %s is unset", key)
	}
	return value, nil
}

func (s *ssmW) MayGet(ctx context.Context, key string) (string, error) {
	out, err := s.ssm.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(key),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		var pnf *ssmtypes.ParameterNotFound
		if errors.As(err, &pnf) {
			return "", nil
		}
		return "", fmt.Errorf("ssm get-parameter %s: %w", key, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", nil
	}
	v := strings.TrimSpace(*out.Parameter.Value)
	if v == "" || v == "UNSET" {
		return "", nil
	}
	return v, nil
}

func (s *ssmW) ListParams(ctx context.Context, prefix string) ([]Param, error) {
	paramsByPath := func(nextToken *string) ([]Param, *string, error) {
		out, err := s.ssm.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{
			Path:           aws.String(prefix),
			Recursive:      aws.Bool(false),
			WithDecryption: aws.Bool(true),
			NextToken:      nextToken,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("ssm get-parameters-by-path %s: %w", prefix, err)
		}

		params := make([]Param, 0, len(out.Parameters))

		for _, p := range out.Parameters {
			if p.Name == nil || p.Value == nil {
				continue
			}
			params = append(params, Param{Name: *p.Name, Value: *p.Value})
		}

		return params, out.NextToken, nil
	}

	params, nextToken, err := paramsByPath(nil)
	if err != nil {
		return nil, err
	}

	for nextToken != nil {
		ps, nt, err := paramsByPath(nextToken)
		if err != nil {
			return nil, err
		}
		params = append(params, ps...)
		nextToken = nt
	}

	return params, nil
}
