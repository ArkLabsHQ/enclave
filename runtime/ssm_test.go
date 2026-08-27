package runtime

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/stretchr/testify/require"
)

type atomicPutSSM struct {
	fakeSSM
	mu sync.Mutex
}

func (f *atomicPutSSM) PutParameter(
	ctx context.Context,
	in *ssm.PutParameterInput,
	opts ...func(*ssm.Options),
) (*ssm.PutParameterOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fakeSSM.PutParameter(ctx, in, opts...)
}

func TestSSMSetAndGet(t *testing.T) {
	ctx := context.Background()
	ssm := NewSSM(&fakeSSM{})

	require.NoError(t, ssm.Set(ctx, "/app/key", "one"))
	require.NoError(t, ssm.Set(ctx, "/app/key", " two\n"))

	got, err := ssm.MustGet(ctx, "/app/key")
	require.NoError(t, err)
	if got != "two" {
		t.Fatalf("got %q, want %q", got, "two")
	}
}

func TestSSMSetIfAbsentIsAtomic(t *testing.T) {
	ctx := context.Background()
	api := &atomicPutSSM{}
	store := NewSSM(api)

	const contenders = 32
	results := make(chan bool, contenders)
	errs := make(chan error, contenders)
	var wg sync.WaitGroup
	for i := range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			created, err := store.SetIfAbsent(ctx, "/app/commit", fmt.Sprintf("key-%d", i))
			results <- created
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	winners := 0
	for err := range errs {
		require.NoError(t, err)
	}
	for created := range results {
		if created {
			winners++
		}
	}
	require.Equal(t, 1, winners)

	got, err := store.MustGet(ctx, "/app/commit")
	require.NoError(t, err)
	require.Contains(t, got, "key-")
}

func TestSSMGet(t *testing.T) {
	ctx := context.Background()
	ssm := NewSSM(&fakeSSM{params: map[string]string{
		"/set":   " value\n",
		"/empty": "",
		"/space": " \n\t",
		"/unset": "UNSET",
	}})

	t.Run("must get returns trimmed value", func(t *testing.T) {
		got, err := ssm.MustGet(ctx, "/set")
		require.NoError(t, err)
		if got != "value" {
			t.Fatalf("got %q, want %q", got, "value")
		}
	})

	t.Run("must get rejects unset", func(t *testing.T) {
		for _, key := range []string{"/missing", "/empty", "/space", "/unset"} {
			t.Run(key, func(t *testing.T) {
				_, err := ssm.MustGet(ctx, key)
				require.Error(t, err)
			})
		}
	})

	t.Run("may get treats unset as absent", func(t *testing.T) {
		for _, key := range []string{"/missing", "/empty", "/space", "/unset"} {
			t.Run(key, func(t *testing.T) {
				got, err := ssm.MayGet(ctx, key)
				require.NoError(t, err)
				if got != "" {
					t.Fatalf("got %q, want empty", got)
				}
			})
		}
	})

	t.Run("may get returns trimmed value", func(t *testing.T) {
		got, err := ssm.MayGet(ctx, "/set")
		require.NoError(t, err)
		if got != "value" {
			t.Fatalf("got %q, want %q", got, "value")
		}
	})
}

func TestSSMListParams(t *testing.T) {
	ctx := context.Background()
	ssm := NewSSM(&fakeSSM{
		pages: [][]ssmtypes.Parameter{
			{
				{Name: aws.String("/app/a"), Value: aws.String("one")},
				{Name: nil, Value: aws.String("skip")},
				{Name: aws.String("/app/skip")},
			},
			{
				{Name: aws.String("/app/b"), Value: aws.String("two")},
			},
		},
		nextTokens: []string{"next"},
	})

	got, err := ssm.ListParams(ctx, "/app")
	require.NoError(t, err)
	if len(got) != 2 {
		t.Fatalf("got %d params, want 2", len(got))
	}
	if got[0].Name != "/app/a" || got[0].Value != "one" {
		t.Fatalf("got first param %#v", got[0])
	}
	if got[1].Name != "/app/b" || got[1].Value != "two" {
		t.Fatalf("got second param %#v", got[1])
	}
}
