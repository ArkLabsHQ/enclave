package runtime

import "context"

func StartClockSyncer(ctx context.Context, _ *Config) (context.Context, error) {
	return ctx, nil
}
