package runtime

import "context"

func StartClockSyncer(ctx context.Context) (context.Context, error) {
	// squash unused lint on darwin
	_ = verifyClockSourceEnabled()
	return ctx, nil
}
