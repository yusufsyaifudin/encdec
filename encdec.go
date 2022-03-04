package ende

import "context"

type Decrypt interface {
	Decrypt(ctx context.Context, data string) (string, error)
}

type Encrypt interface {
	Encrypt(ctx context.Context, data string) (string, error)
}
