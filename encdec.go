package ende

import (
	"context"
	"encoding/base32"
)

type Decrypt interface {
	Decrypt(ctx context.Context, data string) (string, error)
}

type Encrypt interface {
	Encrypt(ctx context.Context, data string) (string, error)
}

// Encoder is a standard interface to encode or decode payload.
type Encoder interface {
	EncodeToString(ctx context.Context, in []byte) (out string, err error)
	DecodeString(ctx context.Context, in string) (out []byte, err error)
}

// Base32 implements Encoder using base32
type Base32 struct{}

var _ Encoder = (*Base32)(nil)

func NewBase32() *Base32 {
	return &Base32{}
}

func (b *Base32) EncodeToString(ctx context.Context, in []byte) (out string, err error) {
	out = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(in)
	return
}

func (b *Base32) DecodeString(ctx context.Context, in string) (out []byte, err error) {
	out, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(in)
	return
}

func (b *Base32) String() string {
	return "base32"
}
