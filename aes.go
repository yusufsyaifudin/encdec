package ende

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type AES struct {
	chiperAEAD cipher.AEAD
	encoder    Encoder
}

var _ Encrypt = (*AES)(nil)
var _ Decrypt = (*AES)(nil)

// NewAES use GenerateAESKey to generate AES symmetric secret key
func NewAES(secretKey []byte) (*AES, error) {
	if len(secretKey) <= 0 || secretKey == nil {
		return nil, fmt.Errorf("aes secret key must not be nil")
	}

	c, err := aes.NewCipher(secretKey)
	if err != nil {
		err = fmt.Errorf("prepare aes chiper error: %w", err)
		return nil, err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		err = fmt.Errorf("error prepare Galois/Counter Mode: %w", err)
		return nil, err
	}

	instance := &AES{
		chiperAEAD: gcm,
		encoder:    NewBase32(),
	}

	return instance, nil
}

func (a *AES) Decrypt(ctx context.Context, ciphertext string) (string, error) {
	ciphertextBytes, err2 := a.encoder.DecodeString(ctx, ciphertext)
	if err2 != nil {
		err2 = fmt.Errorf("cannot decode ciphertext from string: %w", err2)
		return "", err2
	}

	nonceSize := a.chiperAEAD.NonceSize()
	if len(ciphertextBytes) < nonceSize {
		return "", fmt.Errorf("length of ciphertext (%d) less than nonce size (%d)",
			len(ciphertextBytes), nonceSize,
		)
	}

	nonce, ciphertextBytes := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]
	plainTextBytes, err2 := a.chiperAEAD.Open(nil, nonce, ciphertextBytes, nil)
	if err2 != nil {
		return "", fmt.Errorf("error decrypt: %w", err2)
	}

	return string(plainTextBytes), nil
}

func (a *AES) Encrypt(ctx context.Context, data string) (ciphertext string, err error) {
	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, a.chiperAEAD.NonceSize())

	// populates our nonce with a cryptographically secure
	// random sequence
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		err = fmt.Errorf("error populate nonce: %w", err)
		return "", err
	}

	sealed := a.chiperAEAD.Seal(nonce, nonce, []byte(data), nil)
	ciphertext, err = a.encoder.EncodeToString(ctx, sealed)
	return
}
