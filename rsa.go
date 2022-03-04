package encdec

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// ---------- Encrypt method

type RSAEncrypt struct {
	PublicKey *rsa.PublicKey
}

var _ Encrypt = (*RSAEncrypt)(nil)

func NewRSAEncrypt(publicKeyBase64 string) (*RSAEncrypt, error) {
	publicKeyBase64 = strings.TrimSpace(publicKeyBase64)
	if publicKeyBase64 == "" {
		return nil, fmt.Errorf("public key is nil")
	}

	pubKey, err := base64.RawURLEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("cannot decode public key from base64: %w", err)
	}

	block, _ := pem.Decode(pubKey)

	// Confirm we got the PUBLIC KEY block type
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}

	// Convert to rsa
	rsaPubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.parse pki public key: %w", err)
	}

	return &RSAEncrypt{PublicKey: rsaPubKey}, nil
}

func (r *RSAEncrypt) Encrypt(ctx context.Context, data string) (string, error) {
	// https://en.wikipedia.org/wiki/Hybrid_cryptosystem
	// to support large size string payload, we use combination AES and RSA
	// ** Obtains Alice's public key. It's already under RSAEncrypt.PublicKey
	// ** Generates a fresh symmetric key for the data encapsulation scheme.
	aesKey, err := GenerateAESKey()
	if err != nil {
		return "", err
	}

	aesAlg, err := NewAES(aesKey)
	if err != nil {
		return "", err
	}

	// ** Encrypts the message under the data encapsulation scheme, using the symmetric key just generated.
	ciphertext, err := aesAlg.Encrypt(ctx, data)
	if err != nil {
		return "", err
	}

	// ** Encrypts the symmetric key under the key encapsulation scheme, using Alice's public key.
	hash := sha512.New()
	symmetricKey, err := rsa.EncryptOAEP(hash, rand.Reader, r.PublicKey, aesKey, nil)
	if err != nil {
		return "", fmt.Errorf("cannot encrypt using public key: %w", err)
	}

	symmetricKeyText := base64.RawURLEncoding.EncodeToString(symmetricKey)

	// ** Sends both of these ciphertexts to Alice.
	out := fmt.Sprintf("%s.%s", symmetricKeyText, ciphertext)
	return out, nil
}

// ------ Decrypt method

type RSADecrypt struct {
	PrivateKey *rsa.PrivateKey
}

var _ Decrypt = (*RSADecrypt)(nil)

func NewRSADecrypt(privateKeyBase64 string) (*RSADecrypt, error) {
	privateKeyBase64 = strings.TrimSpace(privateKeyBase64)
	if privateKeyBase64 == "" {
		return nil, fmt.Errorf("private key is nil")
	}

	privateKey, err := base64.RawURLEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("cannot decode private key from base64: %w", err)
	}

	block, _ := pem.Decode(privateKey)

	// Confirm we got the PRIVATE KEY block type
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}

	// Convert to rsa
	rsaPubKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.parse private key: %w", err)
	}

	return &RSADecrypt{PrivateKey: rsaPubKey}, nil
}

func (r *RSADecrypt) Decrypt(ctx context.Context, ciphertext string) (string, error) {
	str := strings.Split(strings.TrimSpace(ciphertext), ".")
	if len(str) != 2 {
		return "", fmt.Errorf("encrypted text must contain exactly 2 block, but current payload contain %d block", len(str))
	}

	// ** Uses her private key to decrypt the symmetric key contained in the key encapsulation segment.
	symmetricKey := str[0]
	encryptedText := str[1]

	symmetricKeyDecoded, err := base64.RawURLEncoding.DecodeString(symmetricKey)
	if err != nil {
		return "", fmt.Errorf("not valid base64 string: %w", err)
	}

	hash := sha512.New()
	symmetricKeyForEncryption, err := rsa.DecryptOAEP(hash, rand.Reader, r.PrivateKey, symmetricKeyDecoded, nil)
	if err != nil {
		return "", fmt.Errorf("cannot decrypt: %w", err)
	}

	aesAlg, err := NewAES(symmetricKeyForEncryption)
	if err != nil {
		return "", err
	}

	// ** Uses this symmetric key to decrypt the message contained in the data encapsulation segment.
	plaintext, err := aesAlg.Decrypt(ctx, encryptedText)
	return plaintext, err
}
