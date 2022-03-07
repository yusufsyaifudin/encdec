package ende_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yusufsyaifudin/ende"
)

func TestGenerateRSAKeypair(t *testing.T) {
	keyPair, err := ende.GenerateRSAKeypair()
	assert.NotNil(t, keyPair)
	assert.NoError(t, err)
}

func TestRSAKeyPairEncoded(t *testing.T) {
	keyPair, err := ende.GenerateRSAKeypair()
	assert.NotNil(t, keyPair)
	assert.NoError(t, err)

	base32 := ende.NewBase32()

	privateKey, err := ende.RSAPrivateEncode(base32, keyPair.Private)
	assert.NotEmpty(t, privateKey)
	assert.NoError(t, err)

	publicKey, err := ende.RSAPublicKeyEncode(base32, keyPair.Public)
	assert.NotEmpty(t, publicKey)
	assert.NoError(t, err)

	t.Logf("PRIVATE KEY:\n %s\n", privateKey)
	t.Logf("PUBLIC KEY:\n %s\n", publicKey)
}
