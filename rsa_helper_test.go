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

func TestRSAKeyPairToBase64(t *testing.T) {
	keyPair, err := ende.GenerateRSAKeypair()
	assert.NotNil(t, keyPair)
	assert.NoError(t, err)

	privateKey, err := ende.RSAPrivatePEMKeyToBase64(keyPair.Private)
	assert.NotEmpty(t, privateKey)
	assert.NoError(t, err)

	publicKey, err := ende.RSAPublicKeyToBase64(keyPair.Public)
	assert.NotEmpty(t, publicKey)
	assert.NoError(t, err)

	t.Logf("PRIVATE KEY:\n %s\n", privateKey)
	t.Logf("PUBLIC KEY:\n %s\n", publicKey)
}
