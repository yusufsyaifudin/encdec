package encdec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yusufsyaifudin/encdec"
)

func TestGenerateRSAKeypair(t *testing.T) {
	keyPair, err := encdec.GenerateRSAKeypair()
	assert.NotNil(t, keyPair)
	assert.NoError(t, err)
}

func TestRSAKeyPairToBase64(t *testing.T) {
	keyPair, err := encdec.GenerateRSAKeypair()
	assert.NotNil(t, keyPair)
	assert.NoError(t, err)

	privateKey, err := encdec.RSAPrivatePEMKeyToBase64(keyPair.Private)
	assert.NotEmpty(t, privateKey)
	assert.NoError(t, err)

	publicKey, err := encdec.RSAPublicKeyToBase64(keyPair.Public)
	assert.NotEmpty(t, publicKey)
	assert.NoError(t, err)

	t.Logf("PRIVATE KEY:\n %s\n", privateKey)
	t.Logf("PUBLIC KEY:\n %s\n", publicKey)
}
