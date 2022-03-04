package ende

import (
	"crypto/rand"
	"fmt"
)

// --- Helper AES

func GenerateAESKey() ([]byte, error) {
	randGen := make([]byte, 32)
	_, err := rand.Read(randGen)
	if err != nil {
		return nil, fmt.Errorf("error generate AES key: %w", err)
	}

	return randGen, nil
}
