package device

import (
	"testing"
	"bytes"

	"github.com/stretchr/testify/assert"
	"github.com/cloudflare/circl/kem/kyber/kyber768" /* Added by me */
)

// Test Kyber768 Key Pair Generation
func TestNewPQCKEMKeypair1(t *testing.T) {
	pubKey, privKey, err := newPQCKEMKeypair()
	assert.NoError(t, err, "Key pair generation should not fail")
	assert.NotEmpty(t, pubKey, "Public key should not be empty")
	assert.NotEmpty(t, privKey, "Private key should not be empty")
}

// Test Encapsulation
func TestEncapsulatePQCSecret(t *testing.T) {
	pubKey, _, err := newPQCKEMKeypair()
	assert.NoError(t, err)

	sharedSecret, ciphertext, err := encapsulatePQCSecret(pubKey)
	assert.NoError(t, err, "Encapsulation should not fail")
	assert.NotEmpty(t, sharedSecret, "Shared secret should not be empty")
	assert.NotEmpty(t, ciphertext, "Ciphertext should not be empty")
}

// Test Decapsulation
func TestDecapsulatePQCSecret(t *testing.T) {
    pubKey, privKey, err := newPQCKEMKeypair()
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    sharedSecret1, ciphertext, err := encapsulatePQCSecret(pubKey)
    if err != nil {
        t.Fatalf("unexpected error during encapsulation: %v", err)
    }

    // ✅ Log sizes before decapsulation
    t.Logf("Public Key Size: %d (Expected: %d)", len(pubKey), kyber768.PublicKeySize)
    t.Logf("Ciphertext Size: %d (Expected: %d)", len(ciphertext), kyber768.CiphertextSize)

    sharedSecret2, err := decapsulatePQCSecret(ciphertext, privKey)
    if err != nil {
        t.Fatalf("unexpected error during decapsulation: %v", err)
    }

    // ✅ Compare secrets correctly
    if !bytes.Equal(sharedSecret1, sharedSecret2) {
        t.Fatal("Shared secrets do not match")
    }
}

