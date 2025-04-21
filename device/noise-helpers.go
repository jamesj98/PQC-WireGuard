/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"os"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"hash"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber768" /* Added by me */
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

/* KDF related functions.
 * HMAC-based Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869
 */

func HMAC1(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func HMAC2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func KDF1(t0 *[blake2s.Size]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func KDF3(t0, t1, t2 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	HMAC2(t2, prk[:], t1[:], []byte{0x3})
	setZero(prk[:])
}

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

/* This function is not used as pervasively as it should because this is mostly impossible in Go at the moment */
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

func (sk *NoisePrivateKey) clamp() {
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
}

func newPrivateKey() (sk NoisePrivateKey, err error) {
	_, err = rand.Read(sk[:])
	sk.clamp()
	return
}

func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

var errInvalidPublicKey = errors.New("invalid public key")

func (sk *NoisePrivateKey) sharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte, err error) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarMult(&ss, ask, apk)
	if isZero(ss[:]) {
		return ss, errInvalidPublicKey
	}
	return ss, nil
}

// Generate a PQC keypair
func newPQCKEMKeypair() (publicKey []byte, privateKey []byte, err error) {
    kem := kyber768.Scheme()

    // Generate key pair
    pk, sk, err := kem.GenerateKeyPair()
    if err != nil {
        return nil, nil, fmt.Errorf("key pair generation error: %v", err)
    }

    // Convert structured keys to byte slices
    publicKey, err = pk.MarshalBinary()
    if err != nil {
        return nil, nil, fmt.Errorf("public key marshal error: %v", err)
    }

    privateKey, err = sk.MarshalBinary()
    if err != nil {
        return nil, nil, fmt.Errorf("private key marshal error: %v", err)
    }

    return publicKey, privateKey, nil
}


func encapsulatePQCSecret(pqcPublicKey []byte) (sharedSecret []byte, ciphertext []byte, err error) {
    kem := kyber768.Scheme()

    fmt.Printf("Encapsulating with PQC Public Key Size: %d (Expected: 1184)\n", len(pqcPublicKey))

    // Convert byte slice to a structured PublicKey
    pk, err := kem.UnmarshalBinaryPublicKey(pqcPublicKey)
    if err != nil {
        return nil, nil, fmt.Errorf("public key unmarshal error: %v", err)
    }

    // Perform encapsulation
    ciphertext, sharedSecret, err = kem.Encapsulate(pk)

    if err != nil {
        return nil, nil, fmt.Errorf("encapsulation error: %v", err)
    }

    fmt.Printf("Encapsulation Output - Shared Secret Size: %d (Expected: 32)\n", len(sharedSecret))
    fmt.Printf("Encapsulation Output - Ciphertext Size: %d (Expected: 1088)\n", len(ciphertext))

    return sharedSecret, ciphertext, nil
}






// Decapsulate a PQC shared secret
func decapsulatePQCSecret(ciphertext, pqcPrivateKey []byte) (sharedSecret []byte, err error) {
    kem := kyber768.Scheme() // ✅ Use Kyber768 Scheme

    // Convert byte slice to a structured PrivateKey
    sk, err := kem.UnmarshalBinaryPrivateKey(pqcPrivateKey)
    if err != nil {
        return nil, err
    }

    // Perform decapsulation
    sharedSecret, err = kem.Decapsulate(sk, ciphertext)
    if err != nil {
        return nil, fmt.Errorf("decapsulation failed: %v", err)
    }

    return sharedSecret, nil
}

func HybridKDF(finalKeySend, finalKeyReceive *[32]byte, chainKey, pqcSecret []byte, isInitiator bool) {
    var intermediateKey [32]byte

    // Mix both chainKey and pqcSecret
    mac := hmac.New(func() hash.Hash {
        h, _ := blake2s.New256(nil)
        return h
    }, chainKey)

    mac.Write(pqcSecret)
    mac.Sum(intermediateKey[:0])

    // Expand into two keys
    var key1, key2 [32]byte
    HMAC1(&key1, intermediateKey[:], []byte{0x1})
    HMAC2(&key2, intermediateKey[:], key1[:], []byte{0x2})

    // Ensure initiator and responder use opposite keys
    if isInitiator {
        *finalKeySend = key1  // Initiator encrypts with key1
        *finalKeyReceive = key2 // Initiator decrypts with key2
    } else {
        *finalKeySend = key2  // Responder encrypts with key2
        *finalKeyReceive = key1 // Responder decrypts with key1
    }

    fmt.Printf("[DEBUG] HybridKDF Output (isInitiator=%v) - Send Key: %x, Receive Key: %x\n",
        isInitiator, *finalKeySend, *finalKeyReceive)
    os.Stdout.Sync()

    // Zero out memory for security
    setZero(intermediateKey[:])
}
