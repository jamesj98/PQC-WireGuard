/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// Test Kyber768 KEM Key Pair Generation
func TestNewPQCKEMKeypair(t *testing.T) {
	pubKey, privKey, err := newPQCKEMKeypair()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pubKey) == 0 {
		t.Fatal("Public key should not be empty")
	}
	if len(privKey) == 0 {
		t.Fatal("Private key should not be empty")
	}
}

// Test PQC Encapsulation & Decapsulation
func TestPQCEncapsulationDecapsulation(t *testing.T) {
	pubKey, privKey, err := newPQCKEMKeypair()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sharedSecret1, ciphertext, err := encapsulatePQCSecret(pubKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("Ciphertext should not be empty")
	}

	sharedSecret2, err := decapsulatePQCSecret(ciphertext, privKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Fatalf("Shared secrets do not match")
	}
}

// Create a random test device
func randDevice(t *testing.T) *Device {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tun := tuntest.NewChannelTUN()
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
	device.SetPrivateKey(sk)
	return device
}

// Main WireGuard handshake test with PQC integration
func TestNoiseHandshakeWithPQC(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)

	defer dev1.Close()
	defer dev2.Close()

	peer1, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	peer2, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	peer1.Start()
	peer2.Start()

	if !bytes.Equal(peer1.handshake.precomputedStaticStatic[:], peer2.handshake.precomputedStaticStatic[:]) {
		t.Fatal("Hybrid precomputed shared secret mismatch")
	}

	if !bytes.Equal(peer1.handshake.pqcSharedSecret[:], peer2.handshake.pqcSharedSecret[:]) {
		t.Fatal("PQC shared secret mismatch")
	}

	// Exchange initiation message
	t.Log("exchange initiation message")
	msg1, err := dev1.CreateMessageInitiation(peer2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := make([]byte, 0, 256)
	writer := bytes.NewBuffer(packet)
	err = binary.Write(writer, binary.LittleEndian, msg1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	peer := dev2.ConsumeMessageInitiation(msg1)
	if peer == nil {
		t.Fatal("handshake failed at initiation message")
	}

	// Ensure chain keys and handshake hashes match
	if !bytes.Equal(peer1.handshake.chainKey[:], peer2.handshake.chainKey[:]) {
		t.Fatal("Chain keys mismatch")
	}
	if !bytes.Equal(peer1.handshake.hash[:], peer2.handshake.hash[:]) {
		t.Fatal("Handshake hash mismatch")
	}

	// Exchange response message
	t.Log("exchange response message")
	msg2, err := dev2.CreateMessageResponse(peer1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	peer = dev1.ConsumeMessageResponse(msg2)
	if peer == nil {
		t.Fatal("handshake failed at response message")
	}

	// Ensure chain keys and handshake hashes match again
	if !bytes.Equal(peer1.handshake.chainKey[:], peer2.handshake.chainKey[:]) {
		t.Fatal("Chain keys mismatch after response")
	}
	if !bytes.Equal(peer1.handshake.hash[:], peer2.handshake.hash[:]) {
		t.Fatal("Handshake hash mismatch after response")
	}

	// Derive hybrid encryption keys
	t.Log("deriving hybrid keys")
	err = peer1.BeginSymmetricSession()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = peer2.BeginSymmetricSession()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
