// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agessh_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"reflect"
	"testing"

	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

func TestSSHRSARoundTrip(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&pk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	r, err := agessh.NewRSARecipient(pub)
	if err != nil {
		t.Fatal(err)
	}
	i, err := agessh.NewRSAIdentity(pk)
	if err != nil {
		t.Fatal(err)
	}

	// TODO: replace this with (and go-diff) with go-cmp.
	if !reflect.DeepEqual(r, i.Recipient()) {
		t.Fatalf("i.Recipient is different from r")
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatal(err)
	}
	stanzas, err := r.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	out, err := i.Unwrap(stanzas)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fileKey, out) {
		t.Errorf("invalid output: %x, expected %x", out, fileKey)
	}
}

func TestSSHRSAFingerprintCollision(t *testing.T) {
	targetKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	targetIdentity, err := agessh.NewRSAIdentity(targetKey)
	if err != nil {
		t.Fatal(err)
	}

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherIdentity, err := agessh.NewRSAIdentity(otherKey)
	if err != nil {
		t.Fatal(err)
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatal(err)
	}
	stanzas, err := targetIdentity.Recipient().Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	collision, err := otherIdentity.Recipient().Wrap(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	collision[0].Args[0] = stanzas[0].Args[0]

	out, err := targetIdentity.Unwrap(append(collision, stanzas...))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileKey, out) {
		t.Errorf("invalid output: %x, expected %x", out, fileKey)
	}
}

func TestSSHEd25519RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	r, err := agessh.NewEd25519Recipient(sshPubKey)
	if err != nil {
		t.Fatal(err)
	}
	i, err := agessh.NewEd25519Identity(priv)
	if err != nil {
		t.Fatal(err)
	}

	// TODO: replace this with (and go-diff) with go-cmp.
	if !reflect.DeepEqual(r, i.Recipient()) {
		t.Fatalf("i.Recipient is different from r")
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatal(err)
	}
	stanzas, err := r.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	out, err := i.Unwrap(stanzas)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fileKey, out) {
		t.Errorf("invalid output: %x, expected %x", out, fileKey)
	}
}

func TestSSHEd25519FingerprintCollision(t *testing.T) {
	_, targetKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	targetIdentity, err := agessh.NewEd25519Identity(targetKey)
	if err != nil {
		t.Fatal(err)
	}

	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherIdentity, err := agessh.NewEd25519Identity(otherKey)
	if err != nil {
		t.Fatal(err)
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatal(err)
	}
	stanzas, err := targetIdentity.Recipient().Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	collision, err := otherIdentity.Recipient().Wrap(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	collision[0].Args[0] = stanzas[0].Args[0]

	out, err := targetIdentity.Unwrap(append(collision, stanzas...))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileKey, out) {
		t.Errorf("invalid output: %x, expected %x", out, fileKey)
	}
}

func TestEncryptedSSHIdentityMismatch(t *testing.T) {
	announcedPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	embeddedPub, embeddedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	announcedKey, err := ssh.NewPublicKey(announcedPub)
	if err != nil {
		t.Fatal(err)
	}
	embeddedKey, err := ssh.NewPublicKey(embeddedPub)
	if err != nil {
		t.Fatal(err)
	}

	passphrase := []byte("passphrase")
	block, err := ssh.MarshalPrivateKeyWithPassphrase(embeddedPriv, "", passphrase)
	if err != nil {
		t.Fatal(err)
	}
	prompts := 0
	i, err := agessh.NewEncryptedSSHIdentity(announcedKey, pem.EncodeToMemory(block), func() ([]byte, error) {
		prompts++
		return passphrase, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	announcedRecipient, err := agessh.NewEd25519Recipient(announcedKey)
	if err != nil {
		t.Fatal(err)
	}
	embeddedRecipient, err := agessh.NewEd25519Recipient(embeddedKey)
	if err != nil {
		t.Fatal(err)
	}
	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatal(err)
	}
	stanzas, err := announcedRecipient.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	embeddedStanzas, err := embeddedRecipient.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	stanzas = append(stanzas, embeddedStanzas...)

	for attempt := 1; attempt <= 2; attempt++ {
		_, err := i.Unwrap(stanzas)
		if err == nil || err.Error() != "mismatched private and public SSH key" {
			t.Fatalf("attempt %d: unexpected error: %v", attempt, err)
		}
		if prompts != attempt {
			t.Fatalf("attempt %d: passphrase callback invoked %d times", attempt, prompts)
		}
	}
}
