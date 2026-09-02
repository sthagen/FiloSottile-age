// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"age-keygen": main,
	})
}

func unwritable(t *testing.T) *os.File {
	t.Helper()
	name := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(name, nil, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if _, err := f.Write([]byte("x")); err == nil {
		t.Skip("writes to a read-only file descriptor succeed")
	}
	return f
}

func TestOutputWriteErrors(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		args  []string
		stdin string
	}{
		{"generate", nil, ""},
		{"generate PQ", []string{"-pq"}, ""},
		{"convert", []string{"-y"}, identity.String() + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stderr := &strings.Builder{}
			cmd := exec.Command("age-keygen", tt.args...)
			cmd.Stdin = strings.NewReader(tt.stdin)
			cmd.Stdout = unwritable(t)
			cmd.Stderr = stderr
			if err := cmd.Run(); err == nil {
				t.Error("age-keygen succeeded")
			}
			if !strings.Contains(stderr.String(), "failed to write output") {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}
