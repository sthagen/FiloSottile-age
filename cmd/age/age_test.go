// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"age": func() {
			testOnlyConfigureScryptIdentity = func(r *age.ScryptRecipient) {
				r.SetWorkFactor(10)
			}
			testOnlyFixedRandomWord = "four"
			main()
		},
		"age-plugin-test": func() {
			p, _ := plugin.New("test")
			p.HandleRecipient(func(data []byte) (age.Recipient, error) {
				return testPlugin{}, nil
			})
			p.HandleIdentity(func(data []byte) (age.Identity, error) {
				return testPlugin{}, nil
			})
			os.Exit(p.Main())
		},
	})
}

type testPlugin struct{}

func (testPlugin) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	return []*age.Stanza{{Type: "test", Body: fileKey}}, nil
}

func (testPlugin) Unwrap(ss []*age.Stanza) ([]byte, error) {
	if len(ss) == 1 && ss[0].Type == "test" {
		return ss[0].Body, nil
	}
	return nil, age.ErrIncorrectIdentity
}

func paddedFile(pad int, lines string) io.Reader {
	const chunkSize = 1 << 16
	chunk := strings.Repeat("#\n", chunkSize/2)
	var readers []io.Reader
	if pad%2 != 0 {
		readers = append(readers, strings.NewReader("\n"))
		pad--
	}
	for ; pad > chunkSize; pad -= chunkSize {
		readers = append(readers, strings.NewReader(chunk))
	}
	return io.MultiReader(append(readers,
		strings.NewReader(chunk[:pad]), strings.NewReader(lines))...)
}

func TestParseFileSizeLimit(t *testing.T) {
	const sizeLimit = 16 << 20
	const identity = "AGE-SECRET-KEY-1D6K0SGAX3NU66R4GYFZY0UQWCLM3UUSF3CXLW4KXZM342WQSJ82QKU59QJ\n"
	const recipient = "age1cy0su9fwf3gf9mw868g5yut09p6nytfmmnktexz2ya5uqg9vl9sss4euqm\n"
	tests := []struct {
		name  string
		entry string
		parse func(*testing.T, io.Reader) (int, error)
	}{
		{"identities", identity, func(_ *testing.T, r io.Reader) (int, error) {
			ids, err := parseIdentities(r)
			return len(ids), err
		}},
		{"recipients", recipient, func(t *testing.T, r io.Reader) (int, error) {
			name := filepath.Join(t.TempDir(), "recipients.txt")
			f, err := os.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(f, r); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			recipients, err := parseRecipientsFile(name)
			return len(recipients), err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/at limit", func(t *testing.T) {
			r := paddedFile(sizeLimit-4*len(tt.entry), strings.Repeat(tt.entry, 4))
			n, err := tt.parse(t, r)
			if err != nil {
				t.Fatal(err)
			}
			if n != 4 {
				t.Errorf("got %d entries, want 4", n)
			}
		})
		t.Run(tt.name+"/over limit", func(t *testing.T) {
			r := paddedFile(sizeLimit-4*len(tt.entry), strings.Repeat(tt.entry, 8))
			if _, err := tt.parse(t, r); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestUnsupportedSSHKey(t *testing.T) {
	tests := []struct {
		name, key, want string
		ok              bool
	}{
		{
			"truncated Ed25519",
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9pO5pz22JZEasoS2LEWWvJiUYI9M6l1uZc31FG",
			"", false,
		},
		{
			"type-only RSA",
			"ssh-rsa AAAAB3NzaC1yc2E=",
			"", false,
		},
		{
			"small RSA",
			"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCxlfoYpG04TTnmjocggQZI5l0fjvaUMky1ZD5zwktDKAgBj441OAtFj/3m7Gujpxx/8w3jjJoUXVtU+NFbcC972ROpPI4aPq3OR5SmuuR5bCr6efeZlyAEMY/DmbkeUe1TrvdU3VMDGJAvEEzT1wzokKt9PiwbV2jNkdPjaG5LDQ==",
			"ssh-rsa", true,
		},
		{
			"invalid Ed25519 point",
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
			"", false,
		},
		{
			"unknown type",
			"totally-not-a-key AAAAEXRvdGFsbHktbm90LWEta2V5",
			"totally-not-a-key", true,
		},
		{
			"ECDSA",
			"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOSh0Qo5zaBE33EiJnxwIBuZml9Nt9rCfvGi++FniWSk8X/10EO4E7KMgqGLlkCTDNIcbuKcsgfMw1/tifB8aTc=",
			"ecdsa-sha2-nistp256", true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := unsupportedSSHKey(tt.key)
			if got != tt.want || ok != tt.ok {
				t.Errorf("unsupportedSSHKey() = %q, %v; want %q, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

var buildExtraCommands = sync.OnceValue(func() error {
	bindir := filepath.SplitList(os.Getenv("PATH"))[0]
	// Build age-keygen and age-plugin-pq into the test binary directory.
	cmd := exec.Command("go", "build", "-o", bindir)
	if testing.CoverMode() != "" {
		cmd.Args = append(cmd.Args, "-cover")
	}
	cmd.Args = append(cmd.Args, "filippo.io/age/cmd/age-keygen")
	cmd.Args = append(cmd.Args, "filippo.io/age/extra/age-plugin-pq")
	cmd.Args = append(cmd.Args, "filippo.io/age/cmd/age-plugin-batchpass")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
})

func TestScript(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
		Setup: func(e *testscript.Env) error {
			return buildExtraCommands()
		},
		// TODO: enable AGEDEBUG=plugin without breaking stderr checks.
	})
}
