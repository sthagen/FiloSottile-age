// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestVectors(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.age")
	for _, f := range files {
		name := strings.TrimSuffix(strings.TrimPrefix(f, "testdata/"), ".age")
		expectFailure := strings.HasPrefix(name, "fail_")
		t.Run(name, func(t *testing.T) {
			var identities []age.Identity
			ids, err := parseIdentitiesFile("testdata/" + name + "_key.txt")
			if err == nil {
				identities = append(identities, ids...)
			}
			password, err := ioutil.ReadFile("testdata/" + name + "_password.txt")
			if err == nil {
				i, err := age.NewScryptIdentity(string(password))
				if err != nil {
					t.Fatal(err)
				}
				identities = append(identities, i)
			}

			in, err := os.Open("testdata/" + name + ".age")
			if err != nil {
				t.Fatal(err)
			}
			r, err := age.Decrypt(in, identities...)
			if expectFailure {
				if err == nil {
					t.Fatal("expected Decrypt failure")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				out, err := ioutil.ReadAll(r)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("%s", out)
			}
		})
	}
}
