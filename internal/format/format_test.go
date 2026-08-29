// Copyright 2021 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18

package format_test

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age/internal/format"
)

func TestStanzaMarshal(t *testing.T) {
	s := &format.Stanza{
		Type: "test",
		Args: []string{"1", "2", "3"},
		Body: nil, // empty
	}
	buf := &bytes.Buffer{}
	s.Marshal(buf)
	if exp := "-> test 1 2 3\n\n"; buf.String() != exp {
		t.Errorf("wrong empty stanza encoding: expected %q, got %q", exp, buf.String())
	}

	buf.Reset()
	s.Body = []byte("AAA")
	s.Marshal(buf)
	if exp := "-> test 1 2 3\nQUFB\n"; buf.String() != exp {
		t.Errorf("wrong normal stanza encoding: expected %q, got %q", exp, buf.String())
	}

	buf.Reset()
	s.Body = bytes.Repeat([]byte("A"), format.BytesPerLine)
	s.Marshal(buf)
	if exp := "-> test 1 2 3\nQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n\n"; buf.String() != exp {
		t.Errorf("wrong 64 columns stanza encoding: expected %q, got %q", exp, buf.String())
	}
}

func TestParseLimits(t *testing.T) {
	const (
		intro          = "age-encryption.org/v1\n"
		maxHeaderBytes = 2 << 20
	)
	footer := "--- " + format.EncodeToString(make([]byte, 32)) + "\n"

	t.Run("header size", func(t *testing.T) {
		makeHeader := func(size int) []byte {
			const opening = "-> test "
			fixed := len(intro) + len(opening) + len("\n\n") + len(footer)
			return []byte(intro + opening + strings.Repeat("a", size-fixed) + "\n\n" + footer)
		}

		if _, _, err := format.Parse(bytes.NewReader(makeHeader(maxHeaderBytes))); err != nil {
			t.Fatalf("maximum-size header was rejected: %v", err)
		}
		_, _, err := format.Parse(bytes.NewReader(makeHeader(maxHeaderBytes + 1)))
		if err == nil || !strings.Contains(err.Error(), "header exceeds 2 MiB") {
			t.Fatalf("unexpected oversized-header error: %v", err)
		}
		var parseError *format.ParseError
		if !errors.As(err, &parseError) {
			t.Errorf("oversized-header error is not a ParseError: %T", err)
		}
		if strings.Count(err.Error(), "parsing age header") != 1 {
			t.Errorf("oversized-header error nests ParseError prefixes: %v", err)
		}

		// An intro line that exceeds the limit before any newline.
		_, _, err = format.Parse(bytes.NewReader(bytes.Repeat([]byte{'a'}, maxHeaderBytes+1)))
		if err == nil || !strings.Contains(err.Error(), "header exceeds 2 MiB") {
			t.Fatalf("unexpected oversized-intro error: %v", err)
		}
		if !errors.As(err, &parseError) {
			t.Errorf("oversized-intro error is not a ParseError: %T", err)
		}
		if strings.Count(err.Error(), "parsing age header") != 1 {
			t.Errorf("oversized-intro error nests ParseError prefixes: %v", err)
		}
	})

	t.Run("recipient stanzas", func(t *testing.T) {
		makeHeader := func(stanzas int) []byte {
			return []byte(intro + strings.Repeat("-> test\n\n", stanzas) + footer)
		}

		if _, _, err := format.Parse(bytes.NewReader(makeHeader(1024))); err != nil {
			t.Fatalf("header with 1024 stanzas was rejected: %v", err)
		}
		_, _, err := format.Parse(bytes.NewReader(makeHeader(1025)))
		if err == nil || !strings.Contains(err.Error(), "more than 1024 recipient stanzas") {
			t.Fatalf("unexpected stanza-limit error: %v", err)
		}
	})

	t.Run("recipient stanza arguments", func(t *testing.T) {
		makeHeader := func(args int) []byte {
			return []byte(intro + "-> test" + strings.Repeat(" a", args) + "\n\n" + footer)
		}

		if _, _, err := format.Parse(bytes.NewReader(makeHeader(128))); err != nil {
			t.Fatalf("stanza with 128 arguments was rejected: %v", err)
		}
		_, _, err := format.Parse(bytes.NewReader(makeHeader(129)))
		if err == nil {
			t.Fatal("stanza with 129 arguments was accepted")
		}
	})

	t.Run("payload is not limited", func(t *testing.T) {
		header := []byte(intro + "-> test\n\n" + footer)
		want := bytes.Repeat([]byte("p"), maxHeaderBytes+1)
		_, payload, err := format.Parse(io.MultiReader(bytes.NewReader(header), bytes.NewReader(want)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(payload)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Error("payload was truncated or modified")
		}
	})

	t.Run("bufio reader is preserved", func(t *testing.T) {
		header := []byte(intro + "-> test\n\n" + footer)
		input := bufio.NewReader(bytes.NewReader(append(header, "payload"...)))
		_, payload, err := format.Parse(input)
		if err != nil {
			t.Fatal(err)
		}
		if payload != input {
			t.Error("Parse did not return the input bufio.Reader")
		}
	})
}

func FuzzMalleability(f *testing.F) {
	tests, err := filepath.Glob("../../testdata/testkit/*")
	if err != nil {
		f.Fatal(err)
	}
	for _, test := range tests {
		contents, err := os.ReadFile(test)
		if err != nil {
			f.Fatal(err)
		}
		_, contents, ok := bytes.Cut(contents, []byte("\n\n"))
		if !ok {
			f.Fatal("testkit file without header")
		}
		f.Add(contents)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		h, payload, err := format.Parse(bytes.NewReader(data))
		if err != nil {
			if h != nil {
				t.Error("h != nil on error")
			}
			if payload != nil {
				t.Error("payload != nil on error")
			}
			t.Skip()
		}
		w := &bytes.Buffer{}
		if err := h.Marshal(w); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, payload); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(w.Bytes(), data) {
			t.Error("Marshal output different from input")
		}
	})
}
