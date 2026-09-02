package inspect

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"filippo.io/age/internal/format"
	"filippo.io/age/internal/stream"
)

// buildFile serializes a header with the given stanza types,
// followed by the minimal valid encrypted payload (a 16-byte stream nonce
// and a single empty ChaCha20-Poly1305 chunk).
func buildFile(t *testing.T, stanzaTypes ...string) []byte {
	t.Helper()
	hdr := &format.Header{MAC: make([]byte, 32)}
	for _, stanzaType := range stanzaTypes {
		hdr.Recipients = append(hdr.Recipients, &format.Stanza{Type: stanzaType})
	}
	buf := &bytes.Buffer{}
	if err := hdr.Marshal(buf); err != nil {
		t.Fatalf("Header.Marshal: %v", err)
	}
	// Append nonce (16 bytes) + poly1305 tag for empty chunk (16 bytes).
	buf.Write(make([]byte, 16+16))
	return buf.Bytes()
}

func TestInspectTagStanzas(t *testing.T) {
	tests := []struct {
		stanzaType string
		want       string
	}{
		{stanzaType: "p256tag", want: "no"},
		{stanzaType: "mlkem768p256tag", want: "yes"},
	}
	for _, tt := range tests {
		t.Run(tt.stanzaType, func(t *testing.T) {
			f := buildFile(t, tt.stanzaType)
			md, err := Inspect(bytes.NewReader(f), int64(len(f)))
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}
			if got := md.Postquantum; got != tt.want {
				t.Errorf("Postquantum = %q, want %q", got, tt.want)
			}
			if len(md.StanzaTypes) != 1 || md.StanzaTypes[0] != tt.stanzaType {
				t.Errorf("StanzaTypes = %v, want [%q]", md.StanzaTypes, tt.stanzaType)
			}
		})
	}
}

func TestInspectPostquantum(t *testing.T) {
	tests := []struct {
		name        string
		stanzaTypes []string
		want        string
	}{
		{"postquantum", []string{"mlkem768x25519"}, "yes"},
		{"classical", []string{"X25519"}, "no"},
		{"both", []string{"mlkem768x25519", "X25519"}, "no"},
		{"unrecognized", []string{"tpm-ecc"}, "unknown"},
		{"postquantum and unrecognized", []string{"mlkem768x25519", "tpm-ecc"}, "unknown"},
		{"unrecognized and postquantum", []string{"tpm-ecc", "mlkem768x25519"}, "unknown"},
		{"classical and unrecognized", []string{"X25519", "tpm-ecc"}, "no"},
		{"unrecognized and classical", []string{"tpm-ecc", "X25519"}, "no"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := buildFile(t, tt.stanzaTypes...)
			md, err := Inspect(bytes.NewReader(f), int64(len(f)))
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}
			if md.Postquantum != tt.want {
				t.Errorf("Postquantum = %q, want %q", md.Postquantum, tt.want)
			}
		})
	}
}

// readAfterEOFReader returns io.EOF along with the last of its data, and then
// more data from subsequent Reads, like a terminal that received Ctrl-D
// followed by more input.
type readAfterEOFReader struct {
	data []byte
	eof  bool
}

func (r *readAfterEOFReader) Read(p []byte) (int, error) {
	if r.eof {
		return copy(p, "\n"), nil
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		r.eof = true
		return n, io.EOF
	}
	return n, nil
}

func TestInspectReadAfterEOF(t *testing.T) {
	f := buildFile(t, "X25519")
	r := &readAfterEOFReader{data: f}
	md, err := Inspect(r, -1)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if md.Version != "age-encryption.org/v1" {
		t.Errorf("Version = %q, want age-encryption.org/v1", md.Version)
	}
	// If the reads after EOF were counted towards the file size, the extra
	// bytes would show up in the payload size.
	if md.Sizes.MinPayload != 0 {
		t.Errorf("MinPayload = %d, want 0", md.Sizes.MinPayload)
	}
}

func TestStreamOverhead(t *testing.T) {
	tests := []struct {
		payloadSize int64
		want        int64
		wantErr     bool
	}{
		{payloadSize: 0, wantErr: true},
		{payloadSize: 15, wantErr: true},
		{payloadSize: 16, wantErr: true},
		{payloadSize: 16 + 15, wantErr: true},
		{payloadSize: 16 + 16, want: 16 + 16}, // empty plaintext
		{payloadSize: 16 + 1 + 16, want: 16 + 16},
		{payloadSize: 16 + stream.ChunkSize + 16, want: 16 + 16},
		{payloadSize: 16 + stream.ChunkSize + 16 + 1, wantErr: true},
		{payloadSize: 16 + stream.ChunkSize + 16 + 15, wantErr: true},
		{payloadSize: 16 + stream.ChunkSize + 16 + 16, wantErr: true}, // empty final chunk
		{payloadSize: 16 + stream.ChunkSize + 16 + 1 + 16, want: 16 + 16 + 16},
	}
	for _, tt := range tests {
		name := "payloadSize=" + fmt.Sprint(tt.payloadSize)
		t.Run(name, func(t *testing.T) {
			got, gotErr := streamOverhead(tt.payloadSize)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("streamOverhead() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("streamOverhead() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("streamOverhead() = %v, want %v", got, tt.want)
			}
		})
	}
}
