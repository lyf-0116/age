// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18

package armor_test

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"strings"
	"testing"

	agetest "c2sp.org/CCTV/age"
	"filippo.io/age"
	"filippo.io/age/armor"
	"filippo.io/age/internal/format"
)

func ExampleNewWriter() {
	publicKey := "age1cy0su9fwf3gf9mw868g5yut09p6nytfmmnktexz2ya5uqg9vl9sss4euqm"
	recipient, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		log.Fatalf("Failed to parse public key %q: %v", publicKey, err)
	}

	buf := &bytes.Buffer{}
	armorWriter := armor.NewWriter(buf)

	w, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		log.Fatalf("Failed to create encrypted file: %v", err)
	}
	if _, err := io.WriteString(w, "Black lives matter."); err != nil {
		log.Fatalf("Failed to write to encrypted file: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("Failed to close encrypted file: %v", err)
	}

	if err := armorWriter.Close(); err != nil {
		log.Fatalf("Failed to close armor: %v", err)
	}

	fmt.Printf("%s[...]", buf.Bytes()[:35])
	// Output:
	// -----BEGIN AGE ENCRYPTED FILE-----
	// [...]
}

var privateKey = "AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU"

func ExampleNewReader() {
	fileContents := `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4YWdhZHZ0WG1PZldDT1hD
K3RPRzFkUlJnWlFBQlUwemtjeXFRMFp6V1VFCnRzZFV3a3Vkd1dSUWw2eEtrRkVv
SHcvZnp6Q3lqLy9HMkM4ZjUyUGdDZjQKLS0tIDlpVUpuVUQ5YUJyUENFZ0lNSTB2
ekUvS3E5WjVUN0F5ZWR1ejhpeU5rZUUKsvPGYt7vf0o1kyJ1eVFMz1e4JnYYk1y1
kB/RRusYjn+KVJ+KTioxj0THtzZPXcjFKuQ1
-----END AGE ENCRYPTED FILE-----`

	// DO NOT hardcode the private key. Store it in a secret storage solution,
	// on disk if the local machine is trusted, or have the user provide it.
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key %q: %v", privateKey, err)
	}

	out := &bytes.Buffer{}
	f := strings.NewReader(fileContents)
	armorReader := armor.NewReader(f)

	r, err := age.Decrypt(armorReader, identity)
	if err != nil {
		log.Fatalf("Failed to open encrypted file: %v", err)
	}
	if _, err := io.Copy(out, r); err != nil {
		log.Fatalf("Failed to read encrypted file: %v", err)
	}

	fmt.Printf("File contents: %q\n", out.Bytes())
	// Output:
	// File contents: "Black lives matter."
}

func TestArmor(t *testing.T) {
	t.Run("PartialLine", func(t *testing.T) { testArmor(t, 611) })
	t.Run("FullLine", func(t *testing.T) { testArmor(t, 10*format.BytesPerLine) })
}

func TestWriterLifecycle(t *testing.T) {
	t.Run("CloseWithoutWrite", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := armor.NewWriter(buf)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if want := armor.Header + "\n" + armor.Footer + "\n"; buf.String() != want {
			t.Errorf("output = %q, want %q", buf.String(), want)
		}
	})
	t.Run("WriteAfterClose", func(t *testing.T) {
		w := armor.NewWriter(io.Discard)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if n, err := w.Write([]byte("x")); n != 0 || err == nil {
			t.Errorf("Write after Close = %d, %v", n, err)
		}
	})
}

func testArmor(t *testing.T, size int) {
	buf := &bytes.Buffer{}
	w := armor.NewWriter(buf)
	plain := make([]byte, size)
	rand.Read(plain)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(buf.Bytes())
	if block == nil {
		t.Fatal("PEM decoding failed")
	}
	if len(block.Headers) != 0 {
		t.Error("unexpected headers")
	}
	if block.Type != "AGE ENCRYPTED FILE" {
		t.Errorf("unexpected type %q", block.Type)
	}
	if !bytes.Equal(block.Bytes, plain) {
		t.Error("PEM decoded value doesn't match")
	}
	if !bytes.Equal(buf.Bytes(), pem.EncodeToMemory(block)) {
		t.Error("PEM re-encoded value doesn't match")
	}

	r := armor.NewReader(buf)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Error("decoded value doesn't match")
	}
}

// TestArmorPayloadBoundaryMismatches exercises the two ways the armor layer's
// idea of where the payload ends can disagree with the payload layer's.
//
// The armor layer declares the end of the payload with a short (sub-column)
// base64 line followed by the footer, while the STREAM payload layer finds its
// own boundary from the last-chunk flag authenticated inside the ciphertext.
// Neither layer shares its boundary with the other, so a corrupted file can
// make the two disagree: the payload expecting more bytes than the armor
// delivered (truncation), or the armor delivering more bytes than the payload
// consumes (trailing data). Both mismatches must be rejected, never accepted
// with truncated or extra plaintext.
func TestArmorPayloadBoundaryMismatches(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	// Sizes chosen to cover an aligned final line, a partial final line, and
	// multiple STREAM chunks.
	for _, size := range []int{
		0,
		1,
		format.BytesPerLine - 1,
		format.BytesPerLine,
		10*format.BytesPerLine + 123,
		64*1024 + 1,
		2 * 64 * 1024,
	} {
		plain := make([]byte, size)
		rand.Read(plain)

		buf := &bytes.Buffer{}
		aw := armor.NewWriter(buf)
		w, err := age.Encrypt(aw, id.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(plain); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := aw.Close(); err != nil {
			t.Fatal(err)
		}
		file := buf.Bytes()

		// Sanity check: the intact file decrypts back to the plaintext.
		if out, err := io.ReadAll(decryptFile(t, file, id)); err != nil || !bytes.Equal(out, plain) {
			t.Fatalf("size %d: round trip failed: %v", size, err)
		}

		t.Run(fmt.Sprintf("Truncation/size%d", size), func(t *testing.T) {
			raw, err := io.ReadAll(armor.NewReader(bytes.NewReader(file)))
			if err != nil {
				t.Fatal(err)
			}
			// Re-armor prefixes of the decoded age file. The armor layer
			// accepts each as a complete file (short final line plus footer),
			// so only the payload layer can reject the truncation. Small files
			// are checked exhaustively; large files use a stride plus every
			// offset around the STREAM chunk boundaries.
			cuts := truncationCuts(len(raw))
			for _, cut := range cuts {
				truncated := rearmor(t, raw[:cut])
				out, err := io.ReadAll(decryptFile(t, truncated, id))
				if err == nil {
					t.Fatalf("cut %d of %d: truncated file accepted silently, got %d plaintext bytes", cut, len(raw), len(out))
				}
				msg := err.Error()
				if !strings.Contains(msg, "EOF") &&
					!strings.Contains(msg, "authenticate") &&
					!strings.Contains(msg, "header") &&
					!strings.Contains(msg, "chunk") &&
					!strings.Contains(msg, "payload") {
					t.Fatalf("cut %d of %d: unexpected error %q", cut, len(raw), err)
				}
			}
		})

		t.Run(fmt.Sprintf("TrailingData/size%d", size), func(t *testing.T) {
			// Insert extra full-width base64 lines between the payload and the
			// footer. The armor layer keeps serving them as payload after the
			// STREAM layer has already reached its authenticated last chunk.
			for _, extraLines := range []int{1, 2} {
				extra := bytes.Repeat([]byte(strings.Repeat("A", format.ColumnsPerLine)+"\n"), extraLines)
				injected := bytes.Replace(file, []byte(armor.Footer), append(extra, []byte(armor.Footer)...), 1)
				if bytes.Equal(injected, file) {
					t.Fatal("footer not found")
				}
				out, err := io.ReadAll(decryptFile(t, injected, id))
				if err == nil {
					t.Fatalf("%d extra line(s): trailing data accepted silently, got %d plaintext bytes", extraLines, len(out))
				}
				// The armor layer rejects the extra full-width line when the
				// footer is expected after the payload's short final line.
				if !strings.Contains(err.Error(), "armor") {
					t.Fatalf("%d extra line(s): error %q is not an armor error", extraLines, err)
				}
			}

			// Trailing data after the footer must be rejected as well.
			withGarbage := append(bytes.Clone(file), []byte("not-whitespace")...)
			if out, err := io.ReadAll(decryptFile(t, withGarbage, id)); err == nil {
				t.Fatalf("garbage after footer accepted silently, got %d plaintext bytes", len(out))
			}
		})
	}
}

func decryptFile(t *testing.T, file []byte, id *age.X25519Identity) io.Reader {
	t.Helper()
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(file)), id)
	if err != nil {
		// A failure while parsing the header or nonce is itself a valid
		// rejection of the malformed file; surface it through an error reader.
		return errReader{err: err}
	}
	return r
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func rearmor(t *testing.T, raw []byte) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	w := armor.NewWriter(buf)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// truncationCuts returns the prefix lengths to probe: every offset for small
// inputs, otherwise a fixed stride with exhaustive coverage around each
// encrypted STREAM chunk boundary (chunk size plus the 16-byte AEAD tag).
func truncationCuts(rawLen int) []int {
	const exhaustiveLimit = 4096
	const stride = 64
	const encChunkSize = 64*1024 + 16

	seen := make(map[int]bool)
	var cuts []int
	add := func(cut int) {
		if cut < 0 || cut >= rawLen || seen[cut] {
			return
		}
		seen[cut] = true
		cuts = append(cuts, cut)
	}

	if rawLen <= exhaustiveLimit {
		for cut := rawLen - 1; cut >= 0; cut-- {
			add(cut)
		}
		return cuts
	}

	for cut := rawLen - 1; cut >= 0; cut -= stride {
		add(cut)
	}
	for boundary := encChunkSize; boundary < rawLen; boundary += encChunkSize {
		for delta := -32; delta <= 32; delta++ {
			add(boundary + delta)
		}
	}
	return cuts
}

func FuzzMalleability(f *testing.F) {
	tests, err := fs.ReadDir(agetest.Vectors, ".")
	if err != nil {
		f.Fatal(err)
	}
	seeds := 0
	for _, test := range tests {
		contents, err := fs.ReadFile(agetest.Vectors, test.Name())
		if err != nil {
			f.Fatal(err)
		}
		header, contents, ok := bytes.Cut(contents, []byte("\n\n"))
		if !ok {
			f.Fatal("testkit file without header")
		}
		if bytes.Contains(header, []byte("armored: yes")) {
			f.Add(contents)
			seeds++
		}
	}
	if seeds == 0 {
		f.Fatal("no armored test vectors")
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := armor.NewReader(bytes.NewReader(data))
		content, err := io.ReadAll(r)
		if err != nil {
			if _, ok := err.(*armor.Error); !ok {
				t.Errorf("error type is %T: %v", err, err)
			}
			t.Skip()
		}
		buf := &bytes.Buffer{}
		w := armor.NewWriter(buf)
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(normalize(buf.Bytes()), normalize(data)) {
			t.Error("re-encoded output different from input")
		}
	})
}

func normalize(f []byte) []byte {
	f = bytes.TrimSpace(f)
	f = bytes.Replace(f, []byte("\r\n"), []byte("\n"), -1)
	return f
}
