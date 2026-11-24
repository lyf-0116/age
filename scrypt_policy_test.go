// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestScryptMinWorkFactorPolicy(t *testing.T) {
	const (
		password  = "test passphrase"
		plaintext = "minimum work factor test"
	)

	encrypt := func(t *testing.T, logN int) []byte {
		t.Helper()
		r, err := age.NewScryptRecipient(password)
		if err != nil {
			t.Fatal(err)
		}
		r.SetWorkFactor(logN)

		var buf bytes.Buffer
		w, err := age.Encrypt(&buf, r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(plaintext)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	const fileLogN = 10
	file := encrypt(t, fileLogN)

	t.Run("accepted at minimum", func(t *testing.T) {
		i, err := age.NewScryptIdentity(password)
		if err != nil {
			t.Fatal(err)
		}
		i.SetMinWorkFactor(fileLogN)

		r, err := age.Decrypt(bytes.NewReader(file), i)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != plaintext {
			t.Fatalf("got %q, want %q", got, plaintext)
		}
	})

	t.Run("rejected below minimum", func(t *testing.T) {
		i, err := age.NewScryptIdentity(password)
		if err != nil {
			t.Fatal(err)
		}
		i.SetMinWorkFactor(fileLogN + 1)

		_, err = age.Decrypt(bytes.NewReader(file), i)
		if err == nil {
			t.Fatal("expected decryption to fail")
		}
		if !strings.Contains(err.Error(), "scrypt work factor too small: 10") {
			t.Errorf("unexpected error: %v", err)
		}
		if errors.Is(err, age.ErrIncorrectIdentity) {
			t.Error("rejected work factor must not be reported as an incorrect identity")
		}
	})

	t.Run("default accepts low work factor", func(t *testing.T) {
		lowFile := encrypt(t, 1)
		i, err := age.NewScryptIdentity(password)
		if err != nil {
			t.Fatal(err)
		}
		r, err := age.Decrypt(bytes.NewReader(lowFile), i)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != plaintext {
			t.Fatalf("got %q, want %q", got, plaintext)
		}
	})
}

func TestScryptMinWorkFactorCheckedBeforeBody(t *testing.T) {
	i, err := age.NewScryptIdentity("test passphrase")
	if err != nil {
		t.Fatal(err)
	}
	i.SetMinWorkFactor(11)

	_, err = i.Unwrap([]*age.Stanza{{
		Type: "scrypt",
		Args: []string{"AAAAAAAAAAAAAAAAAAAAAA", "10"},
	}})
	if err == nil || err.Error() != "scrypt work factor too small: 10" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScryptMinWorkFactorSetterBounds(t *testing.T) {
	for _, logN := range []int{-1, 0, 1, 30, 31} {
		i, err := age.NewScryptIdentity("test passphrase")
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				got := recover()
				wantPanic := logN < 1 || logN > 30
				if (got != nil) != wantPanic {
					t.Errorf("SetMinWorkFactor(%d): panic = %v, want panic = %v", logN, got, wantPanic)
				}
			}()
			i.SetMinWorkFactor(logN)
		}()
	}
}

func TestScryptWorkFactorRange(t *testing.T) {
	i, err := age.NewScryptIdentity("test passphrase")
	if err != nil {
		t.Fatal(err)
	}
	i.SetMinWorkFactor(10)
	i.SetMaxWorkFactor(11)

	for _, tc := range []struct {
		logN string
		want string
	}{
		{"9", "scrypt work factor too small: 9"},
		{"10", "invalid scrypt recipient block: incorrect file key size"},
		{"11", "invalid scrypt recipient block: incorrect file key size"},
		{"12", "scrypt work factor too large: 12"},
	} {
		_, err := i.Unwrap([]*age.Stanza{{
			Type: "scrypt",
			Args: []string{"AAAAAAAAAAAAAAAAAAAAAA", tc.logN},
		}})
		if err == nil || err.Error() != tc.want {
			t.Errorf("logN=%s: got %v, want %q", tc.logN, err, tc.want)
		}
	}
}
