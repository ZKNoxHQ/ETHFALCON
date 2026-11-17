package main

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/ZKNoxHQ/ETHFALCON/falcon"
)

func keypair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	pk, sk, err := falcon.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if len(pk) != falcon.PublicKeySize || len(sk) != falcon.SecretKeySize {
		t.Fatalf("key lengths: pk=%d sk=%d", len(pk), len(sk))
	}
	return pk, sk
}

func randomMessage(t *testing.T, n int) []byte {
	t.Helper()
	msg := make([]byte, n)
	if _, err := rand.Read(msg); err != nil {
		t.Fatal(err)
	}
	return msg
}

func sign(t *testing.T, msg, sk []byte) []byte {
	t.Helper()
	sm, err := falcon.SignMessage(msg, sk)
	if err != nil {
		t.Fatalf("SignMessage(%d bytes): %v", len(msg), err)
	}
	return sm
}

func TestSizes(t *testing.T) {
	if falcon.PublicKeySize != 897 || falcon.SecretKeySize != 1281 || falcon.SignatureSize != 690 {
		t.Fatalf("unexpected sizes pk=%d sk=%d sig=%d", falcon.PublicKeySize, falcon.SecretKeySize, falcon.SignatureSize)
	}
}

func TestRoundTripMessageLengths(t *testing.T) {
	pk, sk := keypair(t)
	for _, n := range []int{0, 1, 1023, 1024, 1025, 1330, 5000, 8000} {
		msg := randomMessage(t, n)
		sm := sign(t, msg, sk)

		if len(sm) <= 2+falcon.NonceSize+n || len(sm) > n+falcon.SignatureSize {
			t.Fatalf("n=%d: signed message length %d out of range", n, len(sm))
		}
		if sigLen := int(sm[0])<<8 | int(sm[1]); len(sm) != 2+falcon.NonceSize+n+sigLen {
			t.Fatalf("n=%d: signed message length %d does not match header %d", n, len(sm), sigLen)
		}
		if !bytes.Equal(sm[2+falcon.NonceSize:2+falcon.NonceSize+n], msg) {
			t.Fatalf("n=%d: attached message differs", n)
		}

		ok, err := falcon.VerifySignature(sm, msg, pk)
		if err != nil || !ok {
			t.Fatalf("n=%d: valid signature rejected: ok=%v err=%v", n, ok, err)
		}

		// Wrong expected message: crypto_sign_open succeeds, comparison fails.
		other := append(append([]byte{}, msg...), 0x42)
		if ok, _ := falcon.VerifySignature(sm, other, pk); ok {
			t.Fatalf("n=%d: signature accepted for a different message", n)
		}
		if n > 0 {
			if ok, _ := falcon.VerifySignature(sm, msg[:n-1], pk); ok {
				t.Fatalf("n=%d: signature accepted for a truncated message", n)
			}
		}
	}
}

func TestEmptyMessageNil(t *testing.T) {
	pk, sk := keypair(t)
	sm := sign(t, nil, sk)
	if ok, err := falcon.VerifySignature(sm, nil, pk); err != nil || !ok {
		t.Fatalf("nil message: ok=%v err=%v", ok, err)
	}
	if ok, err := falcon.VerifySignature(sm, []byte{}, pk); err != nil || !ok {
		t.Fatalf("empty message: ok=%v err=%v", ok, err)
	}
}

func TestTruncatedAndEmptySignature(t *testing.T) {
	pk, sk := keypair(t)
	msg := randomMessage(t, 32)
	sm := sign(t, msg, sk)

	cases := map[string][]byte{
		"nil":          nil,
		"empty":        {},
		"one byte":     sm[:1],
		"header only":  sm[:2+falcon.NonceSize],
		"header+1":     sm[:2+falcon.NonceSize+1],
		"minus one":    sm[:len(sm)-1],
		"minus sig":    sm[:2+falcon.NonceSize+len(msg)],
		"zeroes":       make([]byte, len(sm)),
		"length 0xfff": append([]byte{0xff, 0xff}, sm[2:]...),
	}
	for name, s := range cases {
		ok, err := falcon.VerifySignature(s, msg, pk)
		if ok {
			t.Errorf("%s: accepted", name)
		}
		if err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestTamperedSignature(t *testing.T) {
	pk, sk := keypair(t)
	msg := randomMessage(t, 100)
	sm := sign(t, msg, sk)

	// Flip one bit in every byte position: length, nonce, message, signature.
	for i := range sm {
		bad := append([]byte{}, sm...)
		bad[i] ^= 0x01
		if ok, _ := falcon.VerifySignature(bad, msg, pk); ok {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}

	// Extra trailing byte.
	if ok, _ := falcon.VerifySignature(append(append([]byte{}, sm...), 0), msg, pk); ok {
		t.Fatal("signature with trailing byte accepted")
	}
}

func TestWrongPublicKey(t *testing.T) {
	pk, sk := keypair(t)
	msg := randomMessage(t, 64)
	sm := sign(t, msg, sk)

	for _, n := range []int{0, 1, falcon.PublicKeySize - 1, falcon.PublicKeySize + 1, 2 * falcon.PublicKeySize} {
		badPk := make([]byte, n)
		copy(badPk, pk)
		ok, err := falcon.VerifySignature(sm, msg, badPk)
		if ok || err == nil {
			t.Errorf("pk length %d: ok=%v err=%v", n, ok, err)
		}
	}
	if ok, err := falcon.VerifySignature(sm, msg, nil); ok || err == nil {
		t.Errorf("nil pk: ok=%v err=%v", ok, err)
	}

	// Right length, wrong header byte.
	badPk := append([]byte{}, pk...)
	badPk[0] ^= 0xff
	if ok, err := falcon.VerifySignature(sm, msg, badPk); ok || err == nil {
		t.Errorf("bad pk header: ok=%v err=%v", ok, err)
	}

	// Another valid key.
	pk2, _ := keypair(t)
	if ok, _ := falcon.VerifySignature(sm, msg, pk2); ok {
		t.Error("signature accepted under another key")
	}
}

func TestWrongSecretKey(t *testing.T) {
	_, sk := keypair(t)
	msg := randomMessage(t, 16)

	for _, n := range []int{0, 1, falcon.SecretKeySize - 1, falcon.SecretKeySize + 1} {
		badSk := make([]byte, n)
		copy(badSk, sk)
		if sm, err := falcon.SignMessage(msg, badSk); err == nil || sm != nil {
			t.Errorf("sk length %d: expected error, got %d bytes", n, len(sm))
		}
	}
	if _, err := falcon.SignMessage(msg, nil); err == nil {
		t.Error("nil sk: expected error")
	}

	// Right length, wrong header byte.
	badSk := append([]byte{}, sk...)
	badSk[0] ^= 0xff
	if _, err := falcon.SignMessage(msg, badSk); err == nil {
		t.Error("bad sk header: expected error")
	}
	// Empty message with an invalid key must still error cleanly.
	if _, err := falcon.SignMessage(nil, nil); err == nil {
		t.Error("nil message, nil sk: expected error")
	}
}

func TestLongAttachedMessage(t *testing.T) {
	// Regression for H-1: a valid signed message longer than the old fixed
	// 1024-byte recovery buffer used to overflow the Go heap.
	pk, sk := keypair(t)
	msg := randomMessage(t, 8000)
	sm := sign(t, msg, sk)
	if ok, err := falcon.VerifySignature(sm, msg[:16], pk); ok || err != nil {
		t.Fatalf("long attached message vs short expected: ok=%v err=%v", ok, err)
	}
}

func TestConcurrent(t *testing.T) {
	pk, sk := keypair(t)
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 4; i++ {
				msg := make([]byte, 100*g+i)
				sm, err := falcon.SignMessage(msg, sk)
				if err != nil {
					errs <- err.Error()
					return
				}
				if ok, err := falcon.VerifySignature(sm, msg, pk); !ok || err != nil {
					errs <- "verify failed"
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
