package falcon

/*
#cgo CFLAGS: -I${SRCDIR}/nistfalcon/src
#cgo LDFLAGS: -L${SRCDIR}/nistfalcon/build
#cgo LDFLAGS: -lfalcon

#include <stdlib.h>
#include "api.h"

// Wrapper for crypto_sign_keypair, crypto_sign, crypto_sign_open

*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

const (
	// PublicKeySize is the length of an encoded public key (CRYPTO_PUBLICKEYBYTES).
	PublicKeySize = C.CRYPTO_PUBLICKEYBYTES
	// SecretKeySize is the length of an encoded secret key (CRYPTO_SECRETKEYBYTES).
	SecretKeySize = C.CRYPTO_SECRETKEYBYTES
	// SignatureSize is the maximum number of bytes SignMessage adds to a
	// message (CRYPTO_BYTES): a 2-byte length, the NonceSize-byte nonce and
	// the compressed signature. A signed message is therefore at most
	// len(message)+SignatureSize bytes long.
	SignatureSize = C.CRYPTO_BYTES
	// NonceSize is the length of the nonce (salt) in a signed message.
	NonceSize = 40

	// signedMessageHeaderSize is the 2-byte signature length plus the nonce.
	signedMessageHeaderSize = 2 + NonceSize
)

var (
	ErrInvalidPublicKeyLength = fmt.Errorf("falcon: public key must be %d bytes", PublicKeySize)
	ErrInvalidSecretKeyLength = fmt.Errorf("falcon: secret key must be %d bytes", SecretKeySize)
	ErrSignedMessageTooShort  = errors.New("falcon: signed message too short")
)

// rngMu serialises the C calls that draw randomness. randombytes() in the C
// library may keep process-global state, which is not safe for concurrent use.
var rngMu sync.Mutex

// ucharPtr returns a C pointer to the first byte of b. For an empty slice it
// returns a pointer to a 1-byte dummy, so that callers passing a zero length
// never index b[0].
func ucharPtr(b []byte) *C.uchar {
	if len(b) == 0 {
		var dummy [1]byte
		return (*C.uchar)(unsafe.Pointer(&dummy[0]))
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

// GenerateKeypair generates a public/private keypair
func GenerateKeypair() ([]byte, []byte, error) {
	pk := make([]byte, PublicKeySize)
	sk := make([]byte, SecretKeySize)

	rngMu.Lock()
	ret := C.crypto_sign_keypair(ucharPtr(pk), ucharPtr(sk))
	rngMu.Unlock()
	if ret != 0 {
		return nil, nil, fmt.Errorf("keypair generation failed: %d", int(ret))
	}

	return pk, sk, nil
}

// SignMessage signs a message using the private key. It returns the NIST
// signed message: signature length (2 bytes), nonce, message, signature.
func SignMessage(message []byte, sk []byte) ([]byte, error) {
	if len(sk) != SecretKeySize {
		return nil, ErrInvalidSecretKeyLength
	}

	sm := make([]byte, signedMessageHeaderSize+len(message)+SignatureSize)
	var smlen C.ulonglong

	rngMu.Lock()
	ret := C.crypto_sign(ucharPtr(sm), &smlen, ucharPtr(message), C.ulonglong(len(message)), ucharPtr(sk))
	rngMu.Unlock()
	if ret != 0 {
		return nil, fmt.Errorf("signing failed: %d", int(ret))
	}
	if uint64(smlen) > uint64(len(sm)) {
		return nil, fmt.Errorf("signing failed: signed message length %d exceeds buffer", uint64(smlen))
	}

	return sm[:smlen:smlen], nil
}

// VerifySignature verifies a signed message (as returned by SignMessage)
// against the expected message and a public key.
func VerifySignature(signature []byte, message []byte, pk []byte) (bool, error) {
	if len(pk) != PublicKeySize {
		return false, ErrInvalidPublicKeyLength
	}
	// 2-byte length, nonce, and at least the 1-byte signature header.
	if len(signature) < signedMessageHeaderSize+1 {
		return false, ErrSignedMessageTooShort
	}

	// The recovered message is a sub-slice of the signed message.
	m := make([]byte, len(signature))
	var mlen C.ulonglong

	ret := C.crypto_sign_open(ucharPtr(m), &mlen, ucharPtr(signature), C.ulonglong(len(signature)), ucharPtr(pk))
	if ret != 0 {
		return false, fmt.Errorf("verification failed: %d", int(ret))
	}
	if uint64(mlen) > uint64(len(m)) {
		return false, fmt.Errorf("verification failed: recovered message length %d exceeds buffer", uint64(mlen))
	}

	// Compare the recovered message with the original message
	return bytes.Equal(m[:mlen], message), nil
}
