// Copyright (C) 2019-2021 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package cparalithium

import (
	"bytes"
	"errors"
	"runtime"
)

// NOTE: cgo go code couldn't compile with the flags: -Wmissing-prototypes and -Wno-unused-paramete

//#cgo CFLAGS: -Wall -Wextra -Wpedantic -Wredundant-decls -Wshadow -Wvla -Wpointer-arith -Wno-unused-parameter  -O3 -fomit-frame-pointer -DDILITHIUM_MODE=3
//#include "api.h"
import "C"

type (
	// ParalithiumSignature is the signature used by the paralithium scheme
	ParalithiumSignature [3389]byte
	// ParalithiumPublicKey is the public key used by the paralithium scheme
	ParalithiumPublicKey [1952]byte
	// ParalithiumPrivateKey is the private key used by the paralithium scheme
	ParalithiumPrivateKey [4032]byte
	// ParalithiumSeed is a seed data used to generate paralithium keypairs with rho
	ParalithiumSeed [32]byte
)

// Exporting to be used when attempting to wrap and use this package.
const (
	// SigSize is the size of a paralithium signature
	SigSize = C.pqcrystals_dilithium3_BYTES
	// PublicKeySize is the size of a paralithium public key
	PublicKeySize = C.pqcrystals_dilithium3_PUBLICKEYBYTES
	// PrivateKeySize is the size of a paralithium private key
	PrivateKeySize = C.pqcrystals_dilithium3_SECRETKEYBYTES
	// SeedSize is the size of seed used to init keys with rho
	SeedSize = C.pqcrystals_dilithium3_SEED
)

func init() {
	// Check sizes of structs
	_ = [SigSize]byte(ParalithiumSignature{})
	_ = [PublicKeySize]byte(ParalithiumPublicKey{})
	_ = [PrivateKeySize]byte(ParalithiumPrivateKey{})
	_ = [SeedSize]byte(ParalithiumSeed{})
}

// NewKeys Generates a paralithium private and public key .
func NewKeys() (ParalithiumPrivateKey, ParalithiumPublicKey) {
	pk := ParalithiumPublicKey{}
	sk := ParalithiumPrivateKey{}
	C.pqcrystals_dilithium3_ref_keypair((*C.uchar)(&(pk[0])), (*C.uchar)(&(sk[0])))

	return sk, pk
}

// NewKeys Generates a paralithium private and public key using a seed as rho.
func NewKeysWithRho(seed ParalithiumSeed) (ParalithiumPrivateKey, ParalithiumPublicKey) {
	pk := ParalithiumPublicKey{}
	sk := ParalithiumPrivateKey{}

	C.pqcrystals_dilithium3_ref_keypair_rho((*C.uchar)(&(pk[0])), (*C.uchar)(&(sk[0])), (*C.uchar)(&(seed[0])))
	runtime.KeepAlive(seed)

	return sk, pk
}

// SignBytes receives bytes and signs over them.
// the size of the signature should conform with dil3Signature.
// Note: the signature verifies the size of the output signature, bad code underneath will panic.
func (sk *ParalithiumPrivateKey) SignBytes(data []byte) []byte {
	dataLen := len(data)
	cdata := (*C.uchar)(C.NULL)
	if dataLen != 0 {
		cdata = (*C.uchar)(&data[0])
	}
	var sig ParalithiumSignature
	var smlen C.size_t
	C.pqcrystals_dilithium3_ref_signature((*C.uchar)(&sig[0]), (*C.size_t)(&smlen), (*C.uchar)(cdata), (C.size_t)(dataLen), (*C.uchar)(&(sk[0])))
	if uint64(smlen) != uint64(SigSize) {
		panic("const value of dilithium signature had changed.")
	}
	runtime.KeepAlive(data)
	return sig[:]
}

// ErrBadParalithiumSignature indicates signature isn't valid.
var ErrBadParalithiumSignature = errors.New("bad signature")

// ErrPkDoesNotContainRho indicates that the pk does not contain the correct rho value
var ErrPkDoesNotContainRho = errors.New("public key does not contain the correct rho value")

// VerifyRho verifies that the public key was created using a given seed.
func (v *ParalithiumPublicKey) VerifyRho(seed ParalithiumSeed) error {
	if !bytes.Equal(seed[:], v[:SeedSize]) {
		return ErrPkDoesNotContainRho
	}
	return nil
}

// VerifyBytes follows dilithium algorithm to verify a signature.
func (v *ParalithiumPublicKey) VerifyBytes(data []byte, sig []byte) error {
	sigLen := len(sig)
	if sigLen == 0 {
		return ErrBadParalithiumSignature
	}

	dataLen := len(data)
	cdata := (*C.uchar)(C.NULL)
	if dataLen != 0 {
		cdata = (*C.uchar)(&data[0])
	}

	out := C.pqcrystals_dilithium3_ref_verify((*C.uchar)(&sig[0]), (C.size_t)(sigLen), (*C.uchar)(cdata), C.size_t(dataLen), (*C.uchar)(&(v[0])))
	if out != 0 {
		return ErrBadParalithiumSignature
	}
	runtime.KeepAlive(data)
	runtime.KeepAlive(sig)
	return nil
}
