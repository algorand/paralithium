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

import "errors"

// NOTE: cgo go code couldn't compile with the flags: -Wmissing-prototypes and -Wno-unused-paramete

//#cgo CFLAGS: -Wall -Wextra -Wpedantic -Wredundant-decls -Wshadow -Wvla -Wpointer-arith -Wno-unused-parameter  -O3 -fomit-frame-pointer -DDILITHIUM_MODE=3
//#include "api.h"
import "C"

type (
	// ParalithiumSignature is the signature used by the dilithium scheme
	ParalithiumSignature [3389]byte
	// ParalithiumPublicKey is the public key used by the dilithium scheme
	ParalithiumPublicKey [1952]byte
	// DilPrivateKey is the private key used by the dilithium scheme
	ParalithiumPrivateKey [4032]byte
)

// Exporting to be used when attempting to wrap and use this package.
const (
	// SigSize is the size of a dilithium signature
	SigSize = C.pqcrystals_dilithium3_BYTES
	// PublicKeySize is the size of a dilithium public key
	PublicKeySize = C.pqcrystals_dilithium3_PUBLICKEYBYTES
	// PrivateKeySize is the size of a dilithium private key
	PrivateKeySize = C.pqcrystals_dilithium3_SECRETKEYBYTES
)

func init() {
	// Check sizes of structs
	_ = [SigSize]byte(ParalithiumSignature{})
	_ = [PublicKeySize]byte(ParalithiumPublicKey{})
	_ = [PrivateKeySize]byte(ParalithiumPrivateKey{})
}

// NewKeys Generates a paralithium private and public key .
func NewKeys() (ParalithiumPrivateKey, ParalithiumPublicKey) {
	pk := ParalithiumPublicKey{}
	sk := ParalithiumPrivateKey{}
	C.pqcrystals_dilithium3_ref_keypair((*C.uchar)(&(pk[0])), (*C.uchar)(&(sk[0])))

	return sk, pk
}

// SignBytes receives bytes and signs over them.
// the size of the signature should conform with dil3Signature.
// Note: the signature verifies the size of the output signature, bad code underneath will panic.
func (sk *ParalithiumPrivateKey) SignBytes(data []byte) []byte {
	cdata := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		cdata = (*C.uchar)(&data[0])
	}
	var sig ParalithiumSignature
	var smlen uint64
	C.pqcrystals_dilithium3_ref_signature((*C.uchar)(&sig[0]), (*C.size_t)(&smlen), (*C.uchar)(cdata), (C.size_t)(len(data)), (*C.uchar)(&(sk[0])))
	if smlen != uint64(SigSize) {
		panic("const value of dilithium signature had changed.")
	}
	return sig[:]
}

// ErrBadParalithiumSignature indicates signature isn't valid.
var ErrBadParalithiumSignature = errors.New("bad signature")

// VerifyBytes follows dilithium algorithm to verify a signature.
func (v *ParalithiumPublicKey) VerifyBytes(data []byte, sig []byte) error {
	if len(sig) == 0 {
		return ErrBadParalithiumSignature
	}

	cdata := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		cdata = (*C.uchar)(&data[0])
	}

	out := C.pqcrystals_dilithium3_ref_verify((*C.uchar)(&sig[0]), (C.size_t)(len(sig)), (*C.uchar)(cdata), C.size_t(len(data)), (*C.uchar)(&(v[0])))
	if out != 0 {
		return ErrBadParalithiumSignature
	}
	return nil
}
