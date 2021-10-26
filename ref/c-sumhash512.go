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

// NOTE: cgo go code couldn't compile with the flags: -Wmissing-prototypes and -Wno-unused-paramete

//#cgo CFLAGS: -Wall -Wextra -Wpedantic -Wredundant-decls -Wshadow -Wvla -Wpointer-arith -Wno-unused-parameter  -Ofast -mavx2 -fomit-frame-pointer
//#include "sumhash512.h"
//#include "memory.h"
import "C"
import (
	"hash"
	"unsafe"
)

const (
	// Sumhash512DigestSize is the sumhash512 output result in bytes
	Sumhash512DigestSize = C.SUMHASH512_DIGEST_SIZE

	// Sumhash512DigestSize is the sumhash512 blocksize in bytes
	Sumhash512BlockSize = C.SUMHASH512_BLOCK_SIZE
)

// Sumhash512State is a the context used to invoke sumhash function
type Sumhash512State struct {
	context C.sumhash512_state
}

// New512 creates a new sumhash512 context that computes a sumhash checksum.
// The output of the hash function is 64 bytes (512 bits).
func New512() hash.Hash {
	state := &Sumhash512State{}
	C.sumhash512_init((*C.struct_sumhash512_state)(&state.context))
	return state
}

// Reset resets the Hash to its initial state.
func (s *Sumhash512State) Reset() {
	C.sumhash512_init((*C.struct_sumhash512_state)(&s.context))
}

// Size returns the number of bytes Sum will return.
func (s *Sumhash512State) Size() int {
	return Sumhash512DigestSize
}

// BlockSize returns the hash's underlying block size.
func (s *Sumhash512State) BlockSize() int {
	return Sumhash512BlockSize
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (s *Sumhash512State) Write(p []byte) (nn int, err error) {
	cdata := (*C.uchar)(C.NULL)
	if len(p) != 0 {
		cdata = (*C.uchar)(&p[0])
	}

	C.sumhash512_update((*C.struct_sumhash512_state)(&s.context), (*C.uchar)(cdata), (C.size_t)(len(p)))
	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (s *Sumhash512State) Sum(in []byte) []byte {
	stateCopy := &Sumhash512State{}
	C.memcpy(unsafe.Pointer(&stateCopy.context), unsafe.Pointer(&s.context), (C.size_t)(C.sizeof_struct_sumhash512_state))

	var output [Sumhash512DigestSize]byte
	outputPtr := unsafe.Pointer(&output[0])
	C.sumhash512_final((*C.struct_sumhash512_state)(&stateCopy.context), (*C.uchar)(outputPtr))

	return append(in, output[:]...)
}
