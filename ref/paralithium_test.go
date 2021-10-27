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
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParalithiumSigning(t *testing.T) {
	a := require.New(t)
	for i := 0; i < 100; i++ {
		sk, pk := NewKeys()
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(i))
		bs := sha256.Sum256(b)
		sig := sk.SignBytes(bs[:])
		a.NoError(pk.VerifyBytes(bs[:], sig))
		var sig2 ParalithiumSignature
		copy(sig2[:], sig)

		sig2[0]++
		a.Error(pk.VerifyBytes(bs[:], sig2[:]))

		var bs2 [32]byte
		copy(bs2[:], bs[:])

		bs2[0]++
		a.Error(pk.VerifyBytes(bs2[:], sig[:]))
	}
}

func TestParalithiumSigningWithRho(t *testing.T) {
	a := require.New(t)
	for i := 0; i < 100; i++ {
		iter := make([]byte, 8)
		binary.BigEndian.PutUint64(iter, uint64(i+1))
		iterHash := sha256.Sum256(iter)

		rho := ParalithiumRho(iterHash)

		sk, pk := NewKeysWithRho(rho)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(i))
		bs := sha256.Sum256(b)
		sig := sk.SignBytes(bs[:])

		a.NoError(pk.VerifyBytes(bs[:], sig))
		var sig2 ParalithiumSignature
		copy(sig2[:], sig)

		sig2[0]++
		a.Error(pk.VerifyBytes(bs[:], sig2[:]))

		var bs2 [32]byte
		copy(bs2[:], bs[:])

		bs2[0]++
		a.Error(pk.VerifyBytes(bs2[:], sig[:]))
	}
}

func TestParalithiumWrongRho(t *testing.T) {
	a := require.New(t)

	seed := []byte{'s', 'e', 'e', 'd'}
	seedHash := sha256.Sum256(seed)
	rho := ParalithiumRho(seedHash)

	_, pk := NewKeysWithRho(rho)

	a.NoError(pk.VerifyRho(rho))

	seed2 := []byte{'s', 'e', 'e', 'd', '2'}
	seedHash2 := sha256.Sum256(seed2)
	rho2 := ParalithiumRho(seedHash2)

	a.Error(pk.VerifyRho(rho2))

}

func TestWrongSizedBytes(t *testing.T) {
	a := require.New(t)
	sk, pk := NewKeys()
	bs := sha256.Sum256(make([]byte, 8))
	sig := sk.SignBytes(bs[:])

	sig = append(sig, 0)
	a.Error(pk.VerifyBytes(bs[:], sig))

	sig = sig[:len(sig)-1]
	a.NoError(pk.VerifyBytes(bs[:], sig))

	sig = sig[:len(sig)-1]
	a.Error(pk.VerifyBytes(bs[:], sig))
}

func TestEmpty(t *testing.T) {
	a := require.New(t)
	sk, pk := NewKeys()
	bs := make([]byte, 0)
	sig := sk.SignBytes(bs)
	a.NoError(pk.VerifyBytes(bs, sig))

	sig = append(sig, 0)
	a.Error(pk.VerifyBytes(bs[:], sig))

	sig = sig[:len(sig)-1]
	a.NoError(pk.VerifyBytes(bs[:], sig))

	sig = sig[:len(sig)-1]
	a.Error(pk.VerifyBytes(bs[:], sig))

	a.Error(pk.VerifyBytes(bs[:], nil))
}
