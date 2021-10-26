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
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"golang.org/x/crypto/sha3"
)

type testElement struct {
	input  string
	output string
}

var testVector = []testElement{
	{
		"",
		"0e7698f535975ebaf1fdcd38819589aa9906595ea9e86c73aded6964651d869a2c1579fbdd9c977ec5f5fc3b61749db57cad898f80f5c69f9a8f013cb7aafedc",
	},
	{
		"a",
		"4aa8bd2e6d455ff812cecd8dcd258e1c9f97561888e3474c9740c71ad31c86522d980f522e2964c733d4f52d94897ce143674b20fc41feae95ee092154925eda",
	},
	{
		"ab",
		"a33ae2accf2d45021fa57831ed0152a24aa5553a45f240a1d29b5e732f87b697b50c5e4fe25f442b3e30ec035a44ae95045912d59ae5993f05575b6bb3017188",
	},
	{
		"abc",
		"3fb641e5b7ffdce77abf80104b458dab1a0012729d158f4dac96a43993b26ad1b58261f090e50b20e242d02e531834aa5a76c5a99ab2e49d01b282eceeae6ec8",
	},
	{
		"abcd",
		"e5775a6f14bdb1cca1b0c2378e9c0c140332efe9bb48ebe32236a52902580e1ad199670cb3f9a773931a4b1467e899e91dd23bc95a4929f132ef9b34fd1c3de4",
	},
	{
		"You must be the change you wish to see in the world. -Mahatma Gandhi",
		"2495462abaa3b2eaa84b32eae9d97e1031dfde9cfebe78e8de1df110a0f1a80f918e4f652b8f6c754698413ebbfac41f74ec1a25111769a7633151e49b90ecfe",
	},
	{
		"I think, therefore I am. – Rene Descartes.",
		"4a22a6207adb7a978a980c8bfb173d96d24d5faf3f22848f8bd4de09c24f11180d3eeafdc06a13d3f9e62458460ece5587e0b1cbca875663cf19d146788b1dd4",
	},
}

func TestSumHash512TestVector(t *testing.T) {
	for i, element := range testVector {
		h := New512()

		bytesWritten, err := io.WriteString(h, element.input)
		if err != nil {
			t.Errorf("write returned error : %s", err)
		}

		if bytesWritten != len(element.input) {
			t.Errorf("write return %d expected %d", bytesWritten, len(element.input))
		}
		output := h.Sum(nil)
		if hex.EncodeToString(output) != element.output {
			t.Errorf("test vector element mismatched on index %d failed! got %s, want %s", i, hex.EncodeToString(output), element.output)
		}
	}

}

func TestSumHash512(t *testing.T) {
	input := make([]byte, 6000)
	v := sha3.NewShake256()
	v.Write([]byte("sumhash input"))
	v.Read(input)

	h := New512()
	bytesWritten, err := h.Write(input)
	if err != nil {
		t.Errorf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Errorf("write return %d expected %d", bytesWritten, len(input))
	}

	sum := h.Sum(nil)
	expectedSum := "1ad6dafe03f330e06554300ecc24a59d41ec6afe387c34f4d9a2d971e71ae751823f520135cdc766ba7886a0a2a8954fd17ecae64f58e4431e572571e0f0a9aa"
	if hex.EncodeToString(sum) != expectedSum {
		t.Errorf("got %x, want %s", sum, expectedSum)
	}
}

func TestSumHash512Reset(t *testing.T) {
	input := make([]byte, 6000)
	v := sha3.NewShake256()
	v.Write([]byte("sumhash"))
	v.Read(input)

	h := New512()
	h.Write(input)
	bytesWritten, err := h.Write(input)
	if err != nil {
		t.Errorf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Errorf("write return %d expected %d", bytesWritten, len(input))
	}

	input = make([]byte, 6000)
	v = sha3.NewShake256()
	v.Write([]byte("sumhash input"))
	v.Read(input)

	h.Reset()
	bytesWritten, err = h.Write(input)
	if err != nil {
		t.Errorf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Errorf("write return %d expected %d", bytesWritten, len(input))
	}

	sum := h.Sum(nil)
	expectedSum := "1ad6dafe03f330e06554300ecc24a59d41ec6afe387c34f4d9a2d971e71ae751823f520135cdc766ba7886a0a2a8954fd17ecae64f58e4431e572571e0f0a9aa"
	if hex.EncodeToString(sum) != expectedSum {
		t.Errorf("got %x, want %s", sum, expectedSum)
	}
}

func TestSumHash512ChecksumWithValue(t *testing.T) {
	input := make([]byte, 6000)
	v := sha3.NewShake256()
	v.Write([]byte("sumhash input"))
	v.Read(input)

	h := New512()
	bytesWritten, err := h.Write(input)
	if err != nil {
		t.Errorf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Errorf("write return %d expected %d", bytesWritten, len(input))
	}

	msgPrefix := make([]byte, 64)
	rand.Read(msgPrefix)
	sum := h.Sum(msgPrefix)
	dec, err := hex.DecodeString("1ad6dafe03f330e06554300ecc24a59d41ec6afe387c34f4d9a2d971e71ae751823f520135cdc766ba7886a0a2a8954fd17ecae64f58e4431e572571e0f0a9aa")
	expectedSum := append(msgPrefix, dec...)
	if !bytes.Equal(sum, expectedSum) {
		t.Errorf("got %x, want %s", hex.EncodeToString(sum), hex.EncodeToString(expectedSum))
	}

	// we also validate the the context does not change when return the current digest
	sum = h.Sum(msgPrefix)
	dec, err = hex.DecodeString("1ad6dafe03f330e06554300ecc24a59d41ec6afe387c34f4d9a2d971e71ae751823f520135cdc766ba7886a0a2a8954fd17ecae64f58e4431e572571e0f0a9aa")
	expectedSum = append(msgPrefix, dec...)
	if !bytes.Equal(sum, expectedSum) {
		t.Errorf("got %x, want %s", hex.EncodeToString(sum), hex.EncodeToString(expectedSum))
	}
}

func TestSumHash512Sizes(t *testing.T) {
	h := New512()
	blockSize := h.BlockSize()
	expectedBlockSizeInBytes := 512 / 8
	if blockSize != expectedBlockSizeInBytes {
		t.Errorf("got block size %d, want %d", blockSize, expectedBlockSizeInBytes)
	}

	size := h.Size()
	expectedSizeInBytes := 512 / 8
	if size != expectedSizeInBytes {
		t.Errorf("got block size %d, want %d", blockSize, expectedBlockSizeInBytes)
	}
}

func BenchmarkHashInterface(b *testing.B) {
	msg := make([]byte, 600)

	rand.Read(msg)
	h := New512()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(msg)
		_ = h.Sum(nil)
	}
}
