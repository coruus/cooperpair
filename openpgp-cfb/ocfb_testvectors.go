// Original license:

// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// OpenPGP CFB Mode. http://tools.ietf.org/html/rfc4880#section-13.9

// Patches licensed under CC0
// David Leon Gil

package main

import (
	"bytes"
	"crypto/aes"
	"fmt"

	"code.google.com/p/go.crypto/openpgp/packet"
)

var (
	key128    = []byte{0xaa, 0xbb, 0xcc, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77}
	key256    = []byte{0xaa, 0xbb, 0xcc, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0xaa, 0xbb, 0xcc, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77}
	key192    = key256[:192/8]
	plaintext = []byte("this is the plaintext, which is long enough to span several blocks.")
)

func ocfbTestVector(k []byte, iv []byte, resync packet.OCFBResyncOption) (out []byte, err error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	ocfb, prefix := packet.NewOCFBEncrypter(block, iv, resync)
	ciphertext := make([]byte, len(plaintext))
	ocfb.XORKeyStream(ciphertext, plaintext)

	buf := bytes.NewBuffer(prefix)
	buf.Write(ciphertext)
	out = buf.Bytes()

	fmt.Printf("\n// %d-byte key (resync = %t)\n", len(k), resync == packet.OCFBResync)
	fmt.Printf("key      = \"%x\"\n", k)
	fmt.Printf("prefix   = \"%x\"\n", prefix)
	fmt.Printf("resync   = %t\n", resync == packet.OCFBResync)
	fmt.Printf("ciphered = \"%x\"\n", out)

	ocfbdec := packet.NewOCFBDecrypter(block, prefix, resync)
	if ocfbdec == nil {
		fmt.Errorf("NewOCFBDecrypter failed (resync: %t)", resync)
		return nil, nil
	}
	plaintextCopy := make([]byte, len(plaintext))
	ocfbdec.XORKeyStream(plaintextCopy, ciphertext)

	if !bytes.Equal(plaintextCopy, plaintext) {
		fmt.Errorf("got: %x, want: %x (resync: %t)", plaintextCopy, plaintext, resync)
	}

	return
}

func ocfbTestVectors(k []byte, prefix []byte) {
	_, err := ocfbTestVector(k, prefix, packet.OCFBResync)
	if err != nil {
		fmt.Errorf("Err %t", err)
	}
	_, err = ocfbTestVector(k, prefix, packet.OCFBNoResync)
	if err != nil {
		fmt.Errorf("Err %t", err)
	}
}

func main() {
	prefix := []byte{0xff, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x13}

	ocfbTestVectors(key128, prefix)
	ocfbTestVectors(key192, prefix)
	ocfbTestVectors(key256, prefix)
}
