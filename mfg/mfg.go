/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package mfg

import (
	"crypto/sha256"

	"github.com/apache/mynewt-artifact/errors"
	"github.com/apache/mynewt-artifact/flash"
)

const MFG_BIN_IMG_FILENAME = "mfgimg.bin"
const MFG_HEX_IMG_FILENAME = "mfgimg.hex"
const MANIFEST_FILENAME = "manifest.json"

type Mfg struct {
	Bin  []byte
	Meta *Meta

	// Unused if Meta==nil.
	MetaOff int
}

// StripPadding produces a new byte slice by removing padding from an
// existing byte slice.  Padding is defined as a sequence of trailing bytes,
// all with the specified value.
func StripPadding(b []byte, eraseVal byte) []byte {
	var pad int
	for pad = 0; pad < len(b); pad++ {
		off := len(b) - pad - 1
		if b[off] != eraseVal {
			break
		}
	}

	return b[:len(b)-pad]
}

// AddPadding produces a new byte slice by adding extra bytes to the end of
// an existing slice.
func AddPadding(b []byte, eraseVal byte, padLen int) []byte {
	for i := 0; i < padLen; i++ {
		b = append(b, eraseVal)
	}
	return b
}

// Calculates the SHA256 hash, using the full manufacturing image as input.
// Hash-calculation algorithm is as follows:
// 1. Zero out the 32 bytes that will contain the hash.
// 2. Apply SHA256 to the result.
//
// This function assumes that the 32 bytes of hash data have already been
// zeroed.
func CalcHash(bin []byte) []byte {
	hash := sha256.Sum256(bin)
	return hash[:]
}

func (m *Mfg) RecalcHash(eraseVal byte) ([]byte, error) {
	// The hash TLV needs to be zeroed out in order to calculate the mfg
	// hash.  Duplicate the mfg object so that we don't modify the
	// original.
	dup := m.Clone()
	if dup.Meta != nil {
		dup.Meta.ClearHash()
	}

	bin, err := dup.Bytes(eraseVal)
	if err != nil {
		return nil, err
	}

	return CalcHash(bin), nil
}

// RefillHash replace's the contents of an mfgimage's SHA256 TLV with a newly
// calculated hash.
func (m *Mfg) RefillHash(eraseVal byte) error {
	if m.Meta == nil {
		return nil
	}
	tlv := m.Meta.FindFirstTlv(META_TLV_TYPE_HASH)
	if tlv == nil {
		return nil
	}

	// Calculate hash.
	hash, err := m.RecalcHash(eraseVal)
	if err != nil {
		return err
	}

	// Fill hash TLV.
	copy(tlv.Data, hash)

	return nil
}

// Hash retrieves the SHA256 value associated with an mfgimage.  If the
// mfgimage has an MMR with a SHA256 TLV, the TLV's value is returned.
// Otherwise, the hash is calculated and returned.
func (m *Mfg) Hash(eraseVal byte) ([]byte, error) {
	var hashBytes []byte

	if m.Meta != nil {
		hashBytes = m.Meta.Hash()
	}

	if hashBytes == nil {
		// No hash TLV; calculate hash manually.
		b, err := m.RecalcHash(eraseVal)
		if err != nil {
			return nil, err
		}
		hashBytes = b
	}

	return hashBytes, nil
}

// Bytes serializes an mfgimage into binary form.
func (m *Mfg) Bytes(eraseVal byte) ([]byte, error) {
	binCopy := make([]byte, len(m.Bin))
	copy(binCopy, m.Bin)

	metaBytes, err := m.Meta.Bytes()
	if err != nil {
		return nil, err
	}

	padLen := m.MetaOff + len(metaBytes) - len(binCopy)
	if padLen > 0 {
		binCopy = AddPadding(binCopy, eraseVal, padLen)
	}

	copy(binCopy[m.MetaOff:m.MetaOff+len(metaBytes)], metaBytes)

	return binCopy, nil
}

// Clone performs a deep copy of an mfgimage.
func (m *Mfg) Clone() Mfg {
	var meta *Meta
	if m.Meta != nil {
		metaDup := m.Meta.Clone()
		meta = &metaDup
	}

	bin := make([]byte, len(m.Bin))
	copy(bin, m.Bin)

	return Mfg{
		Bin:     bin,
		Meta:    meta,
		MetaOff: m.MetaOff,
	}
}

// ExtractFlashArea copies a portion out of a serialized mfgimage.  The
// offset and size to copy indicated by the provided FlashArea.
func (m *Mfg) ExtractFlashArea(area flash.FlashArea,
	eraseVal byte) ([]byte, error) {

	b, err := m.Bytes(eraseVal)
	if err != nil {
		return nil, err
	}

	if area.Offset >= len(b) {
		return nil, errors.Errorf(
			"flash area in mmr (\"%s\") is beyond end of mfgimage "+
				"(offset=%d mfgimg_len=%d)",
			area.Name, area.Offset, len(b))
	}

	// If the end of the target contains unwritten bytes, it gets truncated
	// from the mfgimage.
	end := area.Offset + area.Size
	if end > len(b) {
		end = len(b)
	}

	return b[area.Offset:end], nil
}

// Tlvs retrieves the slice of TLVs present in an mfgimage's MMR.  It returns
// nil if the mfgimage has no MMR.
func (m *Mfg) Tlvs() []MetaTlv {
	if m.Meta == nil {
		return nil
	} else {
		return m.Meta.Tlvs
	}
}
