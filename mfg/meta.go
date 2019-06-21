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
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"

	"github.com/apache/mynewt-artifact/errors"
)

// The "manufacturing meta region" is located at the end of the boot loader
// flash area.  This region has the following structure.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version (0x01) |                  0xff padding                 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   TLV type    |   TLV size    | TLV data ("TLV size" bytes)   ~
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               ~
// ~                                                               ~
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   TLV type    |   TLV size    | TLV data ("TLV size" bytes)   ~
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               ~
// ~                                                               ~
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Region size                 |         0xff padding          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Magic (0x3bb2a269)                      |
// +-+-+-+-+-+--+-+-+-+-end of boot loader area+-+-+-+-+-+-+-+-+-+-+
//
// The number of TLVs is variable; two are shown above for illustrative
// purposes.
//
// Fields:
// <Header>
// 1. Version: Manufacturing meta version number; always 0x01.
//
// <TLVs>
// 2. TLV type: Indicates the type of data to follow.
// 3. TLV size: The number of bytes of data to follow.
// 4. TLV data: TLV-size bytes of data.
//
// <Footer>
// 5. Region size: The size, in bytes, of the entire manufacturing meta region;
//    includes header, TLVs, and footer.
// 6. Magic: indicates the presence of the manufacturing meta region.

const META_MAGIC = 0x3bb2a269
const META_VERSION = 2
const META_TLV_TYPE_HASH = 0x01
const META_TLV_TYPE_FLASH_AREA = 0x02
const META_TLV_TYPE_MMR_REF = 0x04

const META_HASH_SZ = 32
const META_FOOTER_SZ = 8
const META_TLV_HEADER_SZ = 2
const META_TLV_HASH_SZ = META_HASH_SZ
const META_TLV_FLASH_AREA_SZ = 10
const META_TLV_MMR_REF_SZ = 1

type MetaFooter struct {
	Size    uint16 // Includes header, TLVs, and footer.
	Version uint8
	Pad8    uint8  // 0xff
	Magic   uint32 // META_MAGIC
}

type MetaTlvHeader struct {
	Type uint8 // Indicates the type of data to follow.
	Size uint8 // The number of bytes of data to follow.
}

type MetaTlvBodyFlashArea struct {
	Area   uint8  // Unique value identifying this flash area.
	Device uint8  // Indicates host flash device (aka section number).
	Offset uint32 // The byte offset within the flash device.
	Size   uint32 // Size, in bytes, of entire flash area.
}

type MetaTlvBodyHash struct {
	Hash [META_HASH_SZ]byte
}

type MetaTlvBodyMmrRef struct {
	Area uint8
}

type MetaTlv struct {
	Header MetaTlvHeader
	Data   []byte
}

type Meta struct {
	Tlvs   []MetaTlv
	Footer MetaFooter
}

type MetaOffsets struct {
	Tlvs      []int
	Footer    int
	TotalSize int
}

var metaTlvTypeNameMap = map[uint8]string{
	META_TLV_TYPE_HASH:       "hash",
	META_TLV_TYPE_FLASH_AREA: "flash_area",
	META_TLV_TYPE_MMR_REF:    "mmr_ref",
}

func MetaTlvTypeName(typ uint8) string {
	name := metaTlvTypeNameMap[typ]
	if name == "" {
		name = "???"
	}
	return name
}

func writeElem(elem interface{}, w io.Writer) error {
	/* XXX: Assume target platform uses little endian. */
	if err := binary.Write(w, binary.LittleEndian, elem); err != nil {
		return errors.Wrapf(err, "failed to write MMR element")
	}
	return nil
}

func (tlv *MetaTlv) Write(w io.Writer) (int, error) {
	sz := 0

	if err := writeElem(tlv.Header, w); err != nil {
		return sz, err
	}
	sz += META_TLV_HEADER_SZ

	if err := writeElem(tlv.Data, w); err != nil {
		return sz, err
	}
	sz += len(tlv.Data)

	return sz, nil
}

// StructuredBody constructs the appropriate "body" object from a raw TLV
// (e.g., MetaTlvBodyHash from a TLV with type=META_TLV_TYPE_HASH).
func (tlv *MetaTlv) StructuredBody() (interface{}, error) {
	r := bytes.NewReader(tlv.Data)

	readBody := func(dst interface{}) error {
		if err := binary.Read(r, binary.LittleEndian, dst); err != nil {
			return errors.Wrapf(err, "error parsing TLV data")
		}
		return nil
	}

	switch tlv.Header.Type {
	case META_TLV_TYPE_HASH:
		var body MetaTlvBodyHash
		if err := readBody(&body); err != nil {
			return nil, err
		}
		return &body, nil

	case META_TLV_TYPE_FLASH_AREA:
		var body MetaTlvBodyFlashArea
		if err := readBody(&body); err != nil {
			return nil, err
		}
		return &body, nil

	case META_TLV_TYPE_MMR_REF:
		var body MetaTlvBodyMmrRef
		if err := readBody(&body); err != nil {
			return nil, err
		}
		return &body, nil

	default:
		return nil, errors.Errorf("unknown meta TLV type: %d", tlv.Header.Type)
	}
}

// WritePlusOffsets writes a binary MMR to the given writer.  It returns the
// offsets of the mfgimage components that got written.
func (meta *Meta) WritePlusOffsets(w io.Writer) (MetaOffsets, error) {
	mo := MetaOffsets{}
	sz := 0

	for _, tlv := range meta.Tlvs {
		tlvSz, err := tlv.Write(w)
		if err != nil {
			return mo, err
		}
		mo.Tlvs = append(mo.Tlvs, sz)
		sz += tlvSz
	}

	if err := writeElem(meta.Footer, w); err != nil {
		return mo, err
	}
	mo.Footer = sz
	sz += META_FOOTER_SZ

	mo.TotalSize = sz

	return mo, nil
}

// Offsets returns the offsets of each of an MMR's components if it were
// serialized.
func (meta *Meta) Offsets() MetaOffsets {
	mo, _ := meta.WritePlusOffsets(ioutil.Discard)
	return mo
}

// Write serializes and writes an MMR.
func (meta *Meta) Write(w io.Writer) (int, error) {
	mo, err := meta.WritePlusOffsets(w)
	if err != nil {
		return 0, err
	}

	return mo.TotalSize, nil
}

// Size calculates the total size of an MMR if it were serialied.
func (meta *Meta) Size() int {
	return meta.Offsets().TotalSize
}

// Bytes serializes an MMR to binary form.
func (meta *Meta) Bytes() ([]byte, error) {
	b := &bytes.Buffer{}

	_, err := meta.Write(b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// FindTlvIndices searches an MMR for TLVs of the specified type and returns
// their indices.
func (meta *Meta) FindTlvIndices(typ uint8) []int {
	indices := []int{}

	for i, tlv := range meta.Tlvs {
		if tlv.Header.Type == typ {
			indices = append(indices, i)
		}
	}

	return indices
}

// FindTlvIndices searches an MMR for all TLVs of the specified type.
func (meta *Meta) FindTlvs(typ uint8) []*MetaTlv {
	indices := meta.FindTlvIndices(typ)

	tlvs := []*MetaTlv{}
	for _, index := range indices {
		tlvs = append(tlvs, &meta.Tlvs[index])
	}

	return tlvs
}

// FindTlvIndices searches an MMR for the first TLV of the specified type.
func (meta *Meta) FindFirstTlv(typ uint8) *MetaTlv {
	tlvs := meta.FindTlvs(typ)
	if len(tlvs) == 0 {
		return nil
	}

	return tlvs[0]
}

// HashOffset calculates the offset of the SHA256 TLV in an MMR if it were
// serialized.
func (meta *Meta) HashOffset() int {
	mo := meta.Offsets()
	indices := meta.FindTlvIndices(META_TLV_TYPE_HASH)
	if len(indices) == 0 {
		return -1
	}

	return META_TLV_HEADER_SZ + mo.Tlvs[indices[0]]
}

// ClearHash zeroes out an MMRs SHA256 TLV.
func (meta *Meta) ClearHash() {
	tlv := meta.FindFirstTlv(META_TLV_TYPE_HASH)
	if tlv != nil {
		tlv.Data = make([]byte, META_HASH_SZ)
	}
}

// Hash locates an MMR's SHA256 TLV and returns its value.  It returns nil if
// the MMR doesn't have a SHA256 TLV.
func (meta *Meta) Hash() []byte {
	tlv := meta.FindFirstTlv(META_TLV_TYPE_HASH)
	if tlv == nil {
		return nil
	}
	return tlv.Data
}

// Clone performs a deep copy of an MMR.
func (meta *Meta) Clone() Meta {
	tlvs := make([]MetaTlv, len(meta.Tlvs))
	for i, src := range meta.Tlvs {
		tlvs[i] = MetaTlv{
			Header: src.Header,
			Data:   make([]byte, len(src.Data)),
		}
		copy(tlvs[i].Data, src.Data)
	}

	return Meta{
		Tlvs:   tlvs,
		Footer: meta.Footer,
	}
}
