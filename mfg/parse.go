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

	"github.com/apache/mynewt-artifact/errors"
)

func parseMetaFooter(bin []byte) (MetaFooter, int, error) {
	r := bytes.NewReader(bin)

	var ftr MetaFooter
	if err := binary.Read(r, binary.LittleEndian, &ftr); err != nil {
		return ftr, 0, errors.Wrapf(err,
			"error reading meta footer")
	}

	if ftr.Magic != META_MAGIC {
		return ftr, 0, errors.Errorf(
			"meta footer contains invalid magic; exp:0x%08x, got:0x%08x",
			META_MAGIC, ftr.Magic)
	}

	return ftr, META_FOOTER_SZ, nil
}

func parseMetaTlv(bin []byte) (MetaTlv, int, error) {
	r := bytes.NewReader(bin)

	tlv := MetaTlv{}
	if err := binary.Read(r, binary.LittleEndian, &tlv.Header); err != nil {
		return tlv, 0, errors.Wrapf(err, "error reading TLV header")
	}

	data := make([]byte, tlv.Header.Size)
	sz, err := r.Read(data)
	if err != nil {
		return tlv, 0, errors.Wrapf(err,
			"error reading %d bytes of TLV data",
			tlv.Header.Size)
	}
	if sz != len(data) {
		return tlv, 0, errors.Errorf(
			"error reading %d bytes of TLV data: incomplete read",
			tlv.Header.Size)
	}
	tlv.Data = data

	return tlv, META_TLV_HEADER_SZ + int(tlv.Header.Size), nil
}

func parseMeta(bin []byte) (Meta, error) {
	if len(bin) < META_FOOTER_SZ {
		return Meta{}, errors.Errorf(
			"binary too small to accommodate meta footer; "+
				"bin-size=%d ftr-size=%d", len(bin), META_FOOTER_SZ)
	}

	ftr, _, err := parseMetaFooter(bin[len(bin)-META_FOOTER_SZ:])
	if err != nil {
		return Meta{}, err
	}

	if int(ftr.Size) > len(bin) {
		return Meta{}, errors.Errorf(
			"binary too small to accommodate meta region; "+
				"bin-size=%d meta-size=%d", len(bin), ftr.Size)
	}

	ftrOff := len(bin) - META_FOOTER_SZ
	off := len(bin) - int(ftr.Size)

	tlvs := []MetaTlv{}
	for off < ftrOff {
		tlv, sz, err := parseMetaTlv(bin[off:])
		if err != nil {
			return Meta{}, err
		}
		tlvs = append(tlvs, tlv)
		off += sz
	}

	return Meta{
		Tlvs:   tlvs,
		Footer: ftr,
	}, nil
}

// Parse parses a serialized mfgimage (e.g., "mfgimg.bin") and produces an
// Mfg object.  metaEndOff is the offset immediately following the MMR, or -1
// if there is no MMR.
func Parse(data []byte, metaEndOff int, eraseVal byte) (Mfg, error) {
	m := Mfg{
		Bin: data,
	}

	if metaEndOff >= 0 {
		if metaEndOff > len(data) {
			return m, errors.Errorf(
				"MMR offset (%d) beyond end of mfgimage (%d)",
				metaEndOff, len(data))
		}

		meta, err := parseMeta(data[:metaEndOff])
		if err != nil {
			return m, err
		}
		m.Meta = &meta
		m.MetaOff = metaEndOff - int(meta.Footer.Size)

		for i := 0; i < int(meta.Footer.Size); i++ {
			m.Bin[m.MetaOff+i] = eraseVal
		}
	}

	return m, nil
}
