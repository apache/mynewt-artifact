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

package image

import (
	"encoding/hex"
	"encoding/json"

	"github.com/apache/mynewt-artifact/errors"
)

func (h *ImageHdr) Map(offset int) map[string]interface{} {
	return map[string]interface{}{
		"_offset": offset,
		"flags":   h.Flags,
		"hdr_sz":  h.HdrSz,
		"prot_sz": h.ProtSz,
		"img_sz":  h.ImgSz,
		"magic":   h.Magic,
		"vers":    h.Vers.String(),
	}
}

func rawBodyMap(offset int) map[string]interface{} {
	return map[string]interface{}{
		"_offset": offset,
	}
}

func (t *ImageTrailer) Map(offset int) map[string]interface{} {
	return map[string]interface{}{
		"_offset":     offset,
		"magic":       t.Magic,
		"tlv_tot_len": t.TlvTotLen,
	}
}

func (t *ImageTlv) Map(index int, offset int) map[string]interface{} {
	return map[string]interface{}{
		"_index":   index,
		"_offset":  offset,
		"_typestr": ImageTlvTypeName(t.Header.Type),
		"data":     hex.EncodeToString(t.Data),
		"len":      t.Header.Len,
		"type":     t.Header.Type,
	}
}

// Map produces a JSON-friendly map representation of an image.
func (img *Image) Map() (map[string]interface{}, error) {
	offs, err := img.Offsets()
	if err != nil {
		return nil, err
	}

	m := map[string]interface{}{}
	m["header"] = img.Header.Map(offs.Header)
	m["body"] = rawBodyMap(offs.Body)

	if img.Header.ProtSz > 0 {
		protTrailer := img.ProtTrailer()
		m["prot_trailer"] = protTrailer.Map(offs.ProtTrailer)
	}

	trailer := img.Trailer()
	m["trailer"] = trailer.Map(offs.Trailer)

	tlvMaps := []map[string]interface{}{}
	for i, tlv := range img.Tlvs {
		tlvMaps = append(tlvMaps, tlv.Map(i, offs.Tlvs[i]))
	}
	m["tlvs"] = tlvMaps

	protTlvMaps := []map[string]interface{}{}
	for i, tlv := range img.ProtTlvs {
		protTlvMaps = append(protTlvMaps, tlv.Map(i, offs.ProtTlvs[i]))
	}
	m["prot_tlvs"] = protTlvMaps

	return m, nil
}

// Json produces a JSON representation of an image.
func (img *Image) Json() (string, error) {
	m, err := img.Map()
	if err != nil {
		return "", err
	}

	b, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		return "", errors.Wrapf(err, "failed to marshal image")
	}

	return string(b), nil
}
