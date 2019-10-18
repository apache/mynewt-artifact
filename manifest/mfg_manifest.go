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

package manifest

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"

	"github.com/apache/mynewt-artifact/errors"
	"github.com/apache/mynewt-artifact/flash"
	"github.com/apache/mynewt-artifact/sec"
)

type MfgManifestTarget struct {
	Name         string `json:"name"`
	Offset       int    `json:"offset"`
	BinPath      string `json:"bin_path,omitempty"`
	ImagePath    string `json:"image_path,omitempty"`
	HexPath      string `json:"hex_path,omitempty"`
	ManifestPath string `json:"manifest_path"`
}

type MfgManifestRaw struct {
	Filename string `json:"filename"`
	Offset   int    `json:"offset"`
	BinPath  string `json:"bin_path"`
}

type MfgManifestMetaMmr struct {
	Area      string `json:"area"`
	Device    int    `json:"_device"`
	EndOffset int    `json:"_end_offset"`
}

type MfgManifestMeta struct {
	EndOffset int                  `json:"end_offset"`
	Size      int                  `json:"size"`
	Hash      bool                 `json:"hash_present"`
	FlashMap  bool                 `json:"flash_map_present"`
	Mmrs      []MfgManifestMetaMmr `json:"mmrs,omitempty"`
}

type MfgManifestSig struct {
	Key string `json:"key"`
	Sig string `json:"sig"`
}

type MfgManifest struct {
	Name       string            `json:"name"`
	BuildTime  string            `json:"build_time"`
	Format     int               `json:"format"`
	MfgHash    string            `json:"mfg_hash"`
	Version    string            `json:"version"`
	Device     int               `json:"device"`
	BinPath    string            `json:"bin_path"`
	HexPath    string            `json:"hex_path"`
	Bsp        string            `json:"bsp"`
	EraseVal   byte              `json:"erase_val"`
	Signatures []MfgManifestSig  `json:"signatures,omitempty"`
	FlashAreas []flash.FlashArea `json:"flash_map"`

	Targets []MfgManifestTarget `json:"targets"`
	Raws    []MfgManifestRaw    `json:"raws"`
	Meta    *MfgManifestMeta    `json:"meta,omitempty"`
}

// ReadMfgManifest reads a JSON mfg manifest from a byte slice and produces an
// MfgManifest object.
func ParseMfgManifest(jsonText []byte) (MfgManifest, error) {
	m := MfgManifest{
		// Backwards compatibility: assume 0xff if unspecified.
		EraseVal: 0xff,
	}

	if err := json.Unmarshal(jsonText, &m); err != nil {
		return m, errors.Wrapf(err, "failure decoding mfg manifest")
	}

	return m, nil
}

// ReadMfgManifest reads a JSON mfg manifest from a file and produces an
// MfgManifest object.
func ReadMfgManifest(path string) (MfgManifest, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return MfgManifest{}, errors.Wrapf(err,
			"failed to read mfg manifest file")
	}

	m, err := ParseMfgManifest(content)
	if err != nil {
		return m, errors.Wrapf(err, "path=%s", path)
	}

	return m, nil
}

// IsBoot indicates whether an mfg manifest target is a boot loader.
func (mt *MfgManifestTarget) IsBoot() bool {
	return mt.BinPath != ""
}

// MarshalJson produces a JSON representation of an mfg manifest.
func (m *MfgManifest) MarshalJson() ([]byte, error) {
	buffer, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, errors.Wrapf(err, "cannot encode mfg manifest")
	}

	return buffer, nil
}

// FindFlashAreaDevOff searches an mfg manifest for a flash area with the
// specified device and offset.
func (m *MfgManifest) FindFlashAreaDevOff(device int, offset int) *flash.FlashArea {
	for i, _ := range m.FlashAreas {
		fa := &m.FlashAreas[i]
		if fa.Device == device && fa.Offset == offset {
			return fa
		}
	}

	return nil
}

// FindFlashAreaName searches an mfg manifest for a flash area with the
// specified name.
func (m *MfgManifest) FindFlashAreaName(name string) *flash.FlashArea {
	for i, _ := range m.FlashAreas {
		fa := &m.FlashAreas[i]
		if fa.Name == name {
			return fa
		}
	}

	return nil
}

// SecSig converts the provided mfg manifest signature into a sec.Sig object.
func (ms *MfgManifestSig) SecSig() (sec.Sig, error) {
	keyHash, err := hex.DecodeString(ms.Key)
	if err != nil {
		return sec.Sig{}, errors.Errorf(
			"invalid hex-encoded key hash: %s", ms.Key)
	}

	data, err := hex.DecodeString(ms.Sig)
	if err != nil {
		return sec.Sig{}, errors.Errorf(
			"invalid hex-encoded signature: %s", ms.Sig)
	}

	return sec.Sig{
		KeyHash: keyHash,
		Data:    data,
	}, nil
}

// SecSigs converts all the signutures in the provided mfg manifest into
// sec.Sig objects.
func (m *MfgManifest) SecSigs() ([]sec.Sig, error) {
	var sigs []sec.Sig
	for _, ms := range m.Signatures {
		s, err := ms.SecSig()
		if err != nil {
			return nil, err
		}

		sigs = append(sigs, s)
	}

	return sigs, nil
}
