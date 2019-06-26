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
	"encoding/hex"

	"github.com/apache/mynewt-artifact/errors"
	"github.com/apache/mynewt-artifact/flash"
	"github.com/apache/mynewt-artifact/image"
	"github.com/apache/mynewt-artifact/manifest"
	"github.com/apache/mynewt-artifact/sec"
)

func (m *Mfg) validateManFlashMap(man manifest.MfgManifest) error {
	idAreaMap := map[int]flash.FlashArea{}
	for _, area := range man.FlashAreas {
		if _, dup := idAreaMap[area.Id]; dup {
			return errors.Errorf(
				"mfg manifest contains duplicate flash area: %d", area.Id)
		}

		idAreaMap[area.Id] = area
	}

	seen := map[int]struct{}{}

	mmrHasFlash := man.Meta != nil && man.Meta.FlashMap

	for _, t := range m.Tlvs() {
		if t.Header.Type == META_TLV_TYPE_FLASH_AREA {
			if !mmrHasFlash {
				return errors.Errorf(
					"mmr contains flash map; manifest indicates otherwise")
			}

			body, err := t.StructuredBody()
			if err != nil {
				return err
			}
			flashBody := body.(*MetaTlvBodyFlashArea)
			if _, ok := idAreaMap[int(flashBody.Area)]; !ok {
				return errors.Errorf(
					"flash area %d missing from mfg manifest", flashBody.Area)
			}

			seen[int(flashBody.Area)] = struct{}{}
		}
	}

	if mmrHasFlash {
		for _, area := range man.FlashAreas {
			if _, ok := seen[area.Id]; !ok {
				return errors.Errorf("flash area %d missing from mmr", area.Id)
			}
		}
	}

	return nil
}

func (m *Mfg) validateManMmrs(man manifest.MfgManifest) error {
	areaMap := map[int]struct{}{}
	if man.Meta != nil {
		for _, mmr := range man.Meta.Mmrs {
			fa := man.FindFlashAreaName(mmr.Area)
			if fa == nil {
				return errors.Errorf(
					"flash area %s missing from mfg manifest", mmr.Area)
			}

			if _, dup := areaMap[fa.Id]; dup {
				return errors.Errorf(
					"mfg manifest contains duplicate mmr ref: %s", mmr.Area)
			}

			areaMap[fa.Id] = struct{}{}
		}
	}

	seen := map[int]struct{}{}
	for _, t := range m.Tlvs() {
		if t.Header.Type == META_TLV_TYPE_MMR_REF {
			body, err := t.StructuredBody()
			if err != nil {
				return err
			}

			mmrBody := body.(*MetaTlvBodyMmrRef)
			if _, ok := areaMap[int(mmrBody.Area)]; !ok {
				return errors.Errorf(
					"mmr ref %d missing from mfg manifest", mmrBody.Area)
			}

			seen[int(mmrBody.Area)] = struct{}{}
		}
	}

	for area, _ := range areaMap {
		if _, ok := seen[area]; !ok {
			return errors.Errorf("mmr ref %d missing from mmr", area)
		}
	}

	return nil
}

func (m *Mfg) validateManTargets(man manifest.MfgManifest) error {
	for _, t := range man.Targets {
		fa := man.FindFlashAreaDevOff(man.Device, t.Offset)
		if fa == nil {
			return errors.Errorf(
				"no flash area in mfgimage corresponding to target \"%s\"",
				t.Name)
		}

		data, err := m.ExtractFlashArea(*fa, man.EraseVal)
		if err != nil {
			return err
		}

		if !t.IsBoot() {
			img, err := image.ParseImage(data)
			if err != nil {
				return errors.Wrapf(err,
					"error parsing build \"%s\" embedded in mfgimage", t.Name)
			}

			if err := img.VerifyStructure(); err != nil {
				return errors.Wrapf(err,
					"mfgimage contains invalid build \"%s\"", t.Name)
			}
		}
	}

	return nil
}

// VerifyStructure checks an mfgimage's structure and internal consistency.  It
// returns an error if the mfgimage is incorrect.
func (m *Mfg) VerifyStructure(eraseVal byte) error {
	for _, t := range m.Tlvs() {
		// Verify that TLV has a valid `type` field.
		body, err := t.StructuredBody()
		if err != nil {
			return err
		}

		// Verify contents of hash TLV.
		switch t.Header.Type {
		case META_TLV_TYPE_HASH:
			hashBody := body.(*MetaTlvBodyHash)

			hash, err := m.RecalcHash(eraseVal)
			if err != nil {
				return err
			}

			if !bytes.Equal(hash, hashBody.Hash[:]) {
				return errors.Errorf(
					"mmr contains incorrect hash: have=%s want=%s",
					hex.EncodeToString(hashBody.Hash[:]),
					hex.EncodeToString(hash))
			}
		}
	}

	return nil
}

// VerifyManifest compares an mfgimage's structure to its manifest.  It returns
// an error if the mfgimage doesn't match the manifest.
func (m *Mfg) VerifyManifest(man manifest.MfgManifest) error {
	if man.Format != 2 {
		return errors.Errorf(
			"only mfgimage format 2 supported (have=%d)", man.Format)
	}

	mfgHash, err := m.Hash(man.EraseVal)
	if err != nil {
		return err
	}
	hashStr := hex.EncodeToString(mfgHash)
	if hashStr != man.MfgHash {
		return errors.Errorf(
			"manifest mfg hash different from mmr: man=%s mfg=%s",
			man.MfgHash, hashStr)
	}

	if err := m.validateManFlashMap(man); err != nil {
		return err
	}

	if err := m.validateManMmrs(man); err != nil {
		return err
	}

	// Verify each embedded build.
	if err := m.validateManTargets(man); err != nil {
		return err
	}

	return nil
}

// VerifySigs checks an mfgimage's signatures against the provided set of keys.
// It succeeds if the mfgimage has no signatures or if any signature can be
// verified.  An error is returned if there is at least one signature and they
// all fail the check.
func VerifySigs(man manifest.MfgManifest, keys []sec.PubSignKey) (int, error) {
	sigs, err := man.SecSigs()
	if err != nil {
		return -1, err
	}

	hash, err := hex.DecodeString(man.MfgHash)
	if err != nil {
		return -1, errors.Wrapf(err,
			"mfg manifest contains invalid hash: %s", man.MfgHash)
	}

	for keyIdx, k := range keys {
		sigIdx, err := sec.VerifySigs(k, sigs, hash)
		if err != nil {
			return -1, errors.Wrapf(err, "failed to verify mfgimg signatures")
		}

		if sigIdx != -1 {
			return keyIdx, nil
		}
	}

	return -1, errors.Errorf("mfg signatures do not match provided keys")
}
