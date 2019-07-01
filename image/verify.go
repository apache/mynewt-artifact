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
	"bytes"
	"encoding/hex"

	"github.com/apache/mynewt-artifact/errors"
	"github.com/apache/mynewt-artifact/manifest"
	"github.com/apache/mynewt-artifact/sec"
)

func (img *Image) verifyHashDecrypted() error {
	// Verify the hash.
	haveHash, err := img.Hash()
	if err != nil {
		return err
	}

	wantHash, err := img.CalcHash()
	if err != nil {
		return err
	}

	if !bytes.Equal(haveHash, wantHash) {
		return errors.Errorf(
			"image contains incorrect hash: have=%x want=%x",
			haveHash, wantHash)
	}

	return nil
}

func (img *Image) verifyEncState() ([]byte, error) {
	secret, err := img.CollectSecret()
	if err != nil {
		return nil, err
	}

	if img.Header.Flags&IMAGE_F_ENCRYPTED == 0 {
		if secret != nil {
			return nil, errors.Errorf(
				"encrypted flag set in image header, but no encryption TLV")
		}

		return nil, nil
	} else {
		if secret == nil {
			return nil, errors.Errorf(
				"encryption TLV, but encrypted flag unset in image header")
		}

		return secret, nil
	}
}

// VerifyStructure checks an image's structure for internal consistency.  It
// returns an error if the image is incorrect.
func (img *Image) VerifyStructure() error {
	// Verify that each TLV has a valid "type" field.
	for _, t := range img.Tlvs {
		if !ImageTlvTypeIsValid(t.Header.Type) {
			return errors.Errorf(
				"image contains TLV with invalid `type` field: %d",
				t.Header.Type)
		}
	}

	if _, err := img.verifyEncState(); err != nil {
		return err
	}

	return nil
}

// VerifyHash calculates an image's hash and compares it to the image's SHA256
// TLV.  If the image is encrypted, this function temporarily decrypts it
// before calculating the hash.  The returned int is the index of the key that
// was used to decrypt the image, or -1 if none.  An error is returned if the
// hash is incorrect.
func (img *Image) VerifyHash(privEncKeys []sec.PrivEncKey) (int, error) {
	secret, err := img.verifyEncState()
	if err != nil {
		return -1, err
	}

	if secret == nil {
		// Image not encrypted.
		if err := img.verifyHashDecrypted(); err != nil {
			return -1, err
		}

		return -1, nil
	}

	// Image is encrypted.
	if len(privEncKeys) == 0 {
		return -1, errors.Errorf(
			"attempt to verify hash of encrypted image: no keys provided")
	}

	// We don't know which key the image is encrypted with.  For each key,
	// decrypt and then check the hash.
	var hashErr error
	for i, key := range privEncKeys {
		dec, err := Decrypt(*img, key)
		if err != nil {
			return -1, err
		}

		hashErr = dec.verifyHashDecrypted()
		if hashErr == nil {
			return i, nil
		}
	}

	return -1, hashErr
}

// VerifySigs checks an image's attached signatures against the provided set of
// keys.  It succeeds if the image has no signatures or if any signature can be
// verified.  The returned int is the index of the key that was used to verify
// a signature, or -1 if none.  An error is returned if there is at least one
// signature and they all fail the check.
func (img *Image) VerifySigs(keys []sec.PubSignKey) (int, error) {
	sigs, err := img.CollectSigs()
	if err != nil {
		return -1, err
	}

	if len(sigs) == 0 {
		return -1, nil
	}

	hash, err := img.Hash()
	if err != nil {
		return -1, err
	}

	for keyIdx, k := range keys {
		sigIdx, err := sec.VerifySigs(k, sigs, hash)
		if err != nil {
			return -1, err
		}

		if sigIdx != -1 {
			return keyIdx, nil
		}
	}

	return -1, errors.Errorf("image signatures do not match provided keys")
}

// VerifyManifest compares an image's structure to its manifest.  It returns
// an error if the image doesn't match the manifest.
func (img *Image) VerifyManifest(man manifest.Manifest) error {
	ver, err := ParseVersion(man.Version)
	if err != nil {
		return errors.Wrapf(err, "manifest contains invalid `version` field")
	}

	if ver.Major != img.Header.Vers.Major ||
		ver.Minor != img.Header.Vers.Minor ||
		ver.Rev != img.Header.Vers.Rev ||
		ver.BuildNum != img.Header.Vers.BuildNum {

		return errors.Errorf(
			"manifest version different from image header: man=%s img=%s",
			ver.String(), img.Header.Vers.String())
	}

	var imgHash string
	if hash, err := img.Hash(); err == nil {
		imgHash = hex.EncodeToString(hash)
	}

	// A manifest contains two image hashes: `id` and `image_hash`.  Check
	// both.

	checkHash := func(manHash string) error {
		if imgHash != manHash {
			return errors.Errorf(
				"manifest image hash different from image TLV: man=%s img=%s",
				manHash, imgHash)
		}
		return nil
	}

	if err := checkHash(man.BuildID); err != nil {
		return err
	}
	if err := checkHash(man.ImageHash); err != nil {
		return err
	}

	return nil
}
