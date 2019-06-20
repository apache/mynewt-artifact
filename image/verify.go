package image

import (
	"bytes"
	"encoding/hex"

	"github.com/apache/mynewt-artifact/errors"
	"github.com/apache/mynewt-artifact/manifest"
)

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

// Verify checks an image's structure and internal consistency.  It returns
// an error if the image is incorrect.
func (img *Image) Verify() error {
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
			"image manifest contains incorrect hash: have=%x want=%x",
			haveHash, wantHash)
	}

	// Verify that each TLV has a valid "type" field.
	for _, t := range img.Tlvs {
		if !ImageTlvTypeIsValid(t.Header.Type) {
			return errors.Errorf(
				"image contains TLV with invalid `type` field: %d",
				t.Header.Type)
		}
	}

	return nil
}
