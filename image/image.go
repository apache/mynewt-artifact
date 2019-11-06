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
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/apache/mynewt-artifact/errors"
	"github.com/apache/mynewt-artifact/sec"
)

const (
	IMAGE_MAGIC              = 0x96f3b83d /* Image header magic */
	IMAGE_TRAILER_MAGIC      = 0x6907     /* TLV info magic */
	IMAGE_PROT_TRAILER_MAGIC = 0x6908     /* Protected TLV info magic */
)

const (
	IMAGE_HEADER_SIZE  = 32
	IMAGE_TRAILER_SIZE = 4
	IMAGE_TLV_SIZE     = 4 /* Plus `value` field. */
)

/*
 * Image header flags.
 */
const (
	IMAGE_F_PIC          = 0x00000001
	IMAGE_F_ENCRYPTED    = 0x00000004 /* encrypted image */
	IMAGE_F_NON_BOOTABLE = 0x00000010 /* non bootable image */
)

/*
 * Image trailer TLV types.
 */
const (
	IMAGE_TLV_KEYHASH   = 0x01
	IMAGE_TLV_SHA256    = 0x10
	IMAGE_TLV_RSA2048   = 0x20
	IMAGE_TLV_ECDSA224  = 0x21
	IMAGE_TLV_ECDSA256  = 0x22
	IMAGE_TLV_RSA3072   = 0x23
	IMAGE_TLV_ED25519   = 0x24
	IMAGE_TLV_ENC_RSA   = 0x30
	IMAGE_TLV_ENC_KEK   = 0x31
	IMAGE_TLV_ENC_EC256 = 0x32
	IMAGE_TLV_AES_NONCE = 0x50
	IMAGE_TLV_SECRET_ID = 0x60
)

var imageTlvTypeNameMap = map[uint8]string{
	IMAGE_TLV_KEYHASH:   "KEYHASH",
	IMAGE_TLV_SHA256:    "SHA256",
	IMAGE_TLV_RSA2048:   "RSA2048",
	IMAGE_TLV_ECDSA224:  "ECDSA224",
	IMAGE_TLV_ECDSA256:  "ECDSA256",
	IMAGE_TLV_RSA3072:   "RSA3072",
	IMAGE_TLV_ED25519:   "ED25519",
	IMAGE_TLV_ENC_RSA:   "ENC_RSA",
	IMAGE_TLV_ENC_KEK:   "ENC_KEK",
	IMAGE_TLV_ENC_EC256: "ENC_EC256",
	IMAGE_TLV_AES_NONCE: "AES_NONCE",
	IMAGE_TLV_SECRET_ID: "SEC_KEY_ID",
}

var imageTlvTypeSigTypeMap = map[uint8]sec.SigType{
	IMAGE_TLV_RSA2048:  sec.SIG_TYPE_RSA2048,
	IMAGE_TLV_ECDSA224: sec.SIG_TYPE_ECDSA224,
	IMAGE_TLV_ECDSA256: sec.SIG_TYPE_ECDSA256,
	IMAGE_TLV_RSA3072:  sec.SIG_TYPE_RSA3072,
	IMAGE_TLV_ED25519:  sec.SIG_TYPE_ED25519,
}

type ImageVersion struct {
	Major    uint8
	Minor    uint8
	Rev      uint16
	BuildNum uint32
}

type ImageHdr struct {
	Magic  uint32
	Pad1   uint32
	HdrSz  uint16
	ProtSz uint16
	ImgSz  uint32
	Flags  uint32
	Vers   ImageVersion
	Pad3   uint32
}

type ImageTlvHdr struct {
	Type uint8
	Pad  uint8
	Len  uint16
}

type ImageTlv struct {
	Header ImageTlvHdr
	Data   []byte
}

type ImageTrailer struct {
	Magic     uint16
	TlvTotLen uint16
}

type Image struct {
	Header   ImageHdr
	Pad      []byte
	Body     []byte
	ProtTlvs []ImageTlv
	Tlvs     []ImageTlv
}

type ImageOffsets struct {
	Header      int
	Body        int
	ProtTrailer int
	Trailer     int
	ProtTlvs    []int
	Tlvs        []int
	TotalSize   int
}

func ImageTlvTypeIsValid(tlvType uint8) bool {
	_, ok := imageTlvTypeNameMap[tlvType]
	return ok
}

func ImageTlvTypeName(tlvType uint8) string {
	name, ok := imageTlvTypeNameMap[tlvType]
	if !ok {
		return "???"
	}

	return name
}

func ImageTlvTypeToSigType(tlvType uint8) (sec.SigType, bool) {
	typ, ok := imageTlvTypeSigTypeMap[tlvType]
	return typ, ok
}

func ImageTlvTypeIsSig(tlvType uint8) bool {
	return tlvType == IMAGE_TLV_RSA2048 ||
		tlvType == IMAGE_TLV_RSA3072 ||
		tlvType == IMAGE_TLV_ECDSA224 ||
		tlvType == IMAGE_TLV_ECDSA256 ||
		tlvType == IMAGE_TLV_ED25519
}

func ImageTlvTypeIsSecret(tlvType uint8) bool {
	return tlvType == IMAGE_TLV_ENC_RSA ||
		tlvType == IMAGE_TLV_ENC_KEK ||
		tlvType == IMAGE_TLV_ENC_EC256
}

func (ver ImageVersion) String() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ver.Major, ver.Minor, ver.Rev, ver.BuildNum)
}

func (tlv *ImageTlv) Clone() ImageTlv {
	return ImageTlv{
		Header: tlv.Header,
		Data:   append([]byte(nil), tlv.Data...),
	}
}

func (tlv *ImageTlv) Write(w io.Writer) (int, error) {
	totalSize := 0

	err := binary.Write(w, binary.LittleEndian, &tlv.Header)
	if err != nil {
		return totalSize, errors.Wrapf(err, "failed to write image TLV header")
	}
	totalSize += IMAGE_TLV_SIZE

	size, err := w.Write(tlv.Data)
	if err != nil {
		return totalSize, errors.Wrapf(err, "failed to write image TLV data")
	}
	totalSize += size

	return totalSize, nil
}

// Clone performs a deep copy of an image.
func (img *Image) Clone() Image {
	dup := Image{
		Header:   img.Header,
		Pad:      append([]byte(nil), img.Pad...),
		Body:     append([]byte(nil), img.Body...),
		ProtTlvs: make([]ImageTlv, len(img.ProtTlvs)),
		Tlvs:     make([]ImageTlv, len(img.Tlvs)),
	}

	for i, tlv := range img.ProtTlvs {
		dup.ProtTlvs[i] = tlv.Clone()
	}

	for i, tlv := range img.Tlvs {
		dup.Tlvs[i] = tlv.Clone()
	}

	return dup
}

// FindTlvIndicesIf searches an image for TLVs satisfying the given predicate
// and returns their indices.
func (img *Image) FindTlvIndicesIf(pred func(tlv ImageTlv) bool) []int {
	var idxs []int

	for i, tlv := range img.Tlvs {
		if pred(tlv) {
			idxs = append(idxs, i)
		}
	}

	return idxs
}

// FindTlvIndices searches an image for TLVs of the specified type and
// returns their indices.
func (img *Image) FindTlvIndices(tlvType uint8) []int {
	return img.FindTlvIndicesIf(func(tlv ImageTlv) bool {
		return tlv.Header.Type == tlvType
	})
}

// FindTlvIndices searches an image for TLVs satisfying the given predicate and
// returns them.
func (img *Image) FindTlvsIf(pred func(tlv ImageTlv) bool) []*ImageTlv {
	var tlvs []*ImageTlv

	idxs := img.FindTlvIndicesIf(pred)
	for _, idx := range idxs {
		tlvs = append(tlvs, &img.Tlvs[idx])
	}

	return tlvs
}

// FindTlvs retrieves all TLVs in an image's footer with the specified type.
func (img *Image) FindTlvs(tlvType uint8) []*ImageTlv {
	var tlvs []*ImageTlv

	idxs := img.FindTlvIndices(tlvType)
	for _, idx := range idxs {
		tlvs = append(tlvs, &img.Tlvs[idx])
	}

	return tlvs
}

// FindUniqueTlv retrieves a TLV in an image's footer with the specified
// type.  It returns an error if there is more than one TLV with this type.
func (i *Image) FindUniqueTlv(tlvType uint8) (*ImageTlv, error) {
	tlvs := i.FindTlvs(tlvType)
	if len(tlvs) == 0 {
		return nil, nil
	}
	if len(tlvs) > 1 {
		return nil, errors.Errorf("image contains %d TLVs with type %d",
			len(tlvs), tlvType)
	}

	return tlvs[0], nil
}

// RemoveTlvsIf removes all TLVs from an image that satisfy the supplied
// predicate.  It returns a slice of the removed TLVs.
func (i *Image) RemoveTlvsIf(pred func(tlv ImageTlv) bool) []ImageTlv {
	rmed := []ImageTlv{}

	for idx := 0; idx < len(i.Tlvs); {
		tlv := i.Tlvs[idx]
		if pred(tlv) {
			rmed = append(rmed, tlv)
			i.Tlvs = append(i.Tlvs[:idx], i.Tlvs[idx+1:]...)
		} else {
			idx++
		}
	}

	return rmed
}

// RemoveTlvsWithType removes from an image all TLVs with the specified type.
// It returns a slice of the removed TLVs.
func (i *Image) RemoveTlvsWithType(tlvType uint8) []ImageTlv {
	return i.RemoveTlvsIf(func(tlv ImageTlv) bool {
		return tlv.Header.Type == tlvType
	})
}

// ProtTrailer constructs a protected ImageTrailer corresponding to the given image.
func (img *Image) ProtTrailer() ImageTrailer {
	trailer := ImageTrailer{
		Magic:     IMAGE_PROT_TRAILER_MAGIC,
		TlvTotLen: IMAGE_TRAILER_SIZE,
	}
	for _, tlv := range img.ProtTlvs {
		trailer.TlvTotLen += IMAGE_TLV_SIZE + tlv.Header.Len
	}

	return trailer
}

// Trailer constructs an ImageTrailer corresponding to the given image.
func (img *Image) Trailer() ImageTrailer {
	trailer := ImageTrailer{
		Magic:     IMAGE_TRAILER_MAGIC,
		TlvTotLen: IMAGE_TRAILER_SIZE,
	}
	for _, tlv := range img.Tlvs {
		trailer.TlvTotLen += IMAGE_TLV_SIZE + tlv.Header.Len
	}

	return trailer
}

// Hash retrieves the contents of an image's SHA256 TLV.
func (i *Image) Hash() ([]byte, error) {
	tlv, err := i.FindUniqueTlv(IMAGE_TLV_SHA256)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve image hash")
	}

	if tlv == nil {
		return nil, errors.Errorf(
			"failed to retrieve image hash: image does not contain hash TLV")
	}

	return tlv.Data, nil
}

// CalcHash calculates a SHA256 of the given image.
func (i *Image) CalcHash() ([]byte, error) {
	return calcHash(nil, i.Header, i.Pad, i.Body, i.ProtTlvs)
}

// WritePlusOffsets writes a binary image to the given writer.  It returns
// the offsets of the image components that got written.
func (i *Image) WritePlusOffsets(w io.Writer) (ImageOffsets, error) {
	offs := ImageOffsets{}
	offset := 0

	offs.Header = offset

	err := binary.Write(w, binary.LittleEndian, &i.Header)
	if err != nil {
		return offs, errors.Wrapf(err, "failed to write image header")
	}
	offset += IMAGE_HEADER_SIZE

	err = binary.Write(w, binary.LittleEndian, i.Pad)
	if err != nil {
		return offs, errors.Wrapf(err, "failed to write image padding")
	}
	offset += len(i.Pad)

	offs.Body = offset
	size, err := w.Write(i.Body)
	if err != nil {
		return offs, errors.Wrapf(err, "failed to write image body")
	}
	offset += size

	if i.Header.ProtSz > 0 {
		protTrailer := i.ProtTrailer()
		offs.ProtTrailer = offset
		err = binary.Write(w, binary.LittleEndian, &protTrailer)
		if err != nil {
			return offs, errors.Wrapf(err, "failed to write image trailer")
		}
		offset += IMAGE_TRAILER_SIZE

		for _, tlv := range i.ProtTlvs {
			offs.ProtTlvs = append(offs.ProtTlvs, offset)
			size, err := tlv.Write(w)
			if err != nil {
				return offs, errors.Wrapf(err, "failed to write image TLV")
			}
			offset += size
		}
	}

	trailer := i.Trailer()
	offs.Trailer = offset
	err = binary.Write(w, binary.LittleEndian, &trailer)
	if err != nil {
		return offs, errors.Wrapf(err, "failed to write image trailer")
	}
	offset += IMAGE_TRAILER_SIZE

	for _, tlv := range i.Tlvs {
		offs.Tlvs = append(offs.Tlvs, offset)
		size, err := tlv.Write(w)
		if err != nil {
			return offs, errors.Wrapf(err, "failed to write image TLV")
		}
		offset += size
	}

	offs.TotalSize = offset

	return offs, nil
}

// Offsets returns the offsets of each of an image's components if it were
// serialized.
func (i *Image) Offsets() (ImageOffsets, error) {
	return i.WritePlusOffsets(ioutil.Discard)
}

// TotalSize returns the size of the image if it were serialized, in bytes.
func (i *Image) TotalSize() (int, error) {
	offs, err := i.Offsets()
	if err != nil {
		return 0, err
	}
	return offs.TotalSize, nil
}

// Write serializes and writes a Mynewt image.
func (i *Image) Write(w io.Writer) (int, error) {
	offs, err := i.WritePlusOffsets(w)
	if err != nil {
		return 0, err
	}

	return offs.TotalSize, nil
}

// WriteToFile writes a Mynewt image to a file.
func (i *Image) WriteToFile(filename string) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		return errors.Wrapf(err, "failed to open image destination file")
	}

	if _, err := i.Write(f); err != nil {
		return errors.Wrapf(err, "failed to write image")
	}

	return nil
}

// CollectSigs returns a slice of all signatures present in an image's
// trailer.
func (img *Image) CollectSigs() ([]sec.Sig, error) {
	var sigs []sec.Sig

	var keyHashTlv *ImageTlv
	for i, _ := range img.Tlvs {
		t := &img.Tlvs[i]

		if t.Header.Type == IMAGE_TLV_KEYHASH {
			if keyHashTlv != nil {
				return nil, errors.Errorf(
					"image contains keyhash tlv without subsequent signature")
			}
			keyHashTlv = t
		} else {
			sigType, ok := ImageTlvTypeToSigType(t.Header.Type)
			if ok {
				if keyHashTlv == nil {
					return nil, errors.Errorf(
						"image contains signature tlv without preceding keyhash")
				}

				sigs = append(sigs, sec.Sig{
					Type:    sigType,
					KeyHash: keyHashTlv.Data,
					Data:    t.Data,
				})

				keyHashTlv = nil
			}
		}
	}

	return sigs, nil
}

// CollectSecret finds the "secret" TLV in an image and returns its body.  It
// returns nil if there is no "secret" TLV.
func (img *Image) CollectSecret() ([]byte, error) {
	tlv, err := img.FindUniqueTlv(IMAGE_TLV_ENC_RSA)
	if err != nil {
		return nil, err
	}

	if tlv == nil {
		return nil, nil
	}

	return tlv.Data, nil
}

// ExtractSecret finds the "secret" TLV in an image, removes it, and returns
// its body.  It returns nil if there is no "secret" TLV.
func (img *Image) ExtractSecret() ([]byte, error) {
	tlvs := img.RemoveTlvsWithType(IMAGE_TLV_ENC_RSA)

	if len(tlvs) == 0 {
		return nil, nil
	}

	if len(tlvs) > 1 {
		return nil, errors.Errorf(
			"image contains >1 ENC_RSA TLVs (%d)", len(tlvs))
	}

	return tlvs[0].Data, nil
}

// Encrypt encrypts an image body and adds a "secret" TLV.  It does NOT set the
// "encrypted" flag in the image header.
func Encrypt(img Image, pubEncKey sec.PubEncKey) (Image, error) {
	dup := img.Clone()

	tlvp, err := dup.FindUniqueTlv(IMAGE_TLV_ENC_RSA)
	if err != nil {
		return dup, err
	}
	if tlvp != nil {
		return dup, errors.Errorf("image already contains an ENC_RSA TLV")
	}

	plainSecret, err := GeneratePlainSecret()
	if err != nil {
		return dup, err
	}

	cipherSecret, err := pubEncKey.Encrypt(plainSecret)
	if err != nil {
		return dup, err
	}

	body, err := sec.EncryptAES(dup.Body, plainSecret, nil)
	if err != nil {
		return dup, err
	}
	dup.Body = body

	tlv, err := GenerateEncTlv(cipherSecret)
	if err != nil {
		return dup, err
	}
	dup.Tlvs = append(dup.Tlvs, tlv)

	return dup, nil
}

// Decrypt decrypts an image body and strips the "secret" TLV.  It does NOT
// clear the "encrypted" flag in the image header.
func Decrypt(img Image, privEncKey sec.PrivEncKey) (Image, error) {
	dup := img.Clone()

	tlvs := dup.RemoveTlvsIf(func(tlv ImageTlv) bool {
		return ImageTlvTypeIsSecret(tlv.Header.Type)
	})
	if len(tlvs) != 1 {
		return dup, errors.Errorf(
			"failed to decrypt image: wrong count of \"secret\" TLVs; "+
				"have=%d want=1", len(tlvs))
	}

	cipherSecret := tlvs[0].Data
	plainSecret, err := privEncKey.Decrypt(cipherSecret)
	if err != nil {
		return img, err
	}

	body, err := sec.EncryptAES(dup.Body, plainSecret, nil)
	if err != nil {
		return img, err
	}

	dup.Body = body

	return dup, nil
}

// IsEncrypted indicates whether an image's "encrypted" flag is set.
func (img *Image) IsEncrypted() bool {
	return img.Header.Flags&IMAGE_F_ENCRYPTED != 0
}
