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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"io/ioutil"
	"math/big"

	"github.com/apache/mynewt-artifact/errors"
	"github.com/apache/mynewt-artifact/sec"
	"golang.org/x/crypto/ed25519"
)

type ImageCreator struct {
	Body         []byte
	Version      ImageVersion
	SigKeys      []sec.PrivSignKey
	PlainSecret  []byte
	CipherSecret []byte
	HeaderSize   int
	InitialHash  []byte
	Bootable     bool
}

type ImageCreateOpts struct {
	SrcBinFilename    string
	SrcEncKeyFilename string
	Version           ImageVersion
	SigKeys           []sec.PrivSignKey
	LoaderHash        []byte
}

type ECDSASig struct {
	R *big.Int
	S *big.Int
}

func NewImageCreator() ImageCreator {
	return ImageCreator{
		HeaderSize: IMAGE_HEADER_SIZE,
		Bootable:   true,
	}
}

func sigTlvType(key sec.PrivSignKey) uint8 {
	key.AssertValid()

	if key.Rsa != nil {
		pubk := key.Rsa.Public().(*rsa.PublicKey)
		switch pubk.Size() {
		case 256:
			return IMAGE_TLV_RSA2048
		case 384:
			return IMAGE_TLV_RSA3072
		default:
			return 0
		}
	} else if key.Ec != nil {
		switch key.Ec.Curve.Params().Name {
		case "P-224":
			return IMAGE_TLV_ECDSA224
		case "P-256":
			return IMAGE_TLV_ECDSA256
		default:
			return 0
		}
	} else {
		return IMAGE_TLV_ED25519
	}
}

func GenerateEncTlv(cipherSecret []byte) (ImageTlv, error) {
	var encType uint8

	if len(cipherSecret) == 256 {
		encType = IMAGE_TLV_ENC_RSA
	} else if len(cipherSecret) == 24 {
		encType = IMAGE_TLV_ENC_KEK
	} else {
		return ImageTlv{}, errors.Errorf("invalid enc TLV size: %d", len(cipherSecret))
	}

	return ImageTlv{
		Header: ImageTlvHdr{
			Type: encType,
			Pad:  0,
			Len:  uint16(len(cipherSecret)),
		},
		Data: cipherSecret,
	}, nil
}

func GenerateSigRsa(key sec.PrivSignKey, hash []byte) ([]byte, error) {
	opts := rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}
	signature, err := rsa.SignPSS(
		rand.Reader, key.Rsa, crypto.SHA256, hash, &opts)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to compute signature")
	}

	return signature, nil
}

func GenerateSigEc(key sec.PrivSignKey, hash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, key.Ec, hash)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to compute signature")
	}

	ECDSA := ECDSASig{
		R: r,
		S: s,
	}

	signature, err := asn1.Marshal(ECDSA)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to construct signature")
	}

	sigLen := key.SigLen()
	if len(signature) > int(sigLen) {
		return nil, errors.Errorf("signature truncated")
	}

	pad := make([]byte, int(sigLen)-len(signature))
	signature = append(signature, pad...)

	return signature, nil
}

func GenerateSigEd25519(key sec.PrivSignKey, hash []byte) ([]byte, error) {
	sig := ed25519.Sign(key.Ed25519, hash)

	if len(sig) != ed25519.SignatureSize {
		return nil, errors.Errorf(
			"ed25519 signature has wrong length: have=%d want=%d",
			len(sig), ed25519.SignatureSize)
	}

	return sig, nil
}

func GenerateSig(key sec.PrivSignKey, hash []byte) ([]byte, error) {
	key.AssertValid()

	if key.Rsa != nil {
		return GenerateSigRsa(key, hash)
	} else if key.Ec != nil {
		return GenerateSigEc(key, hash)
	} else {
		return GenerateSigEd25519(key, hash)
	}
}

func BuildKeyHashTlv(keyBytes []byte) ImageTlv {
	data := sec.RawKeyHash(keyBytes)
	return ImageTlv{
		Header: ImageTlvHdr{
			Type: IMAGE_TLV_KEYHASH,
			Pad:  0,
			Len:  uint16(len(data)),
		},
		Data: data,
	}
}

func BuildSigTlvs(keys []sec.PrivSignKey, hash []byte) ([]ImageTlv, error) {
	var tlvs []ImageTlv

	for _, key := range keys {
		key.AssertValid()

		// Key hash TLV.
		pubKey, err := key.PubBytes()
		if err != nil {
			return nil, err
		}
		tlv := BuildKeyHashTlv(pubKey)
		tlvs = append(tlvs, tlv)

		// Signature TLV.
		sig, err := GenerateSig(key, hash)
		if err != nil {
			return nil, err
		}
		tlv = ImageTlv{
			Header: ImageTlvHdr{
				Type: sigTlvType(key),
				Len:  uint16(len(sig)),
			},
			Data: sig,
		}
		tlvs = append(tlvs, tlv)
	}

	return tlvs, nil
}

func GeneratePlainSecret() ([]byte, error) {
	plainSecret := make([]byte, 16)
	if _, err := rand.Read(plainSecret); err != nil {
		return nil, errors.Wrapf(err, "random generation error")
	}

	return plainSecret, nil
}

func GenerateImage(opts ImageCreateOpts) (Image, error) {
	ic := NewImageCreator()

	srcBin, err := ioutil.ReadFile(opts.SrcBinFilename)
	if err != nil {
		return Image{}, errors.Wrapf(err, "Can't read app binary")
	}

	ic.Body = srcBin
	ic.Version = opts.Version
	ic.SigKeys = opts.SigKeys

	if opts.LoaderHash != nil {
		ic.InitialHash = opts.LoaderHash
		ic.Bootable = false
	} else {
		ic.Bootable = true
	}

	if opts.SrcEncKeyFilename != "" {
		plainSecret, err := GeneratePlainSecret()
		if err != nil {
			return Image{}, err
		}

		pubKeBytes, err := ioutil.ReadFile(opts.SrcEncKeyFilename)
		if err != nil {
			return Image{}, errors.Wrapf(err, "error reading pubkey file")
		}

		pubKe, err := sec.ParsePubEncKey(pubKeBytes)
		if err != nil {
			return Image{}, err
		}

		cipherSecret, err := pubKe.Encrypt(plainSecret)
		if err != nil {
			return Image{}, err
		}

		ic.PlainSecret = plainSecret
		ic.CipherSecret = cipherSecret
	}

	ri, err := ic.Create()
	if err != nil {
		return Image{}, err
	}

	return ri, nil
}

func calcHash(initialHash []byte, hdr ImageHdr, pad []byte,
	plainBody []byte) ([]byte, error) {

	hash := sha256.New()

	add := func(itf interface{}) error {
		b := &bytes.Buffer{}
		if err := binary.Write(b, binary.LittleEndian, itf); err != nil {
			return err
		}
		if err := binary.Write(hash, binary.LittleEndian, itf); err != nil {
			return errors.Wrapf(err, "failed to hash data")
		}

		return nil
	}

	if initialHash != nil {
		if err := add(initialHash); err != nil {
			return nil, err
		}
	}

	if err := add(hdr); err != nil {
		return nil, err
	}

	if err := add(pad); err != nil {
		return nil, err
	}

	extra := hdr.HdrSz - IMAGE_HEADER_SIZE
	if extra > 0 {
		b := make([]byte, extra)
		if err := add(b); err != nil {
			return nil, err
		}
	}

	if err := add(plainBody); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (ic *ImageCreator) Create() (Image, error) {
	img := Image{}

	// First the header
	img.Header = ImageHdr{
		Magic: IMAGE_MAGIC,
		Pad1:  0,
		HdrSz: IMAGE_HEADER_SIZE,
		Pad2:  0,
		ImgSz: uint32(len(ic.Body)),
		Flags: 0,
		Vers:  ic.Version,
		Pad3:  0,
	}

	if !ic.Bootable {
		img.Header.Flags |= IMAGE_F_NON_BOOTABLE
	}

	if ic.CipherSecret != nil {
		img.Header.Flags |= IMAGE_F_ENCRYPTED
	}

	if ic.HeaderSize != 0 {
		// Pad the header out to the given size.  There will just be zeros
		// between the header and the start of the image when it is padded.
		extra := ic.HeaderSize - IMAGE_HEADER_SIZE
		if extra < 0 {
			return img, errors.Errorf(
				"image header must be at least %d bytes", IMAGE_HEADER_SIZE)
		}

		img.Header.HdrSz = uint16(ic.HeaderSize)
		img.Pad = make([]byte, extra)
	}

	hashBytes, err := calcHash(ic.InitialHash, img.Header, img.Pad, ic.Body)
	if err != nil {
		return img, err
	}

	// Followed by data.
	if ic.CipherSecret != nil {
		encBody, err := sec.EncryptAES(ic.Body, ic.PlainSecret)
		if err != nil {
			return img, err
		}
		img.Body = append(img.Body, encBody...)
	} else {
		img.Body = append(img.Body, ic.Body...)
	}

	// Hash TLV.
	tlv := ImageTlv{
		Header: ImageTlvHdr{
			Type: IMAGE_TLV_SHA256,
			Pad:  0,
			Len:  uint16(len(hashBytes)),
		},
		Data: hashBytes,
	}
	img.Tlvs = append(img.Tlvs, tlv)

	tlvs, err := BuildSigTlvs(ic.SigKeys, hashBytes)
	if err != nil {
		return img, err
	}
	img.Tlvs = append(img.Tlvs, tlvs...)

	if ic.CipherSecret != nil {
		tlv, err := GenerateEncTlv(ic.CipherSecret)
		if err != nil {
			return img, err
		}
		img.Tlvs = append(img.Tlvs, tlv)
	}

	return img, nil
}
