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

package sec

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	"github.com/apache/mynewt-artifact/errors"
	"golang.org/x/crypto/ed25519"
)

type PrivSignKey struct {
	// Only one of these members is non-nil.
	Rsa     *rsa.PrivateKey
	Ec      *ecdsa.PrivateKey
	Ed25519 *ed25519.PrivateKey
}

type PubSignKey struct {
	Rsa     *rsa.PublicKey
	Ec      *ecdsa.PublicKey
	Ed25519 ed25519.PublicKey
}

type Sig struct {
	KeyHash []byte
	Data    []byte
}

var oidPrivateKeyEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

func parsePrivSignKeyItf(keyBytes []byte) (interface{}, error) {
	var privKey interface{}
	var err error

	block, data := pem.Decode(keyBytes)
	if block != nil && block.Type == "EC PARAMETERS" {
		/*
		 * Openssl prepends an EC PARAMETERS block before the
		 * key itself.  If we see this first, just skip it,
		 * and go on to the data block.
		 */
		block, _ = pem.Decode(data)
	}
	if block != nil && block.Type == "RSA PRIVATE KEY" {
		/*
		 * ParsePKCS1PrivateKey returns an RSA private key from its ASN.1
		 * PKCS#1 DER encoded form.
		 */
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "Priv key parsing failed")
		}
	}
	if block != nil && block.Type == "EC PRIVATE KEY" {
		/*
		 * ParseECPrivateKey returns a EC private key
		 */
		privKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "Priv key parsing failed")
		}
	}
	if block != nil && block.Type == "PRIVATE KEY" {
		// This indicates a PKCS#8 unencrypted private key.
		// The particular type of key will be indicated within
		// the key itself.
		privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if block != nil && block.Type == "ENCRYPTED PRIVATE KEY" {
		// This indicates a PKCS#8 key wrapped with PKCS#5
		// encryption.
		privKey, err = parseEncryptedPrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrapf(
				err, "Unable to decode encrypted private key")
		}
	}
	if privKey == nil {
		return nil, errors.Errorf(
			"Unknown private key format, EC/RSA private " +
				"key in PEM format only.")
	}

	return privKey, nil
}

func ParsePubSignKey(keyBytes []byte) (PubSignKey, error) {
	key := PubSignKey{}

	itf, err := parsePubPemKey(keyBytes)
	if err != nil {
		return key, err
	}

	switch pub := itf.(type) {
	case *rsa.PublicKey:
		key.Rsa = pub
	case *ecdsa.PublicKey:
		key.Ec = pub
	case ed25519.PublicKey:
		key.Ed25519 = pub
	default:
		return key, errors.Errorf("unknown public signing key type: %T", pub)
	}

	return key, nil
}

func ParsePrivSignKey(keyBytes []byte) (PrivSignKey, error) {
	key := PrivSignKey{}

	itf, err := parsePrivSignKeyItf(keyBytes)
	if err != nil {
		return key, err
	}

	switch priv := itf.(type) {
	case *rsa.PrivateKey:
		key.Rsa = priv
	case *ecdsa.PrivateKey:
		key.Ec = priv
	case ed25519.PrivateKey:
		key.Ed25519 = &priv
	default:
		return key, errors.Errorf("unknown private key type: %T", itf)
	}

	return key, nil
}

func (key *PrivSignKey) AssertValid() {
	if key.Rsa == nil && key.Ec == nil && key.Ed25519 == nil {
		panic("invalid key; neither RSA nor ECC nor ED25519")
	}
}

func (key *PrivSignKey) PubKey() PubSignKey {
	key.AssertValid()

	if key.Rsa != nil {
		return PubSignKey{Rsa: &key.Rsa.PublicKey}
	} else if key.Ec != nil {
		return PubSignKey{Ec: &key.Ec.PublicKey}
	} else {
		x := PubSignKey{Ed25519: key.Ed25519.Public().(ed25519.PublicKey)}
		return x
	}
}

func (key *PrivSignKey) PubBytes() ([]byte, error) {
	pk := key.PubKey()
	return pk.Bytes()
}

func (key *PrivSignKey) SigLen() uint16 {
	key.AssertValid()

	if key.Rsa != nil {
		pubk := key.Rsa.Public().(*rsa.PublicKey)
		return uint16(pubk.Size())
	} else if key.Ec != nil {
		switch key.Ec.Curve.Params().Name {
		case "P-224":
			return 68
		case "P-256":
			return 72
		default:
			return 0
		}
	} else {
		return ed25519.SignatureSize
	}
}

func (key *PubSignKey) AssertValid() {
	if key.Rsa == nil && key.Ec == nil && key.Ed25519 == nil {
		panic("invalid public key; neither RSA nor ECC nor ED25519")
	}

	if key.Ed25519 != nil {
		if _, err := marshalEd25519(key.Ed25519); err != nil {
			panic("invalid public ed25519 key")
		}
	}
}

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

func marshalEd25519(pubbytes []uint8) ([]uint8, error) {
	pkix := pkixPublicKey{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: oidPrivateKeyEd25519,
		},
		BitString: asn1.BitString{
			Bytes:     pubbytes,
			BitLength: 8 * len(pubbytes),
		},
	}

	ret, err := asn1.Marshal(pkix)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to encode ed25519 public key")
	}

	return ret, nil
}

func unmarshalEd25519(pubbytes []uint8) (pkixPublicKey, error) {
	var pkix pkixPublicKey

	if _, err := asn1.Unmarshal(pubbytes, &pkix); err != nil {
		return pkix, errors.Wrapf(err, "failed to parse ed25519 public key")
	}

	return pkix, nil
}

func (key *PubSignKey) Bytes() ([]byte, error) {
	key.AssertValid()

	var b []byte
	var err error

	if key.Rsa != nil {
		b, err = asn1.Marshal(*key.Rsa)
		if err != nil {
			return nil, err
		}
	} else if key.Ec != nil {
		switch key.Ec.Curve.Params().Name {
		case "P-224":
			fallthrough
		case "P-256":
			b, err = x509.MarshalPKIXPublicKey(key.Ec)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.Errorf("unsupported ECC curve")
		}
	} else {
		b, err = marshalEd25519([]byte(key.Ed25519))
		if err != nil {
			return nil, err
		}
	}

	return b, nil
}

func checkOneKeyOneSig(k PubSignKey, sig Sig, hash []byte) (bool, error) {
	pubBytes, err := k.Bytes()
	if err != nil {
		return false, errors.WithStack(err)
	}
	keyHash := RawKeyHash(pubBytes)

	if !bytes.Equal(keyHash, sig.KeyHash) {
		return false, nil
	}

	if k.Rsa != nil {
		opts := rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}
		err := rsa.VerifyPSS(k.Rsa, crypto.SHA256, hash, sig.Data, &opts)
		return err == nil, nil
	}

	if k.Ec != nil {
		return false, errors.Errorf(
			"ecdsa signature verification not supported")
	}

	if k.Ed25519 != nil {
		return ed25519.Verify(k.Ed25519, hash, sig.Data), nil
	}

	return false, nil
}

func VerifySigs(key PubSignKey, sigs []Sig, hash []byte) (int, error) {
	for i, s := range sigs {
		match, err := checkOneKeyOneSig(key, s, hash)
		if err != nil {
			return -1, err
		}
		if match {
			return i, nil
		}
	}

	return -1, nil
}
