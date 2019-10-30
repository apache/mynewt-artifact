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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"io"

	keywrap "github.com/NickBall/go-aes-key-wrap"
	"github.com/apache/mynewt-artifact/errors"
)

type EncType int

const (
	ENC_TYPE_AES_128 EncType = iota
	ENC_TYPE_AES_256
	ENC_TYPE_RSA_2048
)

// XXX: Only RSA supported for now.
type PrivEncKey struct {
	Rsa *rsa.PrivateKey
}

type PubEncKey struct {
	Rsa *rsa.PublicKey
	Aes cipher.Block
}

var encTypeNameMap = map[EncType]string{
	ENC_TYPE_AES_128:  "aes128",
	ENC_TYPE_AES_256:  "aes256",
	ENC_TYPE_RSA_2048: "rsa2048",
}

func EncTypeString(typ EncType) string {
	s := encTypeNameMap[typ]
	if s == "" {
		return "unknown"
	} else {
		return s
	}
}

func EncStringType(s string) (EncType, error) {
	for k, v := range encTypeNameMap {
		if s == v {
			return k, nil
		}
	}

	return 0, errors.Errorf("unknown enc type name: \"%s\"", s)
}

func parsePubKePem(b []byte) (PubEncKey, error) {
	key := PubEncKey{}

	itf, err := parsePubPemKey(b)
	if err != nil {
		return key, err
	}

	switch pub := itf.(type) {
	case *rsa.PublicKey:
		key.Rsa = pub
	default:
		return key, errors.Errorf(
			"unknown public encryption key type: %T", pub)
	}

	return key, nil
}

func parsePubKeBase64(keyBytes []byte) (PubEncKey, error) {
	if len(keyBytes) != 16 && len(keyBytes) != 32 {
		return PubEncKey{}, errors.Errorf(
			"unexpected key size: %d != 16 or 32", len(keyBytes))
	}

	cipher, err := aes.NewCipher(keyBytes)
	if err != nil {
		return PubEncKey{}, errors.Wrapf(err,
			"error creating keywrap cipher")
	}

	return PubEncKey{
		Aes: cipher,
	}, nil
}

func ParsePubEncKey(keyBytes []byte) (PubEncKey, error) {
	b, err := base64.StdEncoding.DecodeString(string(keyBytes))
	if err == nil {
		return parsePubKeBase64(b)
	}

	// Not base64-encoded; assume it is PEM.
	return parsePubKePem(keyBytes)
}

func (key *PrivEncKey) PubEncKey() PubEncKey {
	return PubEncKey{
		Rsa: key.Rsa.Public().(*rsa.PublicKey),
	}
}

func (key *PubEncKey) AssertValid() {
	if key.Rsa == nil && key.Aes == nil {
		panic("invalid public encryption key; neither RSA nor AES")
	}
}

func (key *PubEncKey) EncType() (EncType, error) {
	if key.Rsa != nil {
		return ENC_TYPE_RSA_2048, nil
	} else if key.Aes != nil {
		switch key.Aes.BlockSize() {
		case 128 / 8:
			return ENC_TYPE_AES_128, nil
		case 256 / 8:
			return ENC_TYPE_AES_256, nil
		default:
			return 0, errors.Errorf("illegal AES key block size: %d", key.Aes.BlockSize())
		}
	} else {
		return 0, errors.Errorf("invalid enc key: all members nil")
	}
}

func encryptRsa(pubk *rsa.PublicKey, plainSecret []byte) ([]byte, error) {
	rng := rand.Reader
	cipherSecret, err := rsa.EncryptOAEP(
		sha256.New(), rng, pubk, plainSecret, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "Error from encryption")
	}

	return cipherSecret, nil
}

func encryptAes(c cipher.Block, plain []byte) ([]byte, error) {
	ciph, err := keywrap.Wrap(c, plain)
	if err != nil {
		return nil, errors.Wrapf(err, "error key-wrapping")
	}

	return ciph, nil
}

func (k *PubEncKey) Encrypt(plain []byte) ([]byte, error) {
	k.AssertValid()

	if k.Rsa != nil {
		return encryptRsa(k.Rsa, plain)
	} else {
		return encryptAes(k.Aes, plain)
	}
}

func ParsePrivEncKey(keyBytes []byte) (PrivEncKey, error) {
	rpk, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return PrivEncKey{}, errors.Wrapf(err, "error parsing private key file")
	}

	return PrivEncKey{
		Rsa: rpk,
	}, nil
}

func decryptRsa(privk *rsa.PrivateKey, ciph []byte) ([]byte, error) {
	rng := rand.Reader
	plain, err := rsa.DecryptOAEP(sha256.New(), rng, privk, ciph, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "error from encryption")
	}

	return plain, nil
}

func (k *PrivEncKey) Decrypt(ciph []byte) ([]byte, error) {
	return decryptRsa(k.Rsa, ciph)
}

func EncryptAES(plain []byte, secret []byte, nonce []byte) ([]byte, error) {
	blk, err := aes.NewCipher(secret)
	if err != nil {
		return nil, errors.Errorf("Failed to create block cipher")
	}

	var iv []byte
	if nonce == nil {
		iv = make([]byte, 16)
	} else {
		zeros := make([]byte, 8)
		iv = append(nonce, zeros...)
	}

	stream := cipher.NewCTR(blk, iv)

	dataBuf := make([]byte, 16)
	encBuf := make([]byte, 16)
	r := bytes.NewReader(plain)
	w := bytes.Buffer{}
	for {
		cnt, err := r.Read(dataBuf)
		if err != nil && err != io.EOF {
			return nil, errors.Wrapf(err, "Failed to read from plaintext")
		}
		if cnt == 0 {
			break
		}

		stream.XORKeyStream(encBuf, dataBuf[0:cnt])
		if _, err = w.Write(encBuf[0:cnt]); err != nil {
			return nil, errors.Wrapf(err, "failed to write ciphertext")
		}
	}

	return w.Bytes(), nil
}