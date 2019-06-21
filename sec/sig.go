package sec

import (
	"bytes"
	"crypto"
	"crypto/rsa"

	"github.com/apache/mynewt-artifact/errors"
)

type Sig struct {
	KeyHash []byte
	Data    []byte
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
