package sec

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/apache/mynewt-artifact/errors"
	"golang.org/x/crypto/ed25519"
)

func parsePubPemKey(data []byte) (interface{}, error) {
	p, _ := pem.Decode(data)
	if p == nil {
		return nil, errors.Errorf(
			"error parsing public key: unknown format")
	}

	if p.Type != "PUBLIC KEY" && p.Type != "RSA PUBLIC KEY" {
		return nil, errors.Errorf(
			"error parsing public key: PEM type=\"%s\"", p.Type)
	}

	itf, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		// Not x509; assume ed25519.
		pkix, err := unmarshalEd25519(p.Bytes)
		if err != nil {
			return nil, errors.Errorf(
				"error parsing public key: unrecognized format")
		}

		if len(pkix.BitString.Bytes) != ed25519.PublicKeySize {
			return nil, errors.Errorf(
				"error parsing public key: "+
					"ed25519 public key has wrong size: have=%d want=%d",
				len(pkix.BitString.Bytes), ed25519.PublicKeySize)
		}

		itf = ed25519.PublicKey(pkix.BitString.Bytes)
	}

	return itf, nil
}
