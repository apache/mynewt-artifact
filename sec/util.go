package sec

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/apache/mynewt-artifact/errors"
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
		return nil, errors.Wrapf(err, "error parsing public key")
	}

	return itf, nil
}
