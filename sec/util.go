package sec

import (
	"crypto/aes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"

	"github.com/apache/mynewt-artifact/errors"
	"golang.org/x/crypto/ed25519"
)

var oidPrivateKeyEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

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

func parsePubBase64Key(data []byte) (interface{}, error) {
	b64, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, errors.Wrapf(err, "error decoding base64 key data")
	}

	if len(b64) != 16 {
		return nil, errors.Errorf(
			"unexpected key size: have=%d want=16", len(b64))
	}

	cipher, err := aes.NewCipher(b64)
	if err != nil {
		return nil, errors.Wrapf(err, "error creating keywrap cipher")
	}

	return cipher, nil
}

func parsePubKey(data []byte) (interface{}, error) {
	pemKey, pemErr := parsePubPemKey(data)
	if pemErr == nil {
		return pemKey, nil
	}

	b64Key, b64Err := parsePubBase64Key(data)
	if b64Err == nil {
		return b64Key, nil
	}

	return nil, errors.Errorf(
		"failed to parse public key: %s, %s", pemErr.Error(), b64Err.Error())
}

// Parse an ed25519 PKCS#8 certificate
func parsePrivEd25519Pkcs8(der []byte) (ed25519.PrivateKey, error) {
	var privKey struct {
		Version int
		Algo    pkix.AlgorithmIdentifier
		SeedKey []byte
	}

	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.Errorf("error parsing ASN1 key")
	}
	switch {
	case privKey.Algo.Algorithm.Equal(oidPrivateKeyEd25519):
		// ASN1 header (type+length) + seed
		if len(privKey.SeedKey) != ed25519.SeedSize+2 {
			return nil, errors.Errorf("unexpected size for Ed25519 private key")
		}
		key := ed25519.NewKeyFromSeed(privKey.SeedKey[2:])
		return key, nil
	default:
		return nil, errors.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}

func parsePrivPemKey(keyBytes []byte) (interface{}, error) {
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
		if err != nil {
			return nil, errors.Wrapf(err, "Priv key parsing failed")
		}
	}
	if block != nil && block.Type == "PRIVATE KEY" {
		// This indicates a PKCS#8 unencrypted private key.
		// The particular type of key will be indicated within
		// the key itself.
		privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			var _privKey interface{}
			_privKey, err = parsePrivEd25519Pkcs8(block.Bytes)
			if err != nil {
				return nil, errors.Wrapf(err, "private key parsing failed")
			}
			privKey = _privKey
		}
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

func parsePrivDerKey(keyBytes []byte) (interface{}, error) {
	// *rsa.PrivateKey
	rsaKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err == nil {
		return rsaKey, nil
	}

	// *ed25519.PrivateKey
	ed25519Key, err := parsePrivEd25519Pkcs8(keyBytes)
	if err == nil {
		return ed25519Key, nil
	}

	return nil, errors.Wrapf(err, "error parsing private key file")
}

func parsePrivKey(keyBytes []byte) (interface{}, error) {
	itf, err := parsePrivPemKey(keyBytes)
	if err == nil {
		return itf, nil
	}

	itf, err = parsePrivDerKey(keyBytes)
	if err == nil {
		return itf, nil
	}

	return nil, err
}
