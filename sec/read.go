package sec

import (
	"io/ioutil"

	"github.com/apache/mynewt-artifact/errors"
)

// ReadPubSignKey reads a public signing key from a file.
func ReadPubSignKey(filename string) (PubSignKey, error) {
	keyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return PubSignKey{}, errors.Wrapf(err, "error reading key file")
	}

	return ParsePubSignKey(keyBytes)
}

// ReadPubSignKeys reads a set of public signing keys from several files.
func ReadPubSignKeys(filenames []string) ([]PubSignKey, error) {
	keys := make([]PubSignKey, len(filenames))

	for i, filename := range filenames {
		key, err := ReadPubSignKey(filename)
		if err != nil {
			return nil, err
		}

		keys[i] = key
	}

	return keys, nil
}

// ReadPrivSignKey reads a private signing key from a file.
func ReadPrivSignKey(filename string) (PrivSignKey, error) {
	keyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return PrivSignKey{}, errors.Wrapf(err, "error reading key file")
	}

	return ParsePrivSignKey(keyBytes)
}

// ReadPubSignKeys reads a set of private signing keys from several files.
func ReadPrivSignKeys(filenames []string) ([]PrivSignKey, error) {
	keys := make([]PrivSignKey, len(filenames))

	for i, filename := range filenames {
		key, err := ReadPrivSignKey(filename)
		if err != nil {
			return nil, err
		}

		keys[i] = key
	}

	return keys, nil
}

// ReadPubEncKey reads a public encryption key from a file.
func ReadPubEncKey(filename string) (PubEncKey, error) {
	keyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return PubEncKey{}, errors.Wrapf(err, "error reading key file")
	}

	return ParsePubEncKey(keyBytes)
}

// ReadPubSignKeys reads a set of public encryption keys from several files.
func ReadPubEncKeys(filenames []string) ([]PubEncKey, error) {
	keys := make([]PubEncKey, len(filenames))
	for i, filename := range filenames {
		key, err := ReadPubEncKey(filename)
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}

	return keys, nil
}

// ReadPubEncKey reads a private encryption key from a file.
func ReadPrivEncKey(filename string) (PrivEncKey, error) {
	keyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return PrivEncKey{}, errors.Wrapf(err, "error reading key file")
	}

	return ParsePrivEncKey(keyBytes)
}

// ReadPubSignKeys reads a set of private encryption keys from several files.
func ReadPrivEncKeys(filenames []string) ([]PrivEncKey, error) {
	keys := make([]PrivEncKey, len(filenames))
	for i, filename := range filenames {
		key, err := ReadPrivEncKey(filename)
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}

	return keys, nil
}
