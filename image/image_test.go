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
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/apache/mynewt-artifact/errors"
	"github.com/apache/mynewt-artifact/manifest"
	"github.com/apache/mynewt-artifact/sec"
)

const testdataPath = "testdata"

type entry struct {
	basename  string
	form      bool
	structure bool
	hash      bool
	man       bool
	sign      bool
	encrypted bool
}

func readImageData(basename string) []byte {
	path := fmt.Sprintf("%s/%s.img", testdataPath, basename)

	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("failed to read image file \"%s\": %s", path, err.Error()))
	}

	return data
}

func readManifest(basename string) manifest.Manifest {
	path := fmt.Sprintf("%s/%s.json", testdataPath, basename)

	man, err := manifest.ReadManifest(path)
	if err != nil {
		panic(fmt.Sprintf("failed to read manifest file \"%s\": %s", path, err.Error()))
	}

	return man
}

func readPubSignKey() sec.PubSignKey {
	path := fmt.Sprintf("%s/sign-key.pem", testdataPath)

	key, err := sec.ReadPrivSignKey(path)
	if err != nil {
		panic(fmt.Sprintf("failed to read key file \"%s\": %s", path, err.Error()))
	}

	return key.PubKey()
}

func readPrivEncKey() sec.PrivEncKey {
	path := fmt.Sprintf("%s/enc-key.der", testdataPath)

	key, err := sec.ReadPrivEncKey(path)
	if err != nil {
		panic(fmt.Sprintf("failed to read key file \"%s\": %s", path, err.Error()))
	}

	return key
}

func testOne(t *testing.T, e entry) {
	fatalErr := func(field string, have string, want string, err error) {
		s := fmt.Sprintf("image \"%s\" has unexpected `%s` status: "+
			"have=%s want=%s", e.basename, field, have, want)
		if err != nil {
			s += "; " + err.Error()
		}

		t.Fatal(s)
	}

	imgData := readImageData(e.basename)

	img, err := ParseImage(imgData)
	if !e.form {
		if err == nil {
			fatalErr("form", "good", "bad", nil)
		}
		return
	} else {
		if err != nil {
			fatalErr("form", "bad", "good", err)
			return
		}
	}

	err = img.VerifyStructure()
	if !e.structure {
		if err == nil {
			fatalErr("structure", "good", "bad", nil)
		}
		return
	} else {
		if err != nil {
			fatalErr("structure", "bad", "good", err)
			return
		}
	}

	kek := readPrivEncKey()

	kekIdx, err := img.VerifyHash([]sec.PrivEncKey{kek})
	if !e.hash {
		if err == nil {
			fatalErr("hash", "good", "bad", nil)
		}
		return
	} else {
		if err != nil {
			fatalErr("hash", "bad", "good", err)
			return
		}

		var wantKekIdx int
		if e.encrypted {
			wantKekIdx = 0
		} else {
			wantKekIdx = -1
		}

		if kekIdx != wantKekIdx {
			fatalErr("hash", "good", "bad", errors.Errorf(
				"wrong kek idx: have=%d want=%d", kekIdx, wantKekIdx))
			return
		}
	}

	man := readManifest(e.basename)

	err = img.VerifyManifest(man)
	if !e.man {
		if err == nil {
			fatalErr("manifest", "good", "bad", nil)
		}
		return
	} else {
		if err != nil {
			fatalErr("manifest", "bad", "good", err)
			return
		}
	}

	isk := readPubSignKey()

	idx, err := img.VerifySigs([]sec.PubSignKey{isk})
	if !e.sign {
		if err == nil && idx != -1 {
			fatalErr("signature", "good", "bad", nil)
		}
		return
	} else {
		if err != nil || idx == -1 {
			fatalErr("signature", "bad", "good", err)
		}
	}
}

func TestImageVerify(t *testing.T) {
	entries := []entry{
		entry{
			basename:  "garbage",
			form:      false,
			structure: false,
			man:       false,
			sign:      false,
			encrypted: false,
		},
		entry{
			basename:  "truncated",
			form:      false,
			structure: false,
			man:       false,
			sign:      false,
			encrypted: false,
		},
		entry{
			basename:  "bad-hash",
			form:      true,
			structure: true,
			hash:      false,
			man:       false,
			sign:      false,
			encrypted: false,
		},
		entry{
			basename:  "mismatch-hash",
			form:      true,
			structure: true,
			hash:      true,
			man:       false,
			sign:      false,
			encrypted: false,
		},
		entry{
			basename:  "mismatch-version",
			form:      true,
			structure: true,
			hash:      true,
			man:       false,
			sign:      false,
			encrypted: false,
		},
		entry{
			basename:  "bad-signature",
			form:      true,
			structure: true,
			hash:      true,
			man:       true,
			sign:      false,
			encrypted: false,
		},
		entry{
			basename:  "wrong-enc-key",
			form:      true,
			structure: true,
			hash:      false,
			man:       true,
			sign:      true,
			encrypted: true,
		},
		entry{
			basename:  "good-unsigned-unencrypted",
			form:      true,
			structure: true,
			hash:      true,
			man:       true,
			sign:      false,
			encrypted: false,
		},
		entry{
			basename:  "good-signed-unencrypted",
			form:      true,
			structure: true,
			hash:      true,
			man:       true,
			sign:      true,
			encrypted: false,
		},
		entry{
			basename:  "good-signed-encrypted",
			form:      true,
			structure: true,
			hash:      true,
			man:       true,
			sign:      true,
			encrypted: true,
		},
	}

	for _, e := range entries {
		testOne(t, e)
	}
}
