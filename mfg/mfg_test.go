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

package mfg

import (
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/apache/mynewt-artifact/manifest"
	"github.com/apache/mynewt-artifact/sec"
)

const testdataPath = "testdata"

type entry struct {
	basename  string
	form      bool
	structure bool
	man       bool
	sign      bool
}

func readMfgData(basename string) []byte {
	path := fmt.Sprintf("%s/%s.bin", testdataPath, basename)

	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic("failed to read mfgimage file " + path)
	}

	return data
}

func readManifest(basename string) manifest.MfgManifest {
	path := fmt.Sprintf("%s/%s.json", testdataPath, basename)

	man, err := manifest.ReadMfgManifest(path)
	if err != nil {
		panic("failed to read manifest file " + path)
	}

	return man
}

func readPubKey() sec.PubSignKey {
	path := fmt.Sprintf("%s/sign-key.pem", testdataPath)

	key, err := sec.ReadPrivSignKey(path)
	if err != nil {
		panic("failed to read key file " + path)
	}

	return key.PubKey()
}

func testOne(t *testing.T, e entry) {
	fatalErr := func(field string, have string, want string, err error) {
		s := fmt.Sprintf("mfgimage \"%s\" has unexpected `%s` status: "+
			"have=%s want=%s", e.basename, field, have, want)
		if err != nil {
			s += "; " + err.Error()
		}

		t.Fatal(s)
	}

	mfgData := readMfgData(e.basename)
	man := readManifest(e.basename)

	var metaOff int
	if man.Meta != nil {
		metaOff = man.Meta.EndOffset
	} else {
		metaOff = -1
	}

	m, err := Parse(mfgData, metaOff, man.EraseVal)
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

	err = m.VerifyStructure(man.EraseVal)
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

	err = m.VerifyManifest(man)
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

	key := readPubKey()

	idx, err := VerifySigs(man, []sec.PubSignKey{key})
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

func TestMfgVerify(t *testing.T) {
	entries := []entry{
		// Not an mfgimage.
		entry{
			basename:  "garbage",
			form:      false,
			structure: false,
			man:       false,
			sign:      false,
		},
		// Contains a TLV with type=0xaa.
		entry{
			basename:  "unknown-tlv",
			form:      true,
			structure: false,
			man:       false,
			sign:      false,
		},
		// MMR and manifest contain the same incorrect hash.
		entry{
			basename:  "hashx-fm1-ext0-tgts1-sign0",
			form:      true,
			structure: false,
			man:       false,
			sign:      false,
		},
		// MMR hash doesn't match manifest.
		entry{
			basename:  "hashm-fm1-ext0-tgts1-sign0",
			form:      true,
			structure: true,
			man:       false,
			sign:      false,
		},
		// MMR flash map doesn't match manifest.
		entry{
			basename:  "hash1-fmm-ext1-tgts1-sign0",
			form:      true,
			structure: true,
			man:       false,
			sign:      false,
		},
		// MMR ext ref doesn't match manifest.
		entry{
			basename:  "hash1-fm1-extm-tgts1-sign0",
			form:      true,
			structure: true,
			man:       false,
			sign:      false,
		},
		// Manifest indicates build where there is none.
		entry{
			basename:  "hash1-fm1-ext1-tgtsm-sign0",
			form:      true,
			structure: true,
			man:       false,
			sign:      false,
		},
		// Good unsigned mfgimage without ref ext TLV.
		entry{
			basename:  "hash1-fm1-ext0-tgts1-sign0",
			form:      true,
			structure: true,
			man:       true,
			sign:      false,
		},
		// Good unsigned mfgimage.
		entry{
			basename:  "hash1-fm1-ext1-tgts1-sign0",
			form:      true,
			structure: true,
			man:       true,
			sign:      false,
		},
		// Good signed mfgimage.
		entry{
			basename:  "hash1-fm1-ext1-tgts1-sign1",
			form:      true,
			structure: true,
			man:       true,
			sign:      true,
		},
	}

	for _, e := range entries {
		testOne(t, e)
	}
}
