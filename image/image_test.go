package image

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
	integrity bool
	man       bool
	sign      bool
}

func readImageData(basename string) []byte {
	path := fmt.Sprintf("%s/%s.img", testdataPath, basename)

	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic("failed to read image file " + path)
	}

	return data
}

func readManifest(basename string) manifest.Manifest {
	path := fmt.Sprintf("%s/%s.json", testdataPath, basename)

	man, err := manifest.ReadManifest(path)
	if err != nil {
		panic("failed to read manifest file " + path)
	}

	return man
}

func readPubKey() sec.PubSignKey {
	path := fmt.Sprintf("%s/sign-key.pem", testdataPath)

	key, err := sec.ReadKey(path)
	if err != nil {
		panic("failed to read key file " + path)
	}

	return key.PubKey()
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

	err = img.Verify()
	if !e.integrity {
		if err == nil {
			fatalErr("integrity", "good", "bad", nil)
		}
		return
	} else {
		if err != nil {
			fatalErr("integrity", "bad", "good", err)
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

	key := readPubKey()

	sigs, err := img.CollectSigs()
	if err != nil {
		t.Fatalf("failed to collect image signatures: %s", err.Error())
		return
	}

	hash, err := img.Hash()
	if err != nil {
		t.Fatalf("failed to read image hash: %s", err.Error())
		return
	}

	idx, err := sec.VerifySigs(key, sigs, hash)
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
			integrity: false,
			man:       false,
			sign:      false,
		},
		entry{
			basename:  "truncated",
			form:      false,
			integrity: false,
			man:       false,
			sign:      false,
		},
		entry{
			basename:  "bad-hash",
			form:      true,
			integrity: false,
			man:       false,
			sign:      false,
		},
		entry{
			basename:  "mismatch-hash",
			form:      true,
			integrity: true,
			man:       false,
			sign:      false,
		},
		entry{
			basename:  "mismatch-version",
			form:      true,
			integrity: true,
			man:       false,
			sign:      false,
		},
		entry{
			basename:  "bad-signature",
			form:      true,
			integrity: true,
			man:       true,
			sign:      false,
		},
		entry{
			basename:  "good-unsigned",
			form:      true,
			integrity: true,
			man:       true,
			sign:      false,
		},
		entry{
			basename:  "good-signed",
			form:      true,
			integrity: true,
			man:       true,
			sign:      true,
		},
	}

	for _, e := range entries {
		testOne(t, e)
	}
}
