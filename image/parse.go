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
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/apache/mynewt-artifact/errors"
)

// ParseVersion parses an image version string (e.g., "1.2.3.4")
func ParseVersion(versStr string) (ImageVersion, error) {
	var err error
	var major uint64
	var minor uint64
	var rev uint64
	var buildNum uint64
	var ver ImageVersion

	components := strings.SplitN(versStr, ".", 4)
	major, err = strconv.ParseUint(components[0], 10, 8)
	if err != nil {
		return ver, errors.Errorf("invalid version string %s", versStr)
	}
	if len(components) > 1 {
		minor, err = strconv.ParseUint(components[1], 10, 8)
		if err != nil {
			return ver, errors.Errorf("invalid version string %s", versStr)
		}
	}
	if len(components) > 2 {
		rev, err = strconv.ParseUint(components[2], 10, 16)
		if err != nil {
			return ver, errors.Errorf("invalid version string %s", versStr)
		}
	}
	if len(components) > 3 {
		buildNum, err = strconv.ParseUint(components[3], 10, 32)
		if err != nil {
			return ver, errors.Errorf("invalid version string %s", versStr)
		}
	}

	ver.Major = uint8(major)
	ver.Minor = uint8(minor)
	ver.Rev = uint16(rev)
	ver.BuildNum = uint32(buildNum)
	return ver, nil
}

func parseRawHeader(imgData []byte, offset int) (ImageHdr, int, error) {
	var hdr ImageHdr

	r := bytes.NewReader(imgData)
	r.Seek(int64(offset), io.SeekStart)

	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return hdr, 0, errors.Wrapf(err, "error reading image header")
	}

	if hdr.Magic != IMAGE_MAGIC {
		return hdr, 0, errors.Errorf(
			"image magic incorrect; expected 0x%08x, got 0x%08x",
			uint32(IMAGE_MAGIC), hdr.Magic)
	}

	remLen := len(imgData) - offset
	if remLen < int(hdr.HdrSz) {
		return hdr, 0, errors.Errorf(
			"image header incomplete; expected %d bytes, got %d bytes",
			hdr.HdrSz, remLen)
	}

	return hdr, int(hdr.HdrSz), nil
}

func parseRawBody(imgData []byte, hdr ImageHdr,
	offset int) ([]byte, int, error) {

	imgSz := int(hdr.ImgSz)
	remLen := len(imgData) - offset

	if remLen < imgSz {
		return nil, 0, errors.Errorf(
			"image body incomplete; expected %d bytes, got %d bytes",
			imgSz, remLen)
	}

	return imgData[offset : offset+imgSz], imgSz, nil
}

func parseRawTrailer(imgData []byte, offset int) (ImageTrailer, int, error) {
	var trailer ImageTrailer

	r := bytes.NewReader(imgData)
	r.Seek(int64(offset), io.SeekStart)

	if err := binary.Read(r, binary.LittleEndian, &trailer); err != nil {
		return trailer, 0, errors.Wrapf(err,
			"image contains invalid trailer at offset %d", offset)
	}

	return trailer, IMAGE_TRAILER_SIZE, nil
}

func parseRawTlv(imgData []byte, offset int) (ImageTlv, int, error) {
	tlv := ImageTlv{}

	r := bytes.NewReader(imgData)
	r.Seek(int64(offset), io.SeekStart)

	if err := binary.Read(r, binary.LittleEndian, &tlv.Header); err != nil {
		return tlv, 0, errors.Wrapf(err,
			"image contains invalid TLV at offset %d", offset)
	}

	tlv.Data = make([]byte, tlv.Header.Len)
	if _, err := r.Read(tlv.Data); err != nil {
		return tlv, 0, errors.Wrapf(err,
			"image contains invalid TLV at offset %d", offset)
	}

	return tlv, IMAGE_TLV_SIZE + int(tlv.Header.Len), nil
}

func parseRawTlvs(imgData []byte, offset int, size int) ([]ImageTlv, error) {
	var tlvs []ImageTlv

	end := offset + size
	for offset < end {
		tlv, tlvSize, err := parseRawTlv(imgData, offset)
		if err != nil {
			return nil, err
		}

		tlvs = append(tlvs, tlv)

		offset += tlvSize
		if offset > end {
			return nil, errors.Errorf("TLVs extend beyond end of image")
		}
	}

	return tlvs, nil
}

func ParseImage(imgData []byte) (Image, error) {
	img := Image{}
	offset := 0

	hdr, size, err := parseRawHeader(imgData, offset)
	if err != nil {
		return img, err
	}
	offset += size

	body, size, err := parseRawBody(imgData, hdr, offset)
	if err != nil {
		return img, err
	}
	offset += size

	var protTrailer *ImageTrailer
	var protTlvs []ImageTlv
	if hdr.ProtSz > 0 {
		pt, size, err := parseRawTrailer(imgData, offset)
		if err != nil {
			return img, err
		}
		protTrailer = &pt
		offset += size

		tlvsLen := int(hdr.ProtSz) - IMAGE_TRAILER_SIZE

		pts, err := parseRawTlvs(imgData, offset, tlvsLen)
		if err != nil {
			return img, err
		}
		protTlvs = pts
		offset += tlvsLen
	}

	trailer, size, err := parseRawTrailer(imgData, offset)
	if err != nil {
		return img, err
	}
	offset += size

	totalLen := int(hdr.HdrSz) + len(body) + int(trailer.TlvTotLen)
	if protTrailer != nil {
		totalLen += int(protTrailer.TlvTotLen)
	}
	if len(imgData) < totalLen {
		return img, errors.Errorf("image data truncated: have=%d want=%d",
			len(imgData), totalLen)
	}

	// Trim excess data following image trailer.
	imgData = imgData[:totalLen]

	remLen := len(imgData) - offset
	tlvs, err := parseRawTlvs(imgData, offset, remLen)
	if err != nil {
		return img, err
	}

	tlvLen := IMAGE_TRAILER_SIZE

	if int(trailer.TlvTotLen) != IMAGE_TRAILER_SIZE+remLen {
		return img, errors.Errorf(
			"invalid image: trailer indicates TLV-length=%d; actual=%d",
			trailer.TlvTotLen, tlvLen)
	}

	img.Header = hdr
	img.Body = body
	img.Tlvs = tlvs
	img.ProtTlvs = protTlvs

	return img, nil
}

func ReadImage(filename string) (Image, error) {
	ri := Image{}

	imgData, err := ioutil.ReadFile(filename)
	if err != nil {
		return ri, errors.Wrapf(err, "failed to read image from file")
	}

	return ParseImage(imgData)
}
