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

package manifest

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"strings"

	"github.com/apache/mynewt-artifact/errors"
)

/*
 * Data that's going to go to build manifest file
 */
type ManifestSizeArea struct {
	Name string `json:"name"`
	Size uint32 `json:"size"`
}

type ManifestSizeSym struct {
	Name  string              `json:"name"`
	Areas []*ManifestSizeArea `json:"areas"`
}

type ManifestSizeFile struct {
	Name string             `json:"name"`
	Syms []*ManifestSizeSym `json:"sym"`
}

type ManifestSizePkg struct {
	Name  string              `json:"name"`
	Files []*ManifestSizeFile `json:"files"`
}

type ManifestPkg struct {
	Name string `json:"name"`
	Repo string `json:"repo"`
}

type ManifestRepo struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
	Dirty  bool   `json:"dirty,omitempty"`
	URL    string `json:"url,omitempty"`
}

type Manifest struct {
	Name       string            `json:"name"`
	Date       string            `json:"build_time"`
	Version    string            `json:"build_version"`
	BuildID    string            `json:"id"`
	Image      string            `json:"image"`
	ImageHash  string            `json:"image_hash"`
	Loader     string            `json:"loader"`
	LoaderHash string            `json:"loader_hash"`
	Pkgs       []*ManifestPkg    `json:"pkgs"`
	LoaderPkgs []*ManifestPkg    `json:"loader_pkgs,omitempty"`
	TgtVars    []string          `json:"target"`
	Repos      []*ManifestRepo   `json:"repos"`
	Syscfg     map[string]string `json:"syscfg"`

	PkgSizes       []*ManifestSizePkg `json:"pkgsz"`
	LoaderPkgSizes []*ManifestSizePkg `json:"loader_pkgsz,omitempty"`
}

func ReadManifest(path string) (Manifest, error) {
	m := Manifest{}

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return m, errors.Wrapf(err, "failed to read manifest file")
	}

	if err := json.Unmarshal(content, &m); err != nil {
		return m, errors.Wrapf(
			err, "failure decoding manifest with path \"%s\"", path)
	}

	return m, nil
}

func (m *Manifest) Write(w io.Writer) (int, error) {
	buffer, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return 0, errors.Wrapf(err, "Cannot encode manifest")
	}

	cnt, err := w.Write(buffer)
	if err != nil {
		return 0, errors.Wrapf(err, "Cannot write manifest")
	}

	return cnt, nil
}

func (m *Manifest) FindTargetVar(key string) string {
	for _, tv := range m.TgtVars {
		parts := strings.SplitN(tv, "=", 2)
		if len(parts) == 2 && parts[0] == key {
			return parts[1]
		}
	}

	return ""
}
