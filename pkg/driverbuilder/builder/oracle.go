// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package builder

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
)

//go:embed templates/oracle.sh
var oracleTemplate string

// TargetTypeoracle identifies the oracle target ("ol" is the ID from /etc/os-release that Oracle uses)
const TargetTypeoracle Type = "ol"

func init() {
	byTarget[TargetTypeoracle] = &oracle{}
}

// oracle is a driverkit target.
type oracle struct {
}

type oracleTemplateData struct {
	commonTemplateData
	KernelDownloadURL string
}

func (c *oracle) Name() string {
	return TargetTypeoracle.String()
}

func (c *oracle) TemplateScript() string {
	return oracleTemplate
}

func (c *oracle) URLs(kr kernelrelease.KernelRelease) ([]string, error) {

	// oracle FullExtraversion looks like "-2047.510.5.5.el7uek.x86_64"
	// need to get the "el7uek" out of the middle
	splitVersion := strings.Split(kr.FullExtraversion, ".")
	oracleVersion := splitVersion[len(splitVersion)-2] // [ "-2047", "510", "5", "5", "el7uek","x86_64" ] want -2

	// trim off the "el" and "uek" from oracleVersion
	version := strings.Trim(strings.Trim(oracleVersion, "el"), "uek")

	// sometimes Oracle 8 does "8_x" for version, only want the "8"
	if strings.Contains(version, "_") {
		version = strings.Split(version, "_")[0]
	}

	// list of possible UEK versions, which are used in the URL - ex: "UEKR3"
	// may need to evolve over time if Oracle adds more
	ueks := []string{"R3", "R4", "R5", "R6", "R7"}

	// template the kernel info into all possible URL strings
	urls := []string{
		fmt.Sprintf( // latest (Oracle 7)
			"http://yum.oracle.com/repo/OracleLinux/OL%s/latest/%s/getPackage/kernel-devel-%s%s.rpm",
			version,
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		),
		fmt.Sprintf( // latest + baseos (Oracle 8 + 9)
			"http://yum.oracle.com/repo/OracleLinux/OL%s/baseos/latest/%s/getPackage/kernel-devel-%s%s.rpm",
			version,
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		),
		fmt.Sprintf( // appstream (Oracle 8 + 9)
			"http://yum.oracle.com/repo/OracleLinux/OL%s/appstream/%s/getPackage/kernel-devel-%s%s.rpm",
			version,
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		),
		fmt.Sprintf( // MODRHCK (Oracle 7)
			"http://yum.oracle.com/repo/OracleLinux/OL%s/MODRHCK/%s/getPackage/kernel-devel-%s%s.rpm",
			version,
			kr.Architecture.ToNonDeb(),
			kr.Fullversion,
			kr.FullExtraversion,
		),
	}

	// add in all the UEK versions
	for _, uekVers := range ueks {
		urls = append(
			urls,
			fmt.Sprintf( // UEK versions URL
				"http://yum.oracle.com/repo/OracleLinux/OL%s/UEK%s/%s/getPackage/kernel-uek-devel-%s%s.rpm",
				version,
				uekVers,
				kr.Architecture.ToNonDeb(),
				kr.Fullversion,
				kr.FullExtraversion,
			),
		)
	}

	// return out all possible urls
	return urls, nil
}

func (c *oracle) TemplateData(cfg Config, kr kernelrelease.KernelRelease, urls []string) interface{} {
	return oracleTemplateData{
		commonTemplateData: cfg.toTemplateData(c, kr),
		KernelDownloadURL:  urls[0],
	}
}
