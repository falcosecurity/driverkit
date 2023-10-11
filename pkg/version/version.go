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

package version

import (
	"fmt"
	"strconv"
	"time"
)

// Populated by makefile
var (
	gitCommit         string
	commitsFromGitTag string
	gitTag            string
	buildTime         string
)

const versionFormat = "%s-%s+%s"

// GitCommit returns the git commit of the current driverkit version.
func GitCommit() string {
	return gitCommit
}

// GitTag returns the git tag of the current driverkit version.
func GitTag() string {
	return gitTag
}

// CommitsSinceGitTag returns the number of git commits since the current driverkit version contains w.r.t to the previous version.
func CommitsSinceGitTag() string {
	return commitsFromGitTag
}

// Time returns the build time of the current driverkit version.
func Time() *time.Time {
	if len(buildTime) == 0 {
		return nil
	}
	i, err := strconv.ParseInt(buildTime, 10, 64)
	if err != nil {
		return nil
	}
	t := time.Unix(i, 0)
	return &t
}

// String returns current driverkit version info as a string.
func String() string {
	return fmt.Sprintf(versionFormat, GitTag(), CommitsSinceGitTag(), GitCommit())
}
