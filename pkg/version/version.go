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
