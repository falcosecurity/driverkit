package modulebuilder

import (
	"fmt"
	"strings"
)

func prepareKernelConfig(kernelConfigContent string, kernelVersion string) string {
	sp := strings.SplitN(kernelVersion, "-", 2)
	localVersion := ""
	if len(sp) == 2 {
		localVersion = sp[1]
	}

	return fmt.Sprintf("%s\nCONFIG_LOCALVERSION=\"-%s\"\n", kernelConfigContent, localVersion)
}
