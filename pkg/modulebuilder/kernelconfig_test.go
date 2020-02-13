package modulebuilder

import "testing"

func Test_prepareKernelConfig(t *testing.T) {

	tests := map[string]struct {
		kernelConfigContent string
		kernelVersion       string
		want                string
	}{
		"append local version": {
			kernelConfigContent: `
CONFIG_CC_IS_GCC=y
CONFIG_GCC_VERSION=90200
CONFIG_CLANG_VERSION=0
CONFIG_CC_CAN_LINK=y
CONFIG_CC_HAS_ASM_GOTO=y
CONFIG_CC_HAS_ASM_INLINE=y
CONFIG_CC_HAS_WARN_MAYBE_UNINITIALIZED=y
CONFIG_IRQ_WORK=y
CONFIG_BUILDTIME_EXTABLE_SORT=y
CONFIG_THREAD_INFO_IN_TASK=y`,
			kernelVersion: "5.5.2-arch1-1",
			want: `
CONFIG_CC_IS_GCC=y
CONFIG_GCC_VERSION=90200
CONFIG_CLANG_VERSION=0
CONFIG_CC_CAN_LINK=y
CONFIG_CC_HAS_ASM_GOTO=y
CONFIG_CC_HAS_ASM_INLINE=y
CONFIG_CC_HAS_WARN_MAYBE_UNINITIALIZED=y
CONFIG_IRQ_WORK=y
CONFIG_BUILDTIME_EXTABLE_SORT=y
CONFIG_THREAD_INFO_IN_TASK=y
CONFIG_LOCALVERSION="-arch1-1"
`,
		},
	}
	for k, tt := range tests {
		t.Run(k, func(t *testing.T) {
			if got := prepareKernelConfig(tt.kernelConfigContent, tt.kernelVersion); got != tt.want {
				t.Errorf("prepareKernelConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
