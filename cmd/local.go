package cmd

import (
	"bytes"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type localCmdOptions struct {
	useDKMS         bool
	downloadHeaders bool
	srcDir          string
	envMap          map[string]string
}

// NewLocalCmd creates the `driverkit local` command.
func NewLocalCmd(configOpts *ConfigOptions, rootOpts *RootOptions, rootFlags *pflag.FlagSet) *cobra.Command {
	opts := localCmdOptions{}
	localCmd := &cobra.Command{
		Use:   "local",
		Short: "Build Falco kernel modules and eBPF probes in local env with local kernel sources and gcc/clang.",
		RunE: func(c *cobra.Command, args []string) error {
			configOpts.Printer.Logger.Info("starting build",
				configOpts.Printer.Logger.Args("processor", c.Name()))
			if !configOpts.dryRun {
				if !rootOpts.Output.HasOutputs() {
					configOpts.Printer.Logger.Info("no output specified")
					return nil
				}
				// Since we use a spinner, cache log data to a bytesbuffer;
				// we will later print it once we stop the spinner.
				var b *builder.Build
				if configOpts.disableStyling {
					b = rootOpts.ToBuild(configOpts.Printer)
				} else {
					var buf bytes.Buffer
					b = rootOpts.ToBuild(configOpts.Printer.WithWriter(&buf))
					configOpts.Printer.Spinner, _ = configOpts.Printer.Spinner.Start("driver building, it will take a few seconds")
					defer func() {
						configOpts.Printer.DefaultText.Print(buf.String())
					}()
				}
				return driverbuilder.NewLocalBuildProcessor(opts.useDKMS,
					opts.downloadHeaders,
					opts.srcDir,
					opts.envMap,
					configOpts.Timeout).Start(b)
			}
			return nil
		},
	}
	// Add root flags, but not the ones unneeded
	unusedFlagsSet := map[string]struct{}{
		"architecture":        {},
		"kernelurls":          {},
		"builderrepo":         {},
		"builderimage":        {},
		"gccversion":          {},
		"kernelconfigdata":    {},
		"proxy":               {},
		"registry-name":       {},
		"registry-password":   {},
		"registry-plain-http": {},
		"registry-user":       {},
	}
	flagSet := pflag.NewFlagSet("local", pflag.ExitOnError)
	rootFlags.VisitAll(func(flag *pflag.Flag) {
		if _, ok := unusedFlagsSet[flag.Name]; !ok {
			flagSet.AddFlag(flag)
		}
	})
	flagSet.BoolVar(&opts.useDKMS, "dkms", false, "Enforce usage of DKMS to build the kernel module.")
	flagSet.BoolVar(&opts.downloadHeaders, "download-headers", false, "Try to automatically download kernel headers.")
	flagSet.StringVar(&opts.srcDir, "src-dir", "", "Enforce usage of local source dir to build drivers.")
	flagSet.StringToStringVar(&opts.envMap, "env", make(map[string]string), "Env variables to be enforced during the driver build.")
	localCmd.PersistentFlags().AddFlagSet(flagSet)
	return localCmd
}
