package cmd

import (
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder"
	"github.com/falcosecurity/driverkit/validate"
	"github.com/go-playground/validator/v10"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"log/slog"
	"os"
	"os/user"
	"runtime"
)

type localCmdOptions struct {
	UseDKMS bool
	SrcDir  string `validate:"required,abs_dirpath" name:"src-dir"`
	EnvMap  map[string]string
}

func (l *localCmdOptions) validate() []error {
	if err := validate.V.Struct(l); err != nil {
		errors := err.(validator.ValidationErrors)
		errArr := []error{}
		for _, e := range errors {
			// Translate each error one at a time
			errArr = append(errArr, fmt.Errorf(e.Translate(validate.T)))
		}
		return errArr
	}
	return nil
}

// NewLocalCmd creates the `driverkit local` command.
func NewLocalCmd(rootCommand *RootCmd, rootOpts *RootOptions, rootFlags *pflag.FlagSet) *cobra.Command {
	opts := localCmdOptions{}
	localCmd := &cobra.Command{
		Use:               "local",
		Short:             "Build Falco kernel modules and eBPF probes in local env with local kernel sources and gcc/clang.",
		PersistentPreRunE: persistentPreRunFunc(rootCommand, rootOpts, &opts),
		Run: func(c *cobra.Command, args []string) {
			slog.With("processor", c.Name()).Info("driver building, it will take a few seconds")
			if !configOptions.DryRun {
				b := rootOpts.ToBuild()
				if !b.HasOutputs() {
					return
				}
				if opts.UseDKMS {
					currentUser, err := user.Current()
					if err != nil {
						slog.With("err", err.Error()).Error("Failed to retrieve user. Exiting.")
						os.Exit(1)
					}
					if currentUser.Username != "root" {
						slog.Error("Must be run as root for DKMS build.")
						os.Exit(1)
					}
				}
				if err := driverbuilder.NewLocalBuildProcessor(viper.GetInt("timeout"), opts.UseDKMS, opts.SrcDir, opts.EnvMap).Start(b); err != nil {
					slog.With("err", err.Error()).Error("exiting")
					os.Exit(1)
				}
			}
		},
	}
	// Add root flags, but not the ones unneeded
	unusedFlagsSet := map[string]struct{}{
		"architecture":        {},
		"target":              {},
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
	flagSet.BoolVar(&opts.UseDKMS, "dkms", false, "Enforce usage of DKMS to build the kernel module.")
	flagSet.StringVar(&opts.SrcDir, "src-dir", "", "Enforce usage of local source dir to build drivers.")
	flagSet.StringToStringVar(&opts.EnvMap, "env", nil, "Env variables to be enforced during the driver build.")
	localCmd.PersistentFlags().AddFlagSet(flagSet)
	return localCmd
}

// Partially overrides rootCmd.persistentPreRunFunc setting some defaults before config init/validation stage.
func persistentPreRunFunc(rootCommand *RootCmd, rootOpts *RootOptions, localOpts *localCmdOptions) func(c *cobra.Command, args []string) error {
	return func(c *cobra.Command, args []string) error {
		// Default values
		rootOpts.Target = "local"
		rootOpts.Architecture = runtime.GOARCH
		if errs := localOpts.validate(); errs != nil {
			for _, err := range errs {
				slog.With("err", err.Error()).Error("error validating local command options")
			}
			return fmt.Errorf("exiting for validation errors")
		}
		return rootCommand.c.PersistentPreRunE(c, args)
	}
}
