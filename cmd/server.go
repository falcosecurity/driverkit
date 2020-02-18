package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/falcosecurity/build-service/pkg/filesystem"
	"github.com/falcosecurity/build-service/pkg/kubernetes/factory"
	"github.com/falcosecurity/build-service/pkg/modulebuilder"
	"github.com/falcosecurity/build-service/pkg/server"
	"github.com/falcosecurity/build-service/pkg/signals"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func init() {
	rootCmd.AddCommand(NewServerCmd())
}

func NewServerCmd() *cobra.Command {
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "The Falco build server HTTP server",
		Long:  "This is the actual server that exposes the build-server functionalities",
	}

	// Add Flags
	serverCmd.PersistentFlags().String("build-processor", modulebuilder.KubernetesBuildProcessorName, fmt.Sprintf("build processor used to build the kernel modules (supported: %s)", modulebuilder.KubernetesBuildProcessorName))
	serverCmd.PersistentFlags().String("filesystem", filesystem.LocalFilesystemStr, fmt.Sprintf("filesystem to use to save built kernel modules (supported: %s)", filesystem.LocalFilesystemStr))
	serverCmd.PersistentFlags().String("filesystem.local.basepath", os.TempDir(), "directory to use to save files when using the local filesystem")
	serverCmd.PersistentFlags().StringP("bind-address", "b", "127.0.0.1:8093", "the address to bind the HTTP(s) server to")
	serverCmd.PersistentFlags().String("certfile", "", "certificate for running the server with TLS. If you pass this you also need 'keyfile' to enable TLS")
	serverCmd.PersistentFlags().String("keyfile", "", "certificate for running the server with TLS. If you pass this you also need 'certfile' to enable TLS")
	serverCmd.PersistentFlags().Int("build-buffersize", 1024, "maxmimum number of build jobs that can be queued in the same moment")

	configFlags := genericclioptions.NewConfigFlags(false)
	configFlags.AddFlags(serverCmd.PersistentFlags())
	kubefactory := factory.NewFactory(configFlags)

	serverCmd.RunE = serverCmdRunE(kubefactory)

	// Override help on all the commands tree
	walk(serverCmd, func(c *cobra.Command) {
		c.Flags().BoolP("help", "h", false, fmt.Sprintf("Help for the %s command", c.Name()))
	})

	return serverCmd
}
func serverCmdRunE(kubefactory factory.Factory) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		bindAddress, err := cmd.PersistentFlags().GetString("bind-address")
		if err != nil {
			return err
		}
		certFile, err := cmd.PersistentFlags().GetString("certfile")
		if err != nil {
			return err
		}
		keyFile, err := cmd.PersistentFlags().GetString("keyfile")
		if err != nil {
			return err
		}
		buffersize, err := cmd.PersistentFlags().GetInt("build-buffersize")
		if err != nil {
			return err
		}
		fsname, err := cmd.PersistentFlags().GetString("filesystem")
		if err != nil {
			return err
		}
		localfsBasepath, err := cmd.PersistentFlags().GetString("filesystem.local.basepath")
		if err != nil {
			return err
		}
		srv := server.NewServer(bindAddress)

		if len(certFile)+len(keyFile) > 0 {
			tlsopts := server.NewTLSOptions(certFile, keyFile)
			srv.WithTLSOptions(tlsopts)
		}

		srv.WithLogger(logger)
		builderStr, err := cmd.PersistentFlags().GetString("build-processor")
		if err != nil {
			return err
		}

		var buildProcessor modulebuilder.BuildProcessor
		buildProcessor = modulebuilder.NewNopBuildProcessor()

		switch builderStr {
		case modulebuilder.KubernetesBuildProcessorName:
			kc, err := kubefactory.KubernetesClientSet()
			if err != nil {
				return err
			}
			clientConfig, err := kubefactory.ToRESTConfig()
			if err != nil {
				return err
			}
			if err := factory.SetKubernetesDefaults(clientConfig); err != nil {
				return err
			}
			buildProcessor = modulebuilder.NewKubernetesBuildProcessor(kc.CoreV1(), clientConfig, buffersize)
			srv.WithBuildProcessor(buildProcessor)
		default:
			logger.Info("starting without a build processor, builds will not be processed")
		}

		ctx := context.Background()
		ctx = signals.WithStandardSignals(ctx)

		buildProcessor.WithContext(ctx)
		buildProcessor.WithLogger(logger)

		fs, err := filesystem.Factory(fsname, map[string]string{
			"basepath": localfsBasepath,
		})
		if err != nil {
			logger.Fatal("fatal error creating the filesystem", zap.Error(err))
		}

		ms := filesystem.NewModuleStorage(fs)
		buildProcessor.WithModuleStorage(ms)

		go func() {
			err := buildProcessor.Start()
			if err != nil {
				logger.Fatal("unexpected error from the build processor", zap.Error(err))
			}
		}()

		go func() {
			err := srv.ListenAndServe()
			if err != nil {
				logger.Fatal("unexpected error from the http server", zap.Error(err))
			}
		}()

		<-ctx.Done()
		return nil
	}
}

// walk calls f for c and all of its children.
func walk(c *cobra.Command, f func(*cobra.Command)) {
	f(c)
	for _, c := range c.Commands() {
		walk(c, f)
	}
}
