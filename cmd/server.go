package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/falcosecurity/build-service/pkg/kubernetes"
	"github.com/falcosecurity/build-service/pkg/modulebuilder"
	"github.com/falcosecurity/build-service/pkg/server"
	"github.com/falcosecurity/build-service/pkg/signals"
	"github.com/mitchellh/go-homedir"
	"go.uber.org/zap"

	"github.com/spf13/cobra"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "The Falco build server HTTP server",
	Long:  "This is the actual server that exposes the build-server functionalities",
	RunE: func(cmd *cobra.Command, args []string) error {
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
			kubeconfigPath, err := cmd.PersistentFlags().GetString("kubeconfig")
			if err != nil {
				return err
			}
			kc, err := kubernetes.NewKubernetesClientFromConfigPath(kubeconfigPath)
			if err != nil {
				return err
			}
			buildProcessor = modulebuilder.NewKubernetesBuildProcessor(kc, buffersize)
			srv.WithBuildProcessor(buildProcessor)
		default:
			logger.Info("starting without a build processor, builds will not be processed")
		}

		ctx := context.Background()
		ctx = signals.WithStandardSignals(ctx)

		buildProcessor.WithContext(ctx)
		buildProcessor.WithLogger(logger)

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
	},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if builderStr, _ := cmd.PersistentFlags().GetString("build-processor"); builderStr == modulebuilder.KubernetesBuildProcessorName {
			err := cmd.MarkFlagRequired("kubeconfig")
			if err != nil {
				return err
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	home, err := homedir.Dir()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	serverCmd.PersistentFlags().String("build-processor", modulebuilder.KubernetesBuildProcessorName, fmt.Sprintf("build processor used to build the kernel modules (%s)", modulebuilder.KubernetesBuildProcessorName))
	serverCmd.PersistentFlags().String("kubeconfig", filepath.Join(home, ".kube", "config"), fmt.Sprintf("absolute path to the kubeconfig file, required for the '%s' processor", modulebuilder.KubernetesBuildProcessorName))
	serverCmd.PersistentFlags().StringP("bind-address", "b", "127.0.0.1:8093", "the address to bind the HTTP(s) server to")
	serverCmd.PersistentFlags().String("certfile", "", "certificate for running the server with TLS. If you pass this you also need 'keyfile' to enable TLS")
	serverCmd.PersistentFlags().String("keyfile", "", "certificate for running the server with TLS. If you pass this you also need 'certfile' to enable TLS")
	serverCmd.PersistentFlags().Int("build-buffersize", 1024, "maxmimum number of build jobs that can be queued in the same moment")
}
