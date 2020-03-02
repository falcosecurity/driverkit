package cmd

import (
	"log"

	"github.com/creasty/defaults"
)

// RootOptions ...
type RootOptions struct {
	ConfigFile       string `default:".driverkit.yaml" validate:"file"`
	Output           string
	ModuleVersion    string `default:"dev"`
	KernelVersion    string
	KernelRelease    string
	Target           string
	KernelConfigData string
}

// NewRootOptions ...
func NewRootOptions() *RootOptions {
	rootOpts := &RootOptions{}
	if err := defaults.Set(rootOpts); err != nil {
		log.Fatal(err)
	}
	return rootOpts
}
