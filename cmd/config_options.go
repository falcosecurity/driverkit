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

package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/creasty/defaults"
	"github.com/falcosecurity/driverkit/validate"
	"github.com/go-playground/validator/v10"
)

var validProcessors = []string{"docker", "kubernetes", "kubernetes-in-cluster", "local"}
var aliasProcessors = []string{"docker", "k8s", "k8s-ic"}
var configOptions *ConfigOptions

// ConfigOptions represent the persistent configuration flags of driverkit.
type ConfigOptions struct {
	ConfigFile string
	LogLevel   string `validate:"loglevel" name:"log level" default:"INFO"`
	Timeout    int    `validate:"number,min=30" default:"120" name:"timeout"`
	ProxyURL   string `validate:"omitempty,proxy" name:"proxy url"`
	DryRun     bool

	configErrors bool
}

// NewConfigOptions creates an instance of ConfigOptions.
func NewConfigOptions() *ConfigOptions {
	o := &ConfigOptions{}
	if err := defaults.Set(o); err != nil {
		slog.With("err", err.Error(), "options", "ConfigOptions").Error("error setting driverkit options defaults")
		os.Exit(1)
	}
	return o
}

// Validate validates the ConfigOptions fields.
func (co *ConfigOptions) Validate() []error {
	if err := validate.V.Struct(co); err != nil {
		errors := err.(validator.ValidationErrors)
		errArr := []error{}
		for _, e := range errors {
			// Translate each error one at a time
			errArr = append(errArr, fmt.Errorf(e.Translate(validate.T)))
		}
		co.configErrors = true
		return errArr
	}
	return nil
}
