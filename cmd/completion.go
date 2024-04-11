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
	"bytes"
	"fmt"
	"github.com/spf13/pflag"
	"os"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
)

var validShells = []string{"bash", "zsh", "fish"}

const (
	longUsageTemplate = `Generates completion scripts for the following shells: {{.ValidShells}}.

There are two ways to configure your bash shell to load completions for each session.

1. Source the completion script in your ~/.bashrc file

    echo 'source <(driverkit completion bash)' >> ~/.bashrc

2. Add the completion script to /etc/bash_completion.d/ directory

    driverkit completion bash > /etc/bash_completion.d/driverkit
`
)

func validateArgs() cobra.PositionalArgs {
	return func(c *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}
		return cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs)(c, args)
	}
}

// NewCompletionCmd ...
func NewCompletionCmd(_ *ConfigOptions, _ *RootOptions, _ *pflag.FlagSet) *cobra.Command {
	var long bytes.Buffer
	tmpl := template.Must(template.New("long").Parse(longUsageTemplate))
	tmpl.Execute(&long, map[string]interface{}{
		"ValidShells": strings.Join(validShells, ", "),
	})
	cmdArgs := append(validShells, "help")
	completionCmd := &cobra.Command{
		Use:               fmt.Sprintf("completion (%s)", strings.Join(cmdArgs, "|")),
		Short:             "Generates completion scripts.",
		Long:              long.String(),
		Args:              validateArgs(),
		ValidArgs:         cmdArgs,
		DisableAutoGenTag: true,
		Run: func(c *cobra.Command, args []string) {
			if len(args) == 0 {
				c.Help()
				return
			}

			arg := args[0]
			switch arg {
			case "bash":
				c.Root().GenBashCompletion(os.Stdout)
				break
			case "zsh":
				c.Root().GenZshCompletion(os.Stdout)
				break
			case "fish":
				c.Root().GenFishCompletion(os.Stdout, true)
			case "help":
				c.Help()
			}
		},
	}

	return completionCmd
}
