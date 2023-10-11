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

package builder

// BuilderByTarget maps targets to their builder.
var BuilderByTarget = Targets{}

// Type is a type representing targets.
type Type string

func (t Type) String() string {
	return string(t)
}

// Targets is a type representing the list of the supported targets.
type Targets map[Type]Builder

// Targets returns the list of all the supported targets.
func (t Targets) Targets() []string {
	res := []string{}
	for k := range t {
		res = append(res, k.String())
	}
	return res
}
