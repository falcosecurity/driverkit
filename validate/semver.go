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

package validate

import (
	"fmt"
	"reflect"

	"github.com/blang/semver/v4"

	"github.com/go-playground/validator/v10"
)

func checkSemver(field reflect.Value, tolerant bool) bool {
	switch field.Kind() {
	case reflect.String:
		var err error
		if tolerant {
			// Be tolerant (ie: you can pass eg: "5.2" instead of "5.2.0")
			_, err = semver.ParseTolerant(field.String())
		} else {
			_, err = semver.Parse(field.String())
		}
		return err == nil
	}

	panic(fmt.Sprintf("Bad field type %T", field.Interface()))
}

func isSemVer(fl validator.FieldLevel) bool {
	return checkSemver(fl.Field(), false)
}

func isSemVerTolerant(fl validator.FieldLevel) bool {
	return checkSemver(fl.Field(), true)
}
