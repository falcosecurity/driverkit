package validate

import (
	"fmt"
	"github.com/blang/semver"
	"reflect"

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
