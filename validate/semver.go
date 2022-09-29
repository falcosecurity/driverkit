package validate

import (
	"fmt"
	"github.com/blang/semver"
	"reflect"

	"github.com/go-playground/validator/v10"
)

func isSemVer(fl validator.FieldLevel) bool {
	field := fl.Field()

	switch field.Kind() {
	case reflect.String:
		// Be tolerant (ie: you can pass eg: "5.2" instead of "5.2.0")
		_, err := semver.ParseTolerant(field.String())
		return err == nil
	}

	panic(fmt.Sprintf("Bad field type %T", field.Interface()))
}
